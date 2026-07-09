//! Embedded `did:webvh` minting against soland's principal-server.
//!
//! The pure build + cryptography path (keygen, SCID derivation, eddsa-jcs-2022
//! proof, document skeleton) now lives in the shared SDK at
//! [`arkret_signatures::webvh`] so clients (sodmin / inkson) and servers
//! (soland / coauth) all mint byte-for-byte identical inception entries. This
//! module keeps only coauth-specific concerns: the HTTP submission to soland's
//! protocol DID operation endpoint and the lookup-or-mint persistence flow.

use coauth_data::{BoxRepository, Clock, RepositoryAccess, User};
use coauth_keystore::Encrypter;
use arkret_core::DidOperationSubmitOutcome;
pub use arkret_core::DidOperationSubmitRequestBody;
// Re-export the shared SDK builder surface so existing call-sites
// (`soland_webvh::prepare_inception`, `SuppliedInceptionInput`, …) keep working
// without a second copy of the crypto in this crate.
pub use arkret_signatures::webvh::{
    InceptionInput, PreparedInception, SubmittedInception, SuppliedInceptionInput,
    WebvhInceptionError, prepare_inception, prepare_supplied_inception,
};
use rand_core::RngCore;
use thiserror::Error;
use url::Url;

use crate::outbound_http;

/// Errors produced while POSTing a `did:webvh` inception entry or running the
/// lookup-or-mint flow. Build / cryptography failures surface as
/// [`WebvhInceptionError`] from the shared SDK builder and convert into
/// [`SolandWebvhError::Build`].
#[derive(Debug, Error)]
pub enum SolandWebvhError {
    #[error("webvh inception build failed: {0}")]
    Build(#[from] WebvhInceptionError),
    #[error("principal-server endpoint is not a valid URL: {0}")]
    InvalidEndpoint(#[from] url::ParseError),
    #[error("principal-server DID operation submit request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("principal-server returned status {status}: {body}")]
    SubmitRejected { status: u16, body: String },
    #[error("update_key encryption failed")]
    Encrypt,
    #[error("storage error: {0}")]
    Storage(String),
}

/// POST `prepared.submit_body` to the principal server's protocol DID
/// operation endpoint and surface any non-2xx response to the caller.
pub async fn submit_against_principal(
    http_client: &reqwest::Client,
    principal_endpoint: &Url,
    bearer: Option<&str>,
    prepared: &PreparedInception,
) -> Result<DidOperationSubmitOutcome, SolandWebvhError> {
    submit_did_operation(
        http_client,
        principal_endpoint,
        bearer,
        &prepared.submit_body,
    )
    .await
}

pub async fn submit_did_operation(
    http_client: &reqwest::Client,
    principal_endpoint: &Url,
    bearer: Option<&str>,
    body: &DidOperationSubmitRequestBody,
) -> Result<DidOperationSubmitOutcome, SolandWebvhError> {
    let endpoint = principal_endpoint
        .join("/_arkret/root/identity/submit-did-operation")
        .map_err(SolandWebvhError::InvalidEndpoint)?;
    let response = outbound_http::send_with_policy(
        outbound_http::soland_policy("identity_submit_did_operation")
            .with_timeout(std::time::Duration::from_secs(15)),
        || {
            let mut request = http_client.post(endpoint.clone()).json(body);
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            }
            request
        },
    )
    .await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status.is_success() {
        return serde_json::from_str(&body).map_err(|error| SolandWebvhError::SubmitRejected {
            status: status.as_u16(),
            body: format!("invalid response body: {error}"),
        });
    }
    Err(SolandWebvhError::SubmitRejected {
        status: status.as_u16(),
        body: body.chars().take(512).collect(),
    })
}

/// Lookup-or-mint the `did:webvh` for `user` against the principal server
/// identified by `(audience, principal_endpoint)`.
///
/// Idempotent: if `principal_did_update_keys` already has a row for
/// `(user, audience)`, returns the existing DID without contacting the
/// principal server. Otherwise generates fresh key material, submits the
/// inception entry through soland's DID operation endpoint, encrypts the
/// update-key seed, and writes the row.
///
/// Errors short-circuit on:
/// - DB lookup/insert failures (`Storage`),
/// - canonical-JSON / SCID failures (`Build`),
/// - principal-server transport failures (`Http`) or non-2xx responses (`SubmitRejected`),
/// - update-key encryption failures (`Encrypt`).
#[allow(clippy::too_many_arguments)]
pub async fn ensure_principal_did_minted(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    encrypter: &Encrypter,
    http_client: &reqwest::Client,
    user: &User,
    audience: &str,
    principal_endpoint: &Url,
    operation_bearer: Option<&str>,
    also_known_as: &[String],
    enrollment_authority_did: &str,
) -> Result<String, SolandWebvhError> {
    {
        let mut principal_did_repo = repo.principal_did();
        principal_did_repo
            .acquire_mint_lock(user, audience)
            .await
            .map_err(|e| SolandWebvhError::Storage(e.to_string()))?;
        if let Some(existing) = principal_did_repo
            .get_for_user_and_audience(user, audience)
            .await
            .map_err(|e| SolandWebvhError::Storage(e.to_string()))?
        {
            return Ok(existing.did);
        }
    }

    let local_id = user.id.to_string().to_ascii_lowercase();
    let input = InceptionInput {
        principal_endpoint,
        local_id: &local_id,
        also_known_as,
        version_time: clock.now(),
        did_key_fragment: None,
        enrollment_authority_did,
    };
    let prepared = prepare_inception(rng, &input)?;

    submit_against_principal(http_client, principal_endpoint, operation_bearer, &prepared).await?;

    let update_secret_b64 = encrypter
        .encrypt_to_string(&prepared.update_key_seed)
        .map_err(|_| SolandWebvhError::Encrypt)?;

    // `PreparedInception` is zeroize-on-drop in the SDK, so its fields cannot
    // be moved out — clone what the row needs and let the rest be scrubbed.
    repo.principal_did()
        .add(
            rng,
            clock,
            user,
            audience.to_owned(),
            prepared.did.clone(),
            prepared.did_public_key_multibase.clone(),
            prepared.update_public_key_multibase.clone(),
            update_secret_b64,
            Some(prepared.version_id.clone()),
        )
        .await
        .map_err(|e| SolandWebvhError::Storage(e.to_string()))?;

    Ok(prepared.did.clone())
}
