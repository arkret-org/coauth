use std::sync::{Arc, LazyLock};

use coauth_data::oauth::OAuthClientRepository;
use coauth_data::{
    BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, LocalizedClientMetadata, SystemClock,
};
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_keystore::Encrypter;
use coauth_oauth_types::errors::{ClientError, ClientErrorCode};
use coauth_oauth_types::registration::{
    ClientMetadata, ClientMetadataVerificationError, ClientRegistrationResponse, Localized,
    VerifiedClientMetadata,
};
use coauth_policy::{EvaluationResult, PolicyFactory, PolicyInstance};
use opentelemetry::metrics::Counter;
use opentelemetry::{Key, KeyValue};
use psl::Psl;
use rand::distributions::{Alphanumeric, DistString};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::prelude::*;
use serde::Serialize;
use sha2::Digest as _;
use thiserror::Error;
use tracing::info;
use url::Url;

use crate::handlers::METER;

static REGISTRATION_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("coauth.oauth.registration_request")
        .with_description("Number of OAuth registration requests")
        .with_unit("{request}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error("invalid json body: {0}")]
    InvalidJson(String),

    #[error("invalid client metadata")]
    InvalidClientMetadata(#[from] ClientMetadataVerificationError),

    #[error("{0} is a public suffix, not a valid domain")]
    UrlIsPublicSuffix(&'static str),

    #[error("client registration denied by the policy: {0}")]
    PolicyDenied(EvaluationResult),
}

impl_from_error_for_route!(coauth_data::RepositoryError);
impl_from_error_for_route!(coauth_policy::LoadError);
impl_from_error_for_route!(coauth_policy::EvaluationError);
impl_from_error_for_route!(coauth_keystore::aead::Error);
impl_from_error_for_route!(serde_json::Error);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        let event_id = sentry::capture_error(&self);

        REGISTRATION_COUNTER.add(1, &[KeyValue::new(RESULT, "denied")]);

        match self {
            Self::Internal(_) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(ClientError::from(ClientErrorCode::ServerError)));
            }

            Self::InvalidJson(ref e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(e.clone()),
                ));
            }

            // This error comes from the `ClientMetadata::validate` method. We return an
            // `invalid_redirect_uri` error if the error is related to the redirect URIs, else we
            // return an `invalid_client_metadata` error.
            Self::InvalidClientMetadata(
                ClientMetadataVerificationError::MissingRedirectUris
                | ClientMetadataVerificationError::RedirectUriWithFragment(_),
            ) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(ClientErrorCode::InvalidRedirectUri)));
            }

            Self::InvalidClientMetadata(ref e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(e.to_string()),
                ));
            }

            // This error happens if the any of the client's URIs are public suffixes. We return
            // an `invalid_redirect_uri` error if it's a `redirect_uri`, else we return an
            // `invalid_client_metadata` error.
            Self::UrlIsPublicSuffix("redirect_uri") => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidRedirectUri)
                        .with_description("redirect_uri is not using a valid domain".to_owned()),
                ));
            }

            Self::UrlIsPublicSuffix(field) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(
                    ClientError::from(ClientErrorCode::InvalidClientMetadata)
                        .with_description(format!("{field} is not using a valid domain")),
                ));
            }

            // For policy violations, we return an `invalid_client_metadata` error with the details
            // of the violations in most cases. If a violation includes `redirect_uri` in the
            // message, we return an `invalid_redirect_uri` error instead.
            Self::PolicyDenied(ref evaluation) => {
                // TODO: detect them better
                let code = if evaluation
                    .violations
                    .iter()
                    .any(|v| v.msg.contains("redirect_uri"))
                {
                    ClientErrorCode::InvalidRedirectUri
                } else {
                    ClientErrorCode::InvalidClientMetadata
                };

                let collected = &evaluation
                    .violations
                    .iter()
                    .map(|v| v.msg.clone())
                    .collect::<Vec<String>>();
                let joined = collected.join("; ");

                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ClientError::from(code).with_description(joined)));
            }
        }

        let sentry_event_id = crate::salvo_utils::sentry::SentryEventId::from(event_id);
        sentry_event_id.write_to_response(res);
    }
}

#[derive(Serialize)]
struct RegistrationRouteOutcome {
    #[serde(flatten)]
    response: ClientRegistrationResponse,
    #[serde(flatten)]
    metadata: VerifiedClientMetadata,
}

/// Check if the host of the given URL is a public suffix
fn host_is_public_suffix(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default().as_bytes();
    let Some(suffix) = psl::List.suffix(host) else {
        // There is no suffix, which is the case for empty hosts, like with custom
        // schemes
        return false;
    };

    if !suffix.is_known() {
        // The suffix is not known, so it's not a public suffix
        return false;
    }

    // We want to cover two cases:
    // - The host is the suffix itself, like `com`
    // - The host is a dot followed by the suffix, like `.com`
    if host.len() <= suffix.as_bytes().len() + 1 {
        // The host only has the suffix in it, so it's a public suffix
        return true;
    }

    false
}

/// Check if any of the URLs in the given `Localized` field is a public suffix
fn localised_url_has_public_suffix(url: &Localized<Url>) -> bool {
    url.iter().any(|(_lang, url)| host_is_public_suffix(url))
}

#[handler]
#[tracing::instrument(name = "handlers.oauth.registration.post", skip_all)]
pub async fn post(req: &mut Request, depot: &Depot, res: &mut Response) {
    match handle_post(req, depot).await {
        Ok(response) => {
            res.status_code(StatusCode::CREATED);
            res.render(Json(response));
        }
        Err(e) => e.render(res),
    }
}

async fn handle_post(
    req: &mut Request,
    depot: &Depot,
) -> Result<RegistrationRouteOutcome, RouteError> {
    let encrypter = depot
        .get::<Encrypter>("encrypter")
        .expect("Encrypter not found in depot");
    let repo_factory = depot
        .get::<BoxRepositoryFactory>("box_repository_factory")
        .expect("BoxRepositoryFactory not found in depot");
    let policy_factory = depot
        .get::<Arc<PolicyFactory>>("policy_factory")
        .expect("PolicyFactory not found in depot");
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);

    #[allow(clippy::box_default)] // Box::default() doesn't apply to dyn Clock+Send
    let clock: BoxClock = Box::new(SystemClock::default());
    let mut rng: BoxRng =
        Box::new(ChaChaRng::from_rng(rand_core::OsRng).expect("Failed to seed rng"));

    let mut repo: BoxRepository = repo_factory.create().await?;
    let mut policy: PolicyInstance = policy_factory
        .instantiate()
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    let user_agent: Option<String> = req.header("user-agent");

    // Parse the JSON body
    let body: ClientMetadata = req
        .parse_json()
        .await
        .map_err(|e| RouteError::InvalidJson(e.to_string()))?;

    // Sort the properties to ensure a stable serialisation order for hashing
    let body = body.sorted();

    // We need to serialize the body to compute the hash, and to log it
    let body_json = serde_json::to_string(&body)?;

    info!(body = body_json, "Client registration");

    // Validate the body
    let metadata = body.validate()?;

    // Some extra validation that is hard to do in OPA and not done by the
    // `validate` method either
    if let Some(client_uri) = &metadata.client_uri
        && localised_url_has_public_suffix(client_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("client_uri"));
    }

    if let Some(logo_uri) = &metadata.logo_uri
        && localised_url_has_public_suffix(logo_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("logo_uri"));
    }

    if let Some(policy_uri) = &metadata.policy_uri
        && localised_url_has_public_suffix(policy_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("policy_uri"));
    }

    if let Some(tos_uri) = &metadata.tos_uri
        && localised_url_has_public_suffix(tos_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("tos_uri"));
    }

    if let Some(initiate_login_uri) = &metadata.initiate_login_uri
        && host_is_public_suffix(initiate_login_uri)
    {
        return Err(RouteError::UrlIsPublicSuffix("initiate_login_uri"));
    }

    for redirect_uri in metadata.redirect_uris() {
        if host_is_public_suffix(redirect_uri) {
            return Err(RouteError::UrlIsPublicSuffix("redirect_uri"));
        }
    }

    let res = policy
        .evaluate_client_registration(coauth_policy::ClientRegistrationInput {
            client_metadata: &metadata,
            requester: coauth_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
                ..Default::default()
            },
        })
        .await?;
    if !res.valid() {
        return Err(RouteError::PolicyDenied(res));
    }

    let (client_secret, encrypted_client_secret) = match metadata.token_endpoint_auth_method {
        Some(
            OAuthClientAuthenticationMethod::ClientSecretJwt
            | OAuthClientAuthenticationMethod::ClientSecretPost
            | OAuthClientAuthenticationMethod::ClientSecretBasic,
        ) => {
            // Let's generate a random client secret
            let client_secret = Alphanumeric.sample_string(&mut rand::thread_rng(), 20);
            let encrypted_client_secret = encrypter.encrypt_to_string(client_secret.as_bytes())?;
            (Some(client_secret), Some(encrypted_client_secret))
        }
        _ => (None, None),
    };

    // If the client doesn't have a secret, we may be able to deduplicate it. To
    // do so, we hash the client metadata, and look for it in the database
    let (digest_hash, existing_client) = if client_secret.is_none() {
        // TODO: One interesting caveat is that we hash *before* saving to the database.
        // It means it takes into account fields that we don't care about *yet*.
        //
        // This means that if later we start supporting a particular field, we
        // will still serve the 'old' client_id, without updating the client in the
        // database
        let hash = sha2::Sha256::digest(&body_json);
        let hash = hex::encode(hash);
        let client = repo.oauth_client().find_by_metadata_digest(&hash).await?;
        (Some(hash), client)
    } else {
        (None, None)
    };

    let client = if let Some(client) = existing_client {
        tracing::info!(%client.id, "Reusing existing client");
        REGISTRATION_COUNTER.add(1, &[KeyValue::new(RESULT, "reused")]);
        client
    } else {
        let mut client = repo
            .oauth_client()
            .add(
                &mut rng,
                &clock,
                metadata.redirect_uris().to_vec(),
                digest_hash,
                encrypted_client_secret,
                metadata.application_type.clone(),
                //&metadata.response_types(),
                metadata.grant_types().to_vec(),
                metadata
                    .client_name
                    .clone()
                    .map(Localized::to_non_localized),
                metadata.logo_uri.clone().map(Localized::to_non_localized),
                metadata.client_uri.clone().map(Localized::to_non_localized),
                metadata.policy_uri.clone().map(Localized::to_non_localized),
                metadata.tos_uri.clone().map(Localized::to_non_localized),
                metadata.jwks_uri.clone(),
                metadata.jwks.clone(),
                // TODO: those might not be right, should be function calls
                metadata.id_token_signed_response_alg.clone(),
                metadata.userinfo_signed_response_alg.clone(),
                metadata.token_endpoint_auth_method.clone(),
                metadata.token_endpoint_auth_signing_alg.clone(),
                metadata.initiate_login_uri.clone(),
            )
            .await?;

        // Persist any localised metadata variants the registrant supplied
        // (`client_name#ja-Jpan-JP` etc.). The base `add` only stores the
        // non-localised default; the per-locale rows go to a separate
        // table.
        let localized = collect_localized_metadata(&metadata);
        if !localized.is_empty() {
            repo.oauth_client()
                .replace_localized_metadata(client.id, &localized)
                .await?;
            client.localized_metadata = localized;
        }

        tracing::info!(%client.id, "Registered new client");
        REGISTRATION_COUNTER.add(1, &[KeyValue::new(RESULT, "created")]);
        client
    };

    let response = ClientRegistrationResponse {
        client_id: client.client_id.clone(),
        client_secret,
        // TODO: we should have a `created_at` field on the clients
        client_id_issued_at: Some(client.id.datetime().into()),
        client_secret_expires_at: None,
    };

    // We round-trip back to the metadata to output it in the response
    // This should never fail, as the client is valid
    let metadata = client.into_metadata().validate()?;

    repo.save().await?;

    Ok(RegistrationRouteOutcome { response, metadata })
}

/// Extract the tagged (locale-specific) variants from `metadata` into a
/// [`LocalizedClientMetadata`] suitable for
/// [`OAuthClientRepository::replace_localized_metadata`]. The
/// non-localised default is *not* copied — that already lives on the
/// `oauth_clients` row itself.
fn collect_localized_metadata(metadata: &VerifiedClientMetadata) -> LocalizedClientMetadata {
    let mut out = LocalizedClientMetadata::default();

    if let Some(name) = metadata.client_name.as_ref() {
        for (tag, value) in name.iter() {
            if let Some(tag) = tag {
                out.client_name
                    .insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(logo) = metadata.logo_uri.as_ref() {
        for (tag, value) in logo.iter() {
            if let Some(tag) = tag {
                out.logo_uri.insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(uri) = metadata.client_uri.as_ref() {
        for (tag, value) in uri.iter() {
            if let Some(tag) = tag {
                out.client_uri
                    .insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(uri) = metadata.policy_uri.as_ref() {
        for (tag, value) in uri.iter() {
            if let Some(tag) = tag {
                out.policy_uri
                    .insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }
    if let Some(uri) = metadata.tos_uri.as_ref() {
        for (tag, value) in uri.iter() {
            if let Some(tag) = tag {
                out.tos_uri.insert(tag.as_str().to_owned(), value.clone());
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_suffix_list() {
        fn url_is_public_suffix(url: &str) -> bool {
            host_is_public_suffix(&Url::parse(url).unwrap())
        }

        assert!(url_is_public_suffix("https://.com"));
        assert!(url_is_public_suffix("https://.com."));
        assert!(url_is_public_suffix("https://co.uk"));
        assert!(url_is_public_suffix("https://github.io"));
        assert!(!url_is_public_suffix("https://example.com"));
        assert!(!url_is_public_suffix("https://example.com."));
        assert!(!url_is_public_suffix("https://x.com"));
        assert!(!url_is_public_suffix("https://x.com."));
        assert!(!url_is_public_suffix("https://arkret.github.io"));
        assert!(!url_is_public_suffix("http://localhost"));
        assert!(!url_is_public_suffix("arkret:/callback"));
        assert!(!url_is_public_suffix("http://somerandominternaldomain"));
    }

    // Integration tests would need to be updated for Salvo's test utilities
}
