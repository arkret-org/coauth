//! Canonical account-first handoff, lease, and identity-binding operations.
use arkret_models_identity::{
    ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, AccountHandoffAllowedOperation, AccountHandoffBinding,
    AccountHandoffOutcome, AccountHandoffRequestBody, Handle, IdentityBindingChallengeRequestBody,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::Duration;
use coauth_data::{
    AccountHandoffCreation, AccountHandoffCreationAttempt, AccountHandoffCreationAttemptCommit,
    AccountHandoffCreationAttemptReserve, AccountHandoffCreationAttemptState, AccountHandoffGrant,
    AccountHandoffGrantInput, IdentityBindingChallengeInput, IdentityBindingChallengeIssue,
    NewAccountHandoffCreationAttempt, RepositoryAccess as _, Ulid, new_id,
};
use rand_core::RngCore;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::session_grant::map_oidc_exchange_error;
use super::{ArkretRouteError, DepotExt, trust_domain_for};
use crate::handlers::account::auth::oidc_bridge::{
    OidcCodeExchangeInput, exchange_oidc_code_for_account_handoff,
};
use crate::handlers::account::auth::{
    DpopSessionBinding, extract_dpop_binding_for_kickoff_without_replay,
};
use crate::handlers::{make_clock, make_rng};
use crate::services::dpop::{
    DpopVerification, DpopVerifier, dpop_header_from_request, dpop_htu, dpop_replay_record,
};

const HANDOFF_TTL: Duration = Duration::minutes(10);
const IDENTITY_CREATION_LEASE_TTL: Duration = Duration::minutes(15);
const IDENTITY_BINDING_CHALLENGE_TTL: Duration = Duration::minutes(5);
const HANDOFF_ATTEMPT_RETENTION: Duration = Duration::days(7);

pub struct AccountHandoffCanonicalJson(Vec<u8>);

impl Scribe for AccountHandoffCanonicalJson {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
            .write_body(self.0)
            .expect("canonical JSON response body is writable");
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountHandoffAuthorizationCheckpoint {
    service_account_id: String,
    browser_session_id: Option<String>,
    audience: String,
    account_handle: String,
    preferred_locale: Option<String>,
}

/// `POST /_arkret/gate/account/authentication-handoffs`.
#[handler]
pub async fn create_account_handoff(
    req: &mut Request,
    depot: &Depot,
) -> Result<AccountHandoffCanonicalJson, ArkretRouteError> {
    if req.headers().contains_key(http::header::AUTHORIZATION) {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::UNAUTHENTICATED,
            "account handoff creation must not carry an Authorization credential",
        ));
    }
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let dpop_binding = extract_dpop_binding_for_kickoff_without_replay(req, depot, &url_builder)
        .map_err(|error| proof_invalid(format!("invalid account-handoff DPoP proof: {error}")))?
        .ok_or_else(|| proof_invalid("account handoff creation requires a DPoP proof"))?;
    let body: AccountHandoffRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    if body.proof.request_canonical_digest != request_digest {
        return Err(proof_invalid(
            "account handoff request_canonical_digest does not match the canonical request",
        ));
    }
    verify_handoff_holder_signature(&body, &dpop_binding)?;
    if body.proof.challenge != body.proof.nonce {
        return Err(proof_invalid(
            "account handoff challenge does not match the authorization transaction nonce",
        ));
    }

    let canonical_intent = redacted_handoff_intent(&body, &dpop_binding.jkt)?;
    let canonical_intent_digest = sha256_hash(&canonical_intent)?;
    let authorization_code_digest = sha256_hash(body.proof.authorization_code.as_bytes())?;
    let dpop_jti_digest = sha256_hash(dpop_binding.jti.as_bytes())?;
    let clock = make_clock();
    let now = clock.now();
    let mut reserve_repo = depot.repo().await?;
    let reservation = reserve_repo
        .account_handoff()
        .reserve_creation_attempt(NewAccountHandoffCreationAttempt {
            request_id: body.request_id.clone(),
            request_digest: request_digest.clone(),
            canonical_intent_digest: canonical_intent_digest.clone(),
            canonical_intent,
            holder_jkt: dpop_binding.jkt.clone(),
            issuer: body.proof.issuer.clone(),
            client_id: body.proof.client_id.clone(),
            authorization_code_digest,
            dpop_jti_digest,
            retained_until: now + HANDOFF_ATTEMPT_RETENTION,
            now,
        })
        .await?;
    match reservation {
        AccountHandoffCreationAttemptReserve::Reserved(_) => reserve_repo.save().await?,
        AccountHandoffCreationAttemptReserve::Pending(attempt)
            if attempt.state == AccountHandoffCreationAttemptState::Authorized =>
        {
            reserve_repo.cancel().await.ok();
            return commit_authorized_handoff(
                depot,
                attempt.clone(),
                authorized_checkpoint(&attempt)?,
            )
            .await;
        }
        AccountHandoffCreationAttemptReserve::Replay(attempt) => {
            reserve_repo.cancel().await.ok();
            return replay_handoff_outcome(attempt);
        }
        AccountHandoffCreationAttemptReserve::Conflict(_) => {
            reserve_repo.cancel().await.ok();
            return Err(duplicate_handoff_conflict());
        }
        AccountHandoffCreationAttemptReserve::Pending(_)
        | AccountHandoffCreationAttemptReserve::Indeterminate(_) => {
            reserve_repo.cancel().await.ok();
            return Err(indeterminate_handoff_replay());
        }
    }

    let proof = &body.proof;
    let input = OidcCodeExchangeInput {
        authorization_code: proof.authorization_code.clone(),
        code_verifier: proof.code_verifier.clone(),
        redirect_uri: proof.redirect_uri.clone(),
        issuer: proof.issuer.clone(),
        client_id: proof.client_id.clone(),
        state: proof.state.clone(),
        nonce: proof.nonce.clone(),
        device_id: String::new(),
        expected_principal_id: String::new(),
        requested_audience: Some(proof.audience.to_string()),
    };
    let authenticated =
        exchange_oidc_code_for_account_handoff(req, depot, dpop_binding.clone(), input)
            .await
            .map_err(|error| {
                tracing::error!(
                    error_code = error.code,
                    error_message = %error.message,
                    "OIDC exchange failed while creating an account handoff",
                );
                map_oidc_exchange_error(error)
            })?;
    if authenticated.audience != proof.audience.as_str() {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "authenticated handoff audience does not match the request proof",
        ));
    }
    let account_handle = canonical_account_handle(
        &authenticated.user.localpart,
        url_builder.public_hostname(),
        arkret_config.trust_domain.as_deref(),
    )?;
    let preferred_locale = authenticated.user.preferred_locale;
    let checkpoint = AccountHandoffAuthorizationCheckpoint {
        service_account_id: authenticated.user.id.to_string(),
        browser_session_id: authenticated.browser_session_id.map(|id| id.to_string()),
        audience: authenticated.audience,
        account_handle: account_handle.to_string(),
        preferred_locale: preferred_locale.map(|locale| locale.code().to_owned()),
    };
    let checkpoint_value = serde_json::to_value(&checkpoint)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let checkpoint_now = clock.now();
    let mut checkpoint_repo = depot.repo().await?;
    let consumed = checkpoint_repo
        .dpop_replay()
        .consume_jti(dpop_replay_record(&dpop_binding.jti, checkpoint_now))
        .await?;
    if !consumed {
        checkpoint_repo.cancel().await.ok();
        return Err(indeterminate_handoff_replay());
    }
    let checkpoint_result = {
        let mut handoff_repo = checkpoint_repo.account_handoff();
        handoff_repo
            .checkpoint_creation_authorization(
                &body.request_id,
                &canonical_intent_digest,
                &checkpoint_value,
                checkpoint_now,
            )
            .await?
    };
    let authorized_attempt = match checkpoint_result {
        AccountHandoffCreationAttemptCommit::Committed(attempt)
            if attempt.state == AccountHandoffCreationAttemptState::Authorized =>
        {
            checkpoint_repo.save().await?;
            attempt
        }
        AccountHandoffCreationAttemptCommit::Replay(attempt) => {
            checkpoint_repo.cancel().await.ok();
            return replay_handoff_outcome(attempt);
        }
        AccountHandoffCreationAttemptCommit::Conflict(_) => {
            checkpoint_repo.cancel().await.ok();
            return Err(duplicate_handoff_conflict());
        }
        AccountHandoffCreationAttemptCommit::Committed(_)
        | AccountHandoffCreationAttemptCommit::Indeterminate(_) => {
            checkpoint_repo.cancel().await.ok();
            return Err(indeterminate_handoff_replay());
        }
    };
    commit_authorized_handoff(depot, authorized_attempt, checkpoint).await
}

fn redacted_handoff_intent(
    body: &AccountHandoffRequestBody,
    holder_jkt: &str,
) -> Result<Vec<u8>, ArkretRouteError> {
    let mut request =
        serde_json::to_value(body).map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let proof = request
        .get_mut("proof")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            ArkretRouteError::BadRequest("account handoff proof is missing".to_owned())
        })?;
    for field in [
        "authorization_code",
        "code_verifier",
        "signature",
        "challenge",
        "state",
        "nonce",
    ] {
        if let Some(value) = proof.get(field) {
            let bytes = arkret_canonical::canonical_json_bytes(value)
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            proof.insert(
                field.to_owned(),
                serde_json::Value::String(sha256_hash(&bytes)?.to_string()),
            );
        }
    }
    arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "request": request,
        "holder_jkt": holder_jkt,
    }))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

fn sha256_hash(bytes: &[u8]) -> Result<arkret_identifiers::Hash, ArkretRouteError> {
    arkret_identifiers::Hash::new(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(bytes))
    ))
    .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

fn authorized_checkpoint(
    attempt: &AccountHandoffCreationAttempt,
) -> Result<AccountHandoffAuthorizationCheckpoint, ArkretRouteError> {
    let value = attempt.authorization_checkpoint.clone().ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            "authorized account handoff attempt has no durable checkpoint",
        )
    })?;
    serde_json::from_value(value).map_err(|_| indeterminate_handoff_replay())
}

async fn commit_authorized_handoff(
    depot: &Depot,
    attempt: AccountHandoffCreationAttempt,
    checkpoint: AccountHandoffAuthorizationCheckpoint,
) -> Result<AccountHandoffCanonicalJson, ArkretRouteError> {
    let service_account_id = Ulid::from_string(&checkpoint.service_account_id)
        .map_err(|_| indeterminate_handoff_replay())?;
    let browser_session_id = checkpoint
        .browser_session_id
        .as_deref()
        .map(Ulid::from_string)
        .transpose()
        .map_err(|_| indeterminate_handoff_replay())?;
    let account_handle =
        Handle::prepare(&checkpoint.account_handle).map_err(|_| indeterminate_handoff_replay())?;
    let preferred_locale = match checkpoint.preferred_locale.as_deref() {
        Some(value) => Some(
            arkret_locale::UiLocale::from_tag(value).ok_or_else(indeterminate_handoff_replay)?,
        ),
        None => None,
    };
    let now = make_clock().now();
    let mut rng = make_rng();
    let mut repo = depot.repo().await?;
    let creation = repo
        .account_handoff()
        .create_with_lease(AccountHandoffGrantInput {
            id: new_id(now, &mut *rng),
            request_id: attempt.request_id.clone(),
            request_digest: attempt.request_digest.clone(),
            service_account_id,
            browser_session_id,
            audience: checkpoint.audience,
            cnf_jkt: attempt.holder_jkt.clone(),
            account_handoff_grant: random_opaque(&mut *rng, 32),
            issued_at: now,
            expires_at: now + HANDOFF_TTL,
            lease_id: random_opaque(&mut *rng, 24),
            lease_expires_at: now + IDENTITY_CREATION_LEASE_TTL,
        })
        .await?;
    let outcome = creation_to_outcome(creation, account_handle, preferred_locale)?;
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let outcome_digest = sha256_hash(&canonical_outcome)?;
    let committed = repo
        .account_handoff()
        .commit_creation_attempt(
            &attempt.request_id,
            &attempt.canonical_intent_digest,
            &canonical_outcome,
            &outcome_digest,
            now,
        )
        .await?;
    match committed {
        AccountHandoffCreationAttemptCommit::Committed(committed)
        | AccountHandoffCreationAttemptCommit::Replay(committed) => {
            let bytes = committed
                .canonical_outcome
                .ok_or_else(indeterminate_handoff_replay)?;
            repo.save().await?;
            Ok(AccountHandoffCanonicalJson(bytes))
        }
        AccountHandoffCreationAttemptCommit::Conflict(_) => {
            repo.cancel().await.ok();
            Err(duplicate_handoff_conflict())
        }
        AccountHandoffCreationAttemptCommit::Indeterminate(_) => {
            repo.cancel().await.ok();
            Err(indeterminate_handoff_replay())
        }
    }
}

fn replay_handoff_outcome(
    attempt: AccountHandoffCreationAttempt,
) -> Result<AccountHandoffCanonicalJson, ArkretRouteError> {
    attempt
        .canonical_outcome
        .map(AccountHandoffCanonicalJson)
        .ok_or_else(indeterminate_handoff_replay)
}

fn duplicate_handoff_conflict() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        "request_id was reused with a different canonical account-handoff intent",
    )
}

fn indeterminate_handoff_replay() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
        "account handoff creation is fenced but no exact recoverable outcome is available",
    )
}

/// `POST /_arkret/gate/account/identity-binding-challenges`.
#[handler]
pub async fn issue_identity_binding_challenge(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<arkret_models_identity::IdentityBindingChallengeOutcome>, ArkretRouteError> {
    let (grant, _dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::IssueIdentityBindingChallenge,
    )
    .await?;
    enforce_handoff_operation(
        &grant,
        AccountHandoffAllowedOperation::IssueIdentityBindingChallenge,
    )?;
    let body: IdentityBindingChallengeRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let validated =
        arkret_signatures::webvh::validate_principal_inception_operation(&body.did_operation)
            .map_err(|error| failed_precondition(error.to_string()))?;
    if validated.document_profile
        != arkret_signatures::webvh::PrincipalDidDocumentProfile::ExternalAuthority
    {
        return Err(failed_precondition(
            "account-first identity creation requires the external enrollment-authority B model",
        ));
    }
    let key_store = depot.key_store()?;
    let enrollment_authority =
        crate::services::device_enrollment_authority::enrollment_authority(&key_store)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let expected_authority = enrollment_authority.did();
    if validated
        .enrollment_authority
        .as_ref()
        .map(arkret_identifiers::Did::as_str)
        != Some(expected_authority)
    {
        return Err(failed_precondition(
            "principal inception enrollment authority does not match the deployment pin",
        ));
    }

    let arkret_config = depot.arkret_config()?;
    let url_builder = depot.url_builder()?;
    let trust_domain = trust_domain_for(&url_builder, &arkret_config);
    let trust_domain = arkret_identifiers::TypedTrustDomainId::new(trust_domain)
        .map_err(|error| failed_precondition(error.to_string()))?;
    let audience = arkret_identifiers::Did::new(grant.audience.clone())
        .map_err(|error| failed_precondition(error.to_string()))?;
    let origin = depot
        .url_builder()?
        .http_base()
        .origin()
        .ascii_serialization();
    let clock = make_clock();
    let now = clock.now();
    let mut rng = make_rng();
    let mut repo = depot.repo().await?;
    let issue = repo
        .account_handoff()
        .reserve_and_issue_challenge(IdentityBindingChallengeInput {
            request_id: body.request_id,
            request_digest,
            service_account_id: grant.service_account_id,
            audience: grant.audience.clone(),
            lease_id: body.lease_id,
            lease_fence: body.lease_fence,
            holder_jkt: grant.cnf_jkt.clone(),
            did_operation: body.did_operation,
            operation_digest: validated.operation_digest,
            challenge_id: random_opaque(&mut *rng, 24),
            challenge: random_opaque(&mut *rng, 32),
            origin,
            trust_domain,
            issued_at: now,
            expires_at: now + IDENTITY_BINDING_CHALLENGE_TTL,
            lease_expires_at: now + IDENTITY_CREATION_LEASE_TTL,
        })
        .await?;
    match issue {
        IdentityBindingChallengeIssue::Issued(challenge)
        | IdentityBindingChallengeIssue::Replay(challenge) => {
            repo.save().await?;
            let outcome = challenge.wire_outcome();
            if outcome.audience != audience {
                return Err(failed_precondition(
                    "persisted challenge audience does not match the handoff",
                ));
            }
            Ok(Json(outcome))
        }
        IdentityBindingChallengeIssue::DuplicateConflict
        | IdentityBindingChallengeIssue::ReservationConflict => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "request or identity reservation conflicts with durable state",
            ))
        }
        IdentityBindingChallengeIssue::LeaseMismatch
        | IdentityBindingChallengeIssue::StaleRequest => {
            repo.cancel().await.ok();
            Err(failed_precondition(
                "identity-creation lease, fence, holder, or challenge request is stale",
            ))
        }
    }
}

pub(crate) async fn authenticate_account_handoff(
    req: &Request,
    depot: &Depot,
    operation: AccountHandoffAllowedOperation,
) -> Result<(AccountHandoffGrant, DpopVerification), ArkretRouteError> {
    authenticate_account_handoff_inner(req, depot, operation, true).await
}

pub(crate) async fn authenticate_account_handoff_without_replay(
    req: &Request,
    depot: &Depot,
    operation: AccountHandoffAllowedOperation,
) -> Result<(AccountHandoffGrant, DpopVerification), ArkretRouteError> {
    authenticate_account_handoff_inner(req, depot, operation, false).await
}

/// Re-authenticate possession of a presented handoff token without requiring
/// its mutable active/consumed row. Exact replay uses this before consulting
/// the issuer ledger; only a fresh Reserved operation subsequently loads and
/// consumes the active handoff row.
pub(crate) fn verify_account_handoff_holder_without_lookup(
    req: &Request,
    depot: &Depot,
) -> Result<(String, DpopVerification), ArkretRouteError> {
    let token = account_handoff_authorization(req)?.to_owned();
    let now = chrono::Utc::now();
    let dpop = dpop_header_from_request(req)
        .ok_or_else(|| proof_invalid("account handoff request requires a DPoP proof"))?;
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let verification =
        DpopVerifier::verify_without_replay(&dpop, req.method().as_str(), &htu, now, Some(&token))
            .map_err(|error| {
                proof_invalid(format!("account handoff DPoP proof failed: {error}"))
            })?;
    Ok((token, verification))
}

async fn authenticate_account_handoff_inner(
    req: &Request,
    depot: &Depot,
    operation: AccountHandoffAllowedOperation,
    consume_jti: bool,
) -> Result<(AccountHandoffGrant, DpopVerification), ArkretRouteError> {
    let token = account_handoff_authorization(req)?;
    let now = chrono::Utc::now();
    let mut repo = depot.repo().await?;
    let grant = repo
        .account_handoff()
        .get_active_by_token(token, now)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::UNAUTHENTICATED,
                "account handoff is expired, revoked, consumed, or unknown",
            )
        })?;
    enforce_handoff_operation(&grant, operation)?;
    repo.cancel().await.ok();

    let dpop = dpop_header_from_request(req)
        .ok_or_else(|| proof_invalid("account handoff request requires a DPoP proof"))?;
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let verification = if consume_jti {
        depot
            .dpop_verifier()?
            .verify(&dpop, req.method().as_str(), &htu, now, Some(token))
            .await
    } else {
        DpopVerifier::verify_without_replay(&dpop, req.method().as_str(), &htu, now, Some(token))
    }
    .map_err(|error| proof_invalid(format!("account handoff DPoP proof failed: {error}")))?;
    if verification.jkt != grant.cnf_jkt {
        return Err(proof_invalid(
            "account handoff DPoP key does not match the credential cnf.jkt",
        ));
    }
    Ok((grant, verification))
}

pub(crate) fn enforce_handoff_operation(
    grant: &AccountHandoffGrant,
    operation: AccountHandoffAllowedOperation,
) -> Result<(), ArkretRouteError> {
    if grant.allowed_operations != ACCOUNT_HANDOFF_ALLOWED_OPERATIONS
        || !grant.allowed_operations.contains(&operation)
    {
        return Err(ArkretRouteError::Forbidden(
            "account handoff does not authorize this operation".to_owned(),
        ));
    }
    Ok(())
}

fn account_handoff_authorization(req: &Request) -> Result<&str, ArkretRouteError> {
    let value = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::UNAUTHENTICATED,
                "Authorization: DPoP <account_handoff_grant> is required",
            )
        })?;
    let (scheme, token) = value.split_once(' ').ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::UNAUTHENTICATED,
            "account handoff Authorization header is malformed",
        )
    })?;
    if !scheme.eq_ignore_ascii_case("DPoP")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(ArkretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            arkret_wire::ErrorCode::UNAUTHENTICATED,
            "account handoff requires the DPoP authorization scheme",
        ));
    }
    Ok(token)
}

fn verify_handoff_holder_signature(
    body: &AccountHandoffRequestBody,
    dpop_binding: &DpopSessionBinding,
) -> Result<(), ArkretRouteError> {
    let jwk = serde_json::to_value(&dpop_binding.public_jwk)
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let public_key = arkret_signatures::proof::PublicKeyMaterial::Jwk { value: jwk };
    let signing_bytes = body
        .proof
        .canonical_signing_bytes()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    if !arkret_signatures::proof::verify_detached_ed25519_signature(
        &public_key,
        &signing_bytes,
        &body.proof.signature,
    ) {
        return Err(proof_invalid(
            "account handoff holder signature is not valid for the DPoP Ed25519 key",
        ));
    }
    Ok(())
}

fn creation_to_outcome(
    creation: AccountHandoffCreation,
    account_handle: Handle,
    preferred_locale: Option<arkret_locale::UiLocale>,
) -> Result<AccountHandoffOutcome, ArkretRouteError> {
    let (grant, binding) = match creation {
        AccountHandoffCreation::Active { grant, lease } => (
            grant,
            AccountHandoffBinding::IdentityCreationActive {
                identity_creation_lease: lease.wire_lease(),
            },
        ),
        AccountHandoffCreation::Busy {
            grant,
            retry_after_ms,
        } => (
            grant,
            AccountHandoffBinding::IdentityCreationBusy { retry_after_ms },
        ),
        AccountHandoffCreation::Bound {
            grant,
            principal_id,
        } => (grant, AccountHandoffBinding::Bound { principal_id }),
        AccountHandoffCreation::DuplicateConflict => {
            return Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "request_id was reused with different canonical request bytes",
            ));
        }
        AccountHandoffCreation::ExpiredReplay => {
            return Err(ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::UNAUTHENTICATED,
                "the replayed account handoff request is no longer live",
            ));
        }
    };
    let outcome = AccountHandoffOutcome {
        request_id: grant.request_id,
        account_handle,
        preferred_locale,
        account_handoff_grant: grant.account_handoff_grant,
        expires_at: grant.expires_at,
        allowed_operations: grant.allowed_operations,
        binding,
    };
    outcome
        .validate()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    Ok(outcome)
}

fn canonical_account_handle(
    localpart: &str,
    public_hostname: &str,
    configured_trust_domain: Option<&str>,
) -> Result<Handle, ArkretRouteError> {
    let public_candidate = format!("{localpart}:{public_hostname}");
    match Handle::prepare(&public_candidate) {
        Ok(handle) => Ok(handle),
        Err(public_error) => {
            let Some(scope) =
                configured_trust_domain.and_then(|value| value.strip_prefix("ak:trust_domain:"))
            else {
                return Err(ArkretRouteError::Internal(Box::new(public_error)));
            };
            let trust_domain_candidate = format!("{localpart}:{scope}");
            Handle::prepare(&trust_domain_candidate)
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
        }
    }
}

fn random_opaque(rng: &mut (impl RngCore + ?Sized), bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rng.fill_bytes(&mut value);
    Base64UrlUnpadded::encode_string(&value)
}

fn proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::INVALID_SIGNATURE,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn failed_precondition(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff_request() -> AccountHandoffRequestBody {
        let mut body = AccountHandoffRequestBody {
            request_id: arkret_identifiers::RequestId::new(
                "ak:request:018f4f17-71d8-7cc0-8b47-9d67c94d8f42",
            )
            .unwrap(),
            proof: arkret_models_identity::AccountHandoffAuthenticationProof {
                proof_kind:
                    arkret_models_identity::AccountHandoffAuthenticationProofKind::OidcCodeExchange,
                challenge: "private-challenge".to_owned(),
                request_canonical_digest: arkret_identifiers::Hash::new(format!(
                    "sha256:{}",
                    "0".repeat(64)
                ))
                .unwrap(),
                audience: arkret_identifiers::Did::new("did:web:principal.example").unwrap(),
                issuer: "https://issuer.example".to_owned(),
                client_id: "arkret-client".to_owned(),
                redirect_uri: "https://client.example/callback".to_owned(),
                state: "private-state".to_owned(),
                nonce: "private-nonce".to_owned(),
                authorization_code: "private-authorization-code".to_owned(),
                code_verifier: "private-code-verifier".to_owned(),
                signature: "private-signature".to_owned(),
            },
        };
        body.proof.request_canonical_digest = body.canonical_request_digest().unwrap();
        body
    }

    #[test]
    fn durable_handoff_intent_hashes_one_shot_secrets() {
        let body = handoff_request();
        let bytes = redacted_handoff_intent(&body, &"H".repeat(43)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for secret in [
            "private-challenge",
            "private-state",
            "private-nonce",
            "private-authorization-code",
            "private-code-verifier",
            "private-signature",
        ] {
            assert!(!text.contains(secret));
        }
        assert!(text.contains("https://issuer.example"));
        assert!(text.contains("arkret-client"));
        assert!(text.contains("sha256:"));
    }

    #[test]
    fn changing_one_shot_code_changes_the_durable_intent() {
        let first = handoff_request();
        let mut second = first.clone();
        second.proof.authorization_code = "different-authorization-code".to_owned();
        second.proof.request_canonical_digest = second.canonical_request_digest().unwrap();
        assert_ne!(
            redacted_handoff_intent(&first, &"H".repeat(43)).unwrap(),
            redacted_handoff_intent(&second, &"H".repeat(43)).unwrap()
        );
    }

    #[test]
    fn account_handle_uses_public_dns_hostname() {
        let handle = canonical_account_handle("Alice", "auth.example.com", None).unwrap();
        assert_eq!(handle.canonical(), "alice:auth.example.com");
    }

    #[test]
    fn account_handle_uses_explicit_trust_domain_for_loopback_deployment() {
        let handle =
            canonical_account_handle("Alice", "localhost", Some("ak:trust_domain:local.host"))
                .unwrap();
        assert_eq!(handle.canonical(), "alice:local.host");
    }

    #[test]
    fn account_handle_rejects_invalid_public_and_trust_domains() {
        assert!(canonical_account_handle("Alice", "localhost", None).is_err());
        assert!(
            canonical_account_handle(
                "Alice",
                "localhost",
                Some("ak:trust_domain:not_a_handle_domain"),
            )
            .is_err()
        );
    }
}
