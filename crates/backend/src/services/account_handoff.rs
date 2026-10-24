//! Durable account-handoff creation and onboarding projection.
//!
//! Callers own the transaction around OIDC authentication. Local code
//! consumption and creation share one transaction; federated authorization
//! has a durable checkpoint before this service resumes the final commit.
//! No HTTP request or response is used in this module.

use arkret_models_identity::{
    AccountHandoffBinding, AccountHandoffRequestBody, AccountHandoffResponseBody, Handle,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::Duration;
use coauth_data::{
    AccountHandoffAuthorizationCheckpoint, AccountHandoffCreation, AccountHandoffCreationAttempt,
    AccountHandoffCreationAttemptCommit, AccountHandoffCreationAttemptReserve,
    AccountHandoffCreationAttemptState, AccountHandoffGrant, AccountHandoffGrantInput,
    BoxRepository, IdentityCreationLeaseRiskDecision, RepositoryAccess as _, Ulid, new_id,
};
use http::StatusCode;
use rand_core::RngCore;

use crate::handlers::arkret::ArkretRouteError;
use crate::handlers::{make_clock, make_rng};

const HANDOFF_TTL: Duration = Duration::minutes(10);
const IDENTITY_CREATION_LEASE_TTL: Duration = Duration::minutes(15);

/// Transaction-neutral result of reserving a creation attempt.
/// The HTTP adapter commits only a fresh federated reservation before exchange.
pub(crate) enum CreationReservation {
    Fresh,
    Authorized(
        Box<(
            AccountHandoffCreationAttempt,
            AccountHandoffAuthorizationCheckpoint,
        )>,
    ),
    Completed(Vec<u8>),
}

pub(crate) fn classify_reservation(
    reservation: AccountHandoffCreationAttemptReserve,
) -> Result<CreationReservation, ArkretRouteError> {
    match reservation {
        AccountHandoffCreationAttemptReserve::Reserved(_) => Ok(CreationReservation::Fresh),
        AccountHandoffCreationAttemptReserve::Pending(attempt)
            if attempt.state == AccountHandoffCreationAttemptState::Authorized =>
        {
            let checkpoint = authorized_checkpoint(&attempt)?;
            Ok(CreationReservation::Authorized(Box::new((
                attempt, checkpoint,
            ))))
        }
        AccountHandoffCreationAttemptReserve::Replay(attempt) => {
            replay_handoff_outcome(attempt).map(CreationReservation::Completed)
        }
        AccountHandoffCreationAttemptReserve::Conflict(_) => Err(duplicate_handoff_conflict()),
        AccountHandoffCreationAttemptReserve::Pending(_)
        | AccountHandoffCreationAttemptReserve::Indeterminate(_) => {
            Err(indeterminate_handoff_replay())
        }
    }
}

/// Checkpoint classification without saving the caller's repository.
pub(crate) enum AuthorizationCheckpoint {
    Authorized(Box<AccountHandoffCreationAttempt>),
    Completed(Vec<u8>),
}

pub(crate) fn classify_authorization_checkpoint(
    result: AccountHandoffCreationAttemptCommit,
) -> Result<AuthorizationCheckpoint, ArkretRouteError> {
    match result {
        AccountHandoffCreationAttemptCommit::Committed(attempt)
            if attempt.state == AccountHandoffCreationAttemptState::Authorized =>
        {
            Ok(AuthorizationCheckpoint::Authorized(Box::new(attempt)))
        }
        AccountHandoffCreationAttemptCommit::Replay(attempt) => {
            replay_handoff_outcome(attempt).map(AuthorizationCheckpoint::Completed)
        }
        AccountHandoffCreationAttemptCommit::Conflict(_) => Err(duplicate_handoff_conflict()),
        AccountHandoffCreationAttemptCommit::Committed(_)
        | AccountHandoffCreationAttemptCommit::Indeterminate(_) => {
            Err(indeterminate_handoff_replay())
        }
    }
}

pub(crate) fn redacted_handoff_intent(
    body: &AccountHandoffRequestBody,
    holder_jkt: &str,
) -> Result<Vec<u8>, ArkretRouteError> {
    let mut request = serde_json::to_value(body)?;
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
            let bytes = arkret_canonical::canonical_json_bytes(value)?;
            proof.insert(
                field.to_owned(),
                serde_json::Value::String(sha256_hash(&bytes)?.to_string()),
            );
        }
    }
    Ok(arkret_canonical::canonical_json_bytes(
        &serde_json::json!({
            "request": request,
            "holder_jkt": holder_jkt,
        }),
    )?)
}

pub(crate) fn sha256_hash(bytes: &[u8]) -> Result<arkret_identifiers::Hash, ArkretRouteError> {
    Ok(arkret_identifiers::Hash::new(
        arkret_canonical::sha256_digest(bytes),
    )?)
}

pub(crate) fn authorized_checkpoint(
    attempt: &AccountHandoffCreationAttempt,
) -> Result<AccountHandoffAuthorizationCheckpoint, ArkretRouteError> {
    attempt.authorization_checkpoint.clone().ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            "authorized account handoff attempt has no durable checkpoint",
        )
    })
}

pub(crate) async fn commit_authorized_handoff(
    factory: &coauth_data::BoxRepositoryFactory,
    config: &coauth_config::ArkretConfig,
    attempt: AccountHandoffCreationAttempt,
    checkpoint: AccountHandoffAuthorizationCheckpoint,
) -> Result<Vec<u8>, ArkretRouteError> {
    let mut repo = factory.create().await?;
    match finalize_handoff_creation(&mut repo, config, &attempt, &checkpoint).await {
        Ok(bytes) => {
            repo.save().await?;
            Ok(bytes)
        }
        Err(error) => {
            repo.cancel().await.ok();
            Err(error)
        }
    }
}

/// Create the handoff grant and identity-creation lease and record the exact
/// canonical outcome on the attempt, inside the caller's transaction.
///
/// Shared by the single-transaction local-issuer path (which saves once at
/// the end) and the federated resume path ([`commit_authorized_handoff`],
/// which opens and saves its own transaction).
pub(crate) async fn finalize_handoff_creation(
    repo: &mut BoxRepository,
    arkret_config: &coauth_config::ArkretConfig,
    attempt: &AccountHandoffCreationAttempt,
    checkpoint: &AccountHandoffAuthorizationCheckpoint,
) -> Result<Vec<u8>, ArkretRouteError> {
    let local_account_id = Ulid::from_string(&checkpoint.local_account_id)
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
    let account_subject = account_subject(
        &crate::services::station_trust::owning_station_id_for(arkret_config),
        local_account_id,
    )?;
    let creation = repo
        .account_handoff()
        .create_with_lease(AccountHandoffGrantInput {
            id: new_id(now, &mut *rng),
            request_id: attempt.request_id.clone(),
            request_digest: attempt.request_digest.clone(),
            local_account_id,
            browser_session_id,
            audience_id: checkpoint.audience_id.to_string(),
            account_subject: account_subject.clone(),
            // The checkpoint exists only after the OIDC bridge has rejected
            // accounts disallowed by the handoff authentication policy.
            // Carry that fail-closed risk conclusion into the atomic lease
            // acquisition transaction rather than re-inferring it in storage.
            risk_decision: IdentityCreationLeaseRiskDecision::Allowed,
            cnf_jkt: attempt.holder_jkt.clone(),
            account_handoff_grant: random_opaque(&mut *rng, 32),
            issued_at: now,
            expires_at: now + HANDOFF_TTL,
            lease_id: random_opaque(&mut *rng, 24),
            lease_expires_at: now + IDENTITY_CREATION_LEASE_TTL,
        })
        .await?;
    let outcome = creation_to_outcome(creation, account_handle, account_subject, preferred_locale)?;
    let canonical_outcome = arkret_canonical::canonical_json_bytes(&outcome)?;
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
        | AccountHandoffCreationAttemptCommit::Replay(committed) => committed
            .canonical_outcome
            .ok_or_else(indeterminate_handoff_replay),
        AccountHandoffCreationAttemptCommit::Conflict(_) => Err(duplicate_handoff_conflict()),
        AccountHandoffCreationAttemptCommit::Indeterminate(_) => {
            Err(indeterminate_handoff_replay())
        }
    }
}

pub(crate) fn replay_handoff_outcome(
    attempt: AccountHandoffCreationAttempt,
) -> Result<Vec<u8>, ArkretRouteError> {
    attempt
        .canonical_outcome
        .ok_or_else(indeterminate_handoff_replay)
}

pub(crate) fn duplicate_handoff_conflict() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
        "request_id was reused with a different canonical account-handoff intent",
    )
}

pub(crate) fn indeterminate_handoff_replay() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
        "account handoff creation is fenced but no exact recoverable outcome is available",
    )
}

fn creation_to_outcome(
    creation: AccountHandoffCreation,
    account_handle: Handle,
    account_subject: arkret_identifiers::Hash,
    preferred_locale: Option<arkret_locale::UiLocale>,
) -> Result<AccountHandoffResponseBody, ArkretRouteError> {
    let (grant, binding) = creation_binding(creation)?;
    let outcome = AccountHandoffResponseBody {
        request_id: grant.request_id,
        account_handle,
        account_subject,
        preferred_locale,
        account_handoff_grant: grant.account_handoff_grant,
        expires_at: grant.expires_at,
        allowed_operations: grant.allowed_operations,
        binding,
    };
    outcome.validate()?;
    Ok(outcome)
}

pub(crate) fn creation_binding(
    creation: AccountHandoffCreation,
) -> Result<(AccountHandoffGrant, AccountHandoffBinding), ArkretRouteError> {
    let result = match creation {
        AccountHandoffCreation::Active { grant, lease } => (
            grant,
            AccountHandoffBinding::IdentityCreationActive {
                identity_creation_lease: lease.wire_lease(),
            },
        ),
        AccountHandoffCreation::Busy {
            grant,
            retry_after_ms,
            expires_at,
        } => (
            grant,
            AccountHandoffBinding::IdentityCreationBusy {
                retry_after_ms,
                expires_at,
            },
        ),
        AccountHandoffCreation::Bound {
            grant,
            principal_id,
            did,
        } => (grant, AccountHandoffBinding::Bound { principal_id, did }),
        AccountHandoffCreation::RateLimited { retry_after_ms, .. } => {
            return Err(ArkretRouteError::rate_limited(
                format!("identity-creation lease is rate limited; retry after {retry_after_ms} ms"),
                retry_after_ms,
            ));
        }
        AccountHandoffCreation::RiskRejected { .. } => {
            return Err(ArkretRouteError::coded(
                StatusCode::FORBIDDEN,
                arkret_wire::ErrorCode::POLICY_DENIED,
                "account risk state does not permit identity creation",
            ));
        }
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
    Ok(result)
}

pub(crate) fn account_subject(
    account_authority_id: &arkret_identifiers::DidCoreId,
    local_account_id: Ulid,
) -> Result<arkret_identifiers::Hash, ArkretRouteError> {
    let value = serde_json::json!({
        "account_authority_id": account_authority_id,
        "local_account_id": local_account_id.to_string(),
    });
    Ok(arkret_identifiers::Hash::new(
        arkret_canonical::domain_prefixed_canonical_sha256("ak.account-subject.v1", &value)?,
    )?)
}

pub(crate) fn canonical_account_handle(
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
            Ok(Handle::prepare(&trust_domain_candidate)?)
        }
    }
}

pub(crate) fn random_opaque(rng: &mut (impl RngCore + ?Sized), bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rng.fill_bytes(&mut value);
    Base64UrlUnpadded::encode_string(&value)
}
