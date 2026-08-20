//! Canonical account-first handoff, lease, and identity-binding operations.
use arkret_models_identity::{
    ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, AccountHandoffAllowedOperation, AccountHandoffBinding,
    AccountHandoffOutcome, AccountHandoffRequestBody, AccountOnboardingGoal,
    AccountOnboardingSnapshot, DidBindingChallengeRequestBody, Handle,
    IdentityAbandonmentChallengeRequestBody, IdentityAbandonmentRequestBody,
    IdentityBindingChallengeRequestBody,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::Duration;
use coauth_data::{
    AccountHandoffAuthorizationCheckpoint, AccountHandoffCreation, AccountHandoffCreationAttempt,
    AccountHandoffCreationAttemptCommit, AccountHandoffCreationAttemptReserve,
    AccountHandoffCreationAttemptState, AccountHandoffGrant, AccountHandoffGrantInput,
    BoxRepository, DidBindingChallengeInput, DidBindingChallengeIssue,
    IdentityAbandonmentChallengeInput, IdentityAbandonmentChallengeIssue,
    IdentityAbandonmentCommit, IdentityAbandonmentCommitInput, IdentityBindingChallengeInput,
    IdentityBindingChallengeIssue, IdentityCreationLeaseRiskDecision,
    NewAccountHandoffCreationAttempt, RepositoryAccess as _, Ulid, new_id,
};
use rand_core::RngCore;
use salvo::prelude::*;
use sha2::Digest as _;

use super::session_grant::map_oidc_exchange_error;
use super::{ArkretRouteError, DepotExt, trust_domain_for};
use crate::handlers::account::auth::oidc_bridge::{
    OidcCodeExchangeInput, authenticate_local_handoff_code, exchange_oidc_code_for_account_handoff,
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
const IDENTITY_ABANDONMENT_CHALLENGE_TTL: Duration = Duration::minutes(5);
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

/// `POST /_arkret/gate/account/did-binding-challenges`.
#[handler]
pub async fn issue_did_binding_challenge(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<arkret_models_identity::DidBindingChallengeOutcome>, ArkretRouteError> {
    let (grant, _dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::IssueDidBindingChallenge,
    )
    .await?;
    enforce_handoff_operation(
        &grant,
        AccountHandoffAllowedOperation::IssueDidBindingChallenge,
    )?;
    let body: DidBindingChallengeRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;

    let arkret_config = depot.arkret_config()?;
    let account_subject = account_subject(
        &super::service_id_for(&arkret_config),
        grant.service_account_id,
    )?;
    let url_builder = depot.url_builder()?;
    let key_store = depot.key_store()?;
    let resolver = depot.did_resolver_service()?;
    let mut repo = depot.repo().await?;
    let resolution = resolver
        .resolve_did_binding_evidence(
            &depot.http_client()?,
            &url_builder,
            &arkret_config,
            &key_store,
            &mut repo,
            body.full_id.as_str(),
        )
        .await
        .map_err(|error| {
            failed_precondition(format!("published DID resolution failed: {error}"))
        })?;
    if resolution.document.id != body.full_id.as_str() {
        return Err(failed_precondition(
            "resolved DID document does not match the requested full_id",
        ));
    }
    let (did_version_id, log_head_digest, control_key_digest) =
        match resolution.closed_method_evidence {
            Some(arkret_models_identity::IdentityMethodEvidence::DidWebvh {
                version_id,
                log_head_digest,
                control_key_digest,
            }) => (
                version_id.as_str().to_owned(),
                log_head_digest,
                control_key_digest,
            ),
            None => {
                return Err(failed_precondition(
                    "resolver did not return requested closed did_webvh method evidence",
                ));
            }
        };
    let audience = arkret_identifiers::DidCoreId::new(grant.audience.clone())
        .map_err(|error| failed_precondition(error.to_string()))?;
    let trust_domain =
        arkret_identifiers::TrustDomainId::new(trust_domain_for(&url_builder, &arkret_config))
            .map_err(|error| failed_precondition(error.to_string()))?;
    let origin = url_builder.http_base().origin().ascii_serialization();
    let now = make_clock().now();
    let mut rng = make_rng();
    let issue = repo
        .account_handoff()
        .issue_did_binding_challenge(DidBindingChallengeInput {
            request_id: body.request_id,
            request_digest,
            issuing_handoff_grant_id: grant.id,
            service_account_id: grant.service_account_id,
            account_subject,
            principal_id: body.principal_id,
            full_id: body.full_id,
            did_version_id,
            log_head_digest,
            control_key_digest,
            witness_evidence: None,
            challenge_id: random_opaque(&mut *rng, 24),
            challenge: random_opaque(&mut *rng, 32),
            dpop_jkt: grant.cnf_jkt,
            audience,
            origin,
            trust_domain,
            issued_at: now,
            expires_at: now + IDENTITY_BINDING_CHALLENGE_TTL,
        })
        .await?;
    match issue {
        DidBindingChallengeIssue::Issued(challenge)
        | DidBindingChallengeIssue::Replay(challenge) => {
            repo.save().await?;
            Ok(Json(challenge.wire_outcome()))
        }
        DidBindingChallengeIssue::DuplicateConflict => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "request_id was reused for a different published-DID binding challenge",
            ))
        }
        DidBindingChallengeIssue::StaleRequest => {
            repo.cancel().await.ok();
            Err(failed_precondition(
                "published-DID binding challenge request is stale or already consumed",
            ))
        }
    }
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

    // The local-issuer path owns every piece of state the proof touches, so
    // it authenticates in-process and commits once; the federated path keeps
    // its durable fence around the external OIDC exchange. This is exactly
    // the `UpstreamOidcExchangeMode::LocalCoauth` condition of
    // `exchange_mode_for_issuer`; an unparseable issuer falls through to the
    // federated path, which rejects it as `proof_invalid` like before.
    if url::Url::parse(body.proof.issuer.trim())
        .is_ok_and(|issuer| issuer == url_builder.oidc_issuer())
    {
        return create_local_account_handoff(
            req,
            depot,
            &dpop_binding,
            &body,
            canonical_intent,
            canonical_intent_digest,
            authorization_code_digest,
            dpop_jti_digest,
            request_digest,
        )
        .await;
    }

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
        requested_scope: Vec::new(),
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
        audience: arkret_identifiers::DidCoreId::new(authenticated.audience)
            .map_err(|error| failed_precondition(error.to_string()))?,
        account_handle: account_handle.to_string(),
        preferred_locale: preferred_locale.map(|locale| locale.code().to_owned()),
    };
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
                &checkpoint,
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

/// Local-issuer account-handoff creation as a single database transaction.
///
/// Unlike the federated path — which needs the durable `Reserved` fence
/// around the external OIDC token exchange — every effect of the local path
/// lives in this coauth's own persistence domain, so the attempt reservation,
/// authorization-code consumption, DPoP JTI consumption, handoff/lease
/// creation, and the exact canonical outcome all commit — or roll back —
/// together. No outbound HTTP happens between the first write and the single
/// `save()` at the end.
#[allow(clippy::too_many_arguments)]
async fn create_local_account_handoff(
    req: &Request,
    depot: &Depot,
    dpop_binding: &DpopSessionBinding,
    body: &AccountHandoffRequestBody,
    canonical_intent: Vec<u8>,
    canonical_intent_digest: arkret_identifiers::Hash,
    authorization_code_digest: arkret_identifiers::Hash,
    dpop_jti_digest: arkret_identifiers::Hash,
    request_digest: arkret_identifiers::Hash,
) -> Result<AccountHandoffCanonicalJson, ArkretRouteError> {
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let clock = make_clock();
    let now = clock.now();
    let mut repo = depot.repo().await?;
    let reservation = repo
        .account_handoff()
        .reserve_creation_attempt(NewAccountHandoffCreationAttempt {
            request_id: body.request_id.clone(),
            request_digest,
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
        AccountHandoffCreationAttemptReserve::Reserved(_) => {}
        // A durable `Authorized` attempt can only be a leftover from the
        // previous multi-transaction orchestration; resume it without
        // re-authenticating, exactly like the federated path does.
        AccountHandoffCreationAttemptReserve::Pending(attempt)
            if attempt.state == AccountHandoffCreationAttemptState::Authorized =>
        {
            repo.cancel().await.ok();
            return commit_authorized_handoff(
                depot,
                attempt.clone(),
                authorized_checkpoint(&attempt)?,
            )
            .await;
        }
        AccountHandoffCreationAttemptReserve::Replay(attempt) => {
            repo.cancel().await.ok();
            return replay_handoff_outcome(attempt);
        }
        AccountHandoffCreationAttemptReserve::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(duplicate_handoff_conflict());
        }
        AccountHandoffCreationAttemptReserve::Pending(_)
        | AccountHandoffCreationAttemptReserve::Indeterminate(_) => {
            repo.cancel().await.ok();
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
        requested_scope: Vec::new(),
    };
    let authenticated =
        match authenticate_local_handoff_code(depot, &mut repo, &clock, &input).await {
            Ok(authenticated) => authenticated,
            Err(error) => {
                repo.cancel().await.ok();
                tracing::error!(
                    error_code = error.code,
                    error_message = %error.message,
                    "local OIDC authentication failed while creating an account handoff",
                );
                return Err(map_oidc_exchange_error(error));
            }
        };
    if authenticated.audience != proof.audience.as_str() {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "authenticated handoff audience does not match the request proof",
        ));
    }

    // Consume the authorization code in the same transaction. A concurrent
    // consumer of the same code serialized on the grant row lock taken during
    // validation and has already lost.
    repo.oauth_authorization_grant()
        .exchange(&clock, authenticated.authorization_grant)
        .await?;

    let consumed = repo
        .dpop_replay()
        .consume_jti(dpop_replay_record(&dpop_binding.jti, now))
        .await?;
    if !consumed {
        repo.cancel().await.ok();
        return Err(indeterminate_handoff_replay());
    }

    let account_handle = canonical_account_handle(
        &authenticated.user.localpart,
        url_builder.public_hostname(),
        arkret_config.trust_domain.as_deref(),
    )?;
    let checkpoint = AccountHandoffAuthorizationCheckpoint {
        service_account_id: authenticated.user.id.to_string(),
        browser_session_id: Some(authenticated.browser_session_id.to_string()),
        audience: arkret_identifiers::DidCoreId::new(authenticated.audience)
            .map_err(|error| failed_precondition(error.to_string()))?,
        account_handle: account_handle.to_string(),
        preferred_locale: authenticated
            .user
            .preferred_locale
            .map(|locale| locale.code().to_owned()),
    };
    let checkpoint_result = repo
        .account_handoff()
        .checkpoint_creation_authorization(
            &body.request_id,
            &canonical_intent_digest,
            &checkpoint,
            now,
        )
        .await?;
    let authorized_attempt = match checkpoint_result {
        AccountHandoffCreationAttemptCommit::Committed(attempt)
            if attempt.state == AccountHandoffCreationAttemptState::Authorized =>
        {
            attempt
        }
        AccountHandoffCreationAttemptCommit::Replay(attempt) => {
            repo.cancel().await.ok();
            return replay_handoff_outcome(attempt);
        }
        AccountHandoffCreationAttemptCommit::Conflict(_) => {
            repo.cancel().await.ok();
            return Err(duplicate_handoff_conflict());
        }
        AccountHandoffCreationAttemptCommit::Committed(_)
        | AccountHandoffCreationAttemptCommit::Indeterminate(_) => {
            repo.cancel().await.ok();
            return Err(indeterminate_handoff_replay());
        }
    };

    let bytes = match finalize_handoff_creation(
        &mut repo,
        &arkret_config,
        &authorized_attempt,
        &checkpoint,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            repo.cancel().await.ok();
            return Err(error);
        }
    };
    repo.save().await?;

    // Replace the activity side effect the removed self-call produced on the
    // token/introspection/userinfo handlers; recorded once, after the commit.
    crate::handlers::account::extract_bound_activity_tracker(req, depot)
        .record_oauth_session(&clock, &authenticated.oauth_session)
        .await;
    Ok(AccountHandoffCanonicalJson(bytes))
}

/// Read-only reconciliation surface for an unexpired account handoff. The
/// Account Authority reloads the durable lease/binding state on every call;
/// no client checkpoint participates in the projection. A handoff consumed by
/// its completed register command remains valid for this read-only projection
/// until its original expiry so response-loss recovery can observe `bound`.
#[handler]
pub async fn account_onboarding_snapshot(
    req: &Request,
    depot: &Depot,
) -> Result<Json<AccountOnboardingSnapshot>, ArkretRouteError> {
    let (grant, _dpop) = authenticate_account_handoff_snapshot(req, depot).await?;
    let observed_at = make_clock().now();
    let account_subject = account_subject(
        &super::service_id_for(&depot.arkret_config()?),
        grant.service_account_id,
    )?;
    let mut repo = depot.repo().await?;
    let creation = repo
        .account_handoff()
        .resolve_creation(&grant, observed_at)
        .await?;
    let (resolved_grant, binding) = creation_binding(creation)?;
    if resolved_grant.id != grant.id || resolved_grant.request_id != grant.request_id {
        repo.cancel().await.ok();
        return Err(indeterminate_handoff_replay());
    }
    let goal = if let AccountHandoffBinding::IdentityCreationActive {
        identity_creation_lease,
    } = &binding
        && identity_creation_lease
            .allowed_goals()
            .contains(&arkret_models_identity::IdentityCreationGoal::AbandonProvisionalIdentity)
    {
        let audience = arkret_identifiers::DidCoreId::new(grant.audience.clone())
            .map_err(|error| failed_precondition(error.to_string()))?;
        repo.account_handoff()
            .active_identity_abandonment_challenge(
                grant.service_account_id,
                &audience,
                &identity_creation_lease.identity_creation_lease_id,
                observed_at,
            )
            .await?
            .map_or(AccountOnboardingGoal::CompleteIdentity, |challenge| {
                AccountOnboardingGoal::AbandonProvisionalIdentity {
                    fresh_authentication_required: challenge.issuing_handoff_grant_id == grant.id,
                    challenge: challenge.wire_outcome(),
                }
            })
    } else {
        AccountOnboardingGoal::CompleteIdentity
    };
    repo.cancel().await.ok();
    let snapshot = AccountOnboardingSnapshot {
        handoff_request_id: grant.request_id,
        account_subject,
        observed_at,
        binding,
        goal,
    };
    snapshot
        .validate()
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
    let (binding_state, lease_state) = match &snapshot.binding {
        AccountHandoffBinding::IdentityCreationActive {
            identity_creation_lease,
        } => (
            "identity_creation_active",
            Some(identity_creation_lease.state.as_str()),
        ),
        AccountHandoffBinding::IdentityCreationBusy { .. } => ("identity_creation_busy", None),
        AccountHandoffBinding::Bound { .. } => ("bound", None),
    };
    tracing::info!(
        handoff_request_id = %snapshot.handoff_request_id,
        binding_state,
        lease_state,
        goal = ?snapshot.goal.kind(),
        "projected authoritative account onboarding state"
    );
    Ok(Json(snapshot))
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
    attempt.authorization_checkpoint.clone().ok_or_else(|| {
        ArkretRouteError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            "authorized account handoff attempt has no durable checkpoint",
        )
    })
}

async fn commit_authorized_handoff(
    depot: &Depot,
    attempt: AccountHandoffCreationAttempt,
    checkpoint: AccountHandoffAuthorizationCheckpoint,
) -> Result<AccountHandoffCanonicalJson, ArkretRouteError> {
    let mut repo = depot.repo().await?;
    match finalize_handoff_creation(&mut repo, &depot.arkret_config()?, &attempt, &checkpoint).await
    {
        Ok(bytes) => {
            repo.save().await?;
            Ok(AccountHandoffCanonicalJson(bytes))
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
async fn finalize_handoff_creation(
    repo: &mut BoxRepository,
    arkret_config: &coauth_config::ArkretConfig,
    attempt: &AccountHandoffCreationAttempt,
    checkpoint: &AccountHandoffAuthorizationCheckpoint,
) -> Result<Vec<u8>, ArkretRouteError> {
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
    let account_subject =
        account_subject(&super::service_id_for(arkret_config), service_account_id)?;
    let creation = repo
        .account_handoff()
        .create_with_lease(AccountHandoffGrantInput {
            id: new_id(now, &mut *rng),
            request_id: attempt.request_id.clone(),
            request_digest: attempt.request_digest.clone(),
            service_account_id,
            browser_session_id,
            audience: checkpoint.audience.to_string(),
            account_subject: account_subject.clone(),
            // The checkpoint exists only after the OIDC bridge has rejected
            // locked, suspended, deactivated, or otherwise invalid accounts.
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
        | AccountHandoffCreationAttemptCommit::Replay(committed) => committed
            .canonical_outcome
            .ok_or_else(indeterminate_handoff_replay),
        AccountHandoffCreationAttemptCommit::Conflict(_) => Err(duplicate_handoff_conflict()),
        AccountHandoffCreationAttemptCommit::Indeterminate(_) => {
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
    let principal_id = arkret_identifiers::project_full_id_to_core_id(&body.full_id)
        .map_err(|error| failed_precondition(error.to_string()))?;
    if body.full_id != body.did_operation.did || validated.principal_id != principal_id {
        return Err(failed_precondition(
            "identity creation full_id/core projection does not match the inception operation",
        ));
    }

    let arkret_config = depot.arkret_config()?;
    let account_subject = account_subject(
        &super::service_id_for(&arkret_config),
        grant.service_account_id,
    )?;
    let url_builder = depot.url_builder()?;
    let trust_domain = trust_domain_for(&url_builder, &arkret_config);
    let trust_domain = arkret_identifiers::TrustDomainId::new(trust_domain)
        .map_err(|error| failed_precondition(error.to_string()))?;
    let audience = arkret_identifiers::DidCoreId::new(grant.audience.clone())
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
            audience: audience.clone(),
            lease_id: body.identity_creation_lease_id,
            lease_fence: body.lease_fence,
            holder_jkt: grant.cnf_jkt.clone(),
            did_operation: body.did_operation,
            principal_id,
            full_id: body.full_id,
            operation_digest: validated.operation_digest,
            account_subject,
            did_version_id: validated.did_version_id,
            log_head_digest: validated.log_head_digest,
            control_key_digest: validated.control_key_digest,
            pcr_realm_id: body.pcr_realm_id,
            realm_create_payload_digest: body.realm_create_payload_digest,
            founding_authorize_payload_digest: body.founding_authorize_payload_digest,
            initial_session_request_digest: body.initial_session_request_digest,
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
        IdentityBindingChallengeIssue::RateLimited { retry_after_ms } => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::rate_limited(
                format!(
                    "identity-creation lease renewal is rate limited; retry after {retry_after_ms} ms"
                ),
                retry_after_ms,
            ))
        }
    }
}

/// `POST /_arkret/gate/account/identity-abandonment-challenges`.
#[handler]
pub async fn issue_identity_abandonment_challenge(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<arkret_models_identity::IdentityAbandonmentChallengeOutcome>, ArkretRouteError> {
    let (grant, _dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::IssueIdentityAbandonmentChallenge,
    )
    .await?;
    let body: IdentityAbandonmentChallengeRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    body.validate()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let arkret_config = depot.arkret_config()?;
    let account_subject = account_subject(
        &super::service_id_for(&arkret_config),
        grant.service_account_id,
    )?;
    let url_builder = depot.url_builder()?;
    let trust_domain =
        arkret_identifiers::TrustDomainId::new(trust_domain_for(&url_builder, &arkret_config))
            .map_err(|error| failed_precondition(error.to_string()))?;
    let audience = arkret_identifiers::DidCoreId::new(grant.audience.clone())
        .map_err(|error| failed_precondition(error.to_string()))?;
    let origin = url_builder.http_base().origin().ascii_serialization();
    let now = make_clock().now();
    let mut rng = make_rng();
    let mut repo = depot.repo().await?;
    let issue = repo
        .account_handoff()
        .issue_identity_abandonment_challenge(IdentityAbandonmentChallengeInput {
            request_id: body.request_id,
            request_digest,
            issuing_handoff_grant_id: grant.id,
            service_account_id: grant.service_account_id,
            audience: audience.clone(),
            account_subject,
            holder_jkt: grant.cnf_jkt.clone(),
            lease_id: body.identity_creation_lease_id,
            lease_fence: body.lease_fence,
            principal_id: body.principal_id,
            did_version_id: body.did_version_id,
            challenge_id: random_opaque(&mut *rng, 24),
            challenge: random_opaque(&mut *rng, 32),
            origin,
            trust_domain,
            issued_at: now,
            expires_at: now + IDENTITY_ABANDONMENT_CHALLENGE_TTL,
        })
        .await?;
    match issue {
        IdentityAbandonmentChallengeIssue::Issued(challenge)
        | IdentityAbandonmentChallengeIssue::Replay(challenge) => {
            let outcome = challenge.wire_outcome();
            outcome
                .validate()
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
            if outcome.audience != audience {
                repo.cancel().await.ok();
                return Err(failed_precondition(
                    "persisted abandonment challenge audience does not match the handoff",
                ));
            }
            repo.save().await?;
            Ok(Json(outcome))
        }
        IdentityAbandonmentChallengeIssue::DuplicateConflict => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "request_id was reused with a different abandonment challenge intent",
            ))
        }
        IdentityAbandonmentChallengeIssue::LeaseFenced => {
            repo.cancel().await.ok();
            Err(identity_abandonment_error(
                arkret_wire::ReasonCode::IDENTITY_CREATION_LEASE_FENCED,
                "identity-creation lease is absent, expired, held by another key, or fenced",
            ))
        }
        IdentityAbandonmentChallengeIssue::CheckpointMismatch => {
            repo.cancel().await.ok();
            Err(failed_precondition(
                "principal_id or did_version_id does not match the published-DID checkpoint",
            ))
        }
        IdentityAbandonmentChallengeIssue::AlreadyAccepted => {
            repo.cancel().await.ok();
            Err(identity_abandonment_error(
                arkret_wire::ReasonCode::IDENTITY_CREATION_ALREADY_ACCEPTED,
                "the Principal Control Realm has already been accepted",
            ))
        }
    }
}

/// `POST /_arkret/gate/account/identity-abandonments`.
#[handler]
pub async fn abandon_identity_creation(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<arkret_models_identity::IdentityAbandonmentOutcome>, ArkretRouteError> {
    let (grant, _dpop) = authenticate_account_handoff(
        req,
        depot,
        AccountHandoffAllowedOperation::AbandonIdentityCreation,
    )
    .await?;
    let body: IdentityAbandonmentRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    body.validate()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let request_digest = body
        .canonical_request_digest()
        .map_err(|error| ArkretRouteError::BadRequest(error.to_string()))?;
    let audience = arkret_identifiers::DidCoreId::new(grant.audience.clone())
        .map_err(|error| failed_precondition(error.to_string()))?;
    let mut repo = depot.repo().await?;
    let commit = repo
        .account_handoff()
        .abandon_identity_creation(IdentityAbandonmentCommitInput {
            request_id: body.request_id,
            request_digest,
            confirming_handoff_grant_id: grant.id,
            service_account_id: grant.service_account_id,
            audience,
            holder_jkt: grant.cnf_jkt,
            challenge_id: body.challenge_id,
            challenge: body.challenge,
            lease_id: body.identity_creation_lease_id,
            lease_fence: body.lease_fence,
            principal_id: body.principal_id,
            did_version_id: body.did_version_id,
            now: make_clock().now(),
        })
        .await?;
    match commit {
        IdentityAbandonmentCommit::Abandoned(outcome)
        | IdentityAbandonmentCommit::Replay(outcome) => {
            repo.save().await?;
            Ok(Json(outcome))
        }
        IdentityAbandonmentCommit::DuplicateConflict => {
            repo.cancel().await.ok();
            Err(ArkretRouteError::coded(
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::DUPLICATE_CONFLICT,
                "request_id was reused with a different abandonment intent",
            ))
        }
        IdentityAbandonmentCommit::GrantReused => {
            repo.cancel().await.ok();
            Err(proof_invalid(
                "abandonment confirmation must use a fresh account handoff grant",
            ))
        }
        IdentityAbandonmentCommit::ChallengeExpired => {
            repo.cancel().await.ok();
            Err(identity_abandonment_error(
                arkret_wire::ReasonCode::IDENTITY_CREATION_CHALLENGE_EXPIRED,
                "identity-abandonment challenge expired",
            ))
        }
        IdentityAbandonmentCommit::ChallengeConsumed => {
            repo.cancel().await.ok();
            Err(identity_abandonment_error(
                arkret_wire::ReasonCode::IDENTITY_CREATION_CHALLENGE_ALREADY_CONSUMED,
                "identity-abandonment challenge was already consumed",
            ))
        }
        IdentityAbandonmentCommit::LeaseFenced => {
            repo.cancel().await.ok();
            Err(identity_abandonment_error(
                arkret_wire::ReasonCode::IDENTITY_CREATION_LEASE_FENCED,
                "identity-creation lease is absent, expired, held by another key, or fenced",
            ))
        }
        IdentityAbandonmentCommit::AlreadyAccepted => {
            repo.cancel().await.ok();
            Err(identity_abandonment_error(
                arkret_wire::ReasonCode::IDENTITY_CREATION_ALREADY_ACCEPTED,
                "the Principal Control Realm has already been accepted",
            ))
        }
        IdentityAbandonmentCommit::UnknownChallenge
        | IdentityAbandonmentCommit::ChallengeMismatch => {
            repo.cancel().await.ok();
            Err(failed_precondition(
                "abandonment challenge does not match the authenticated holder and checkpoint",
            ))
        }
    }
}

pub(crate) async fn authenticate_account_handoff(
    req: &Request,
    depot: &Depot,
    operation: AccountHandoffAllowedOperation,
) -> Result<(AccountHandoffGrant, DpopVerification), ArkretRouteError> {
    authenticate_account_handoff_inner(req, depot, Some(operation)).await
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
    operation: Option<AccountHandoffAllowedOperation>,
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
    match operation {
        Some(operation) => enforce_handoff_operation(&grant, operation)?,
        None if grant.allowed_operations != ACCOUNT_HANDOFF_ALLOWED_OPERATIONS => {
            return Err(ArkretRouteError::Forbidden(
                "account handoff has a non-canonical operation set".to_owned(),
            ));
        }
        None => {}
    }
    repo.cancel().await.ok();

    let dpop = dpop_header_from_request(req)
        .ok_or_else(|| proof_invalid("account handoff request requires a DPoP proof"))?;
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let verification = depot
        .dpop_verifier()?
        .verify(&dpop, req.method().as_str(), &htu, now, Some(token))
        .await
        .map_err(|error| proof_invalid(format!("account handoff DPoP proof failed: {error}")))?;
    if verification.jkt != grant.cnf_jkt {
        return Err(proof_invalid(
            "account handoff DPoP key does not match the credential cnf.jkt",
        ));
    }
    Ok((grant, verification))
}

async fn authenticate_account_handoff_snapshot(
    req: &Request,
    depot: &Depot,
) -> Result<(AccountHandoffGrant, DpopVerification), ArkretRouteError> {
    let token = account_handoff_authorization(req)?;
    let now = chrono::Utc::now();
    let mut repo = depot.repo().await?;
    let grant = repo
        .account_handoff()
        .get_by_token(token, now)
        .await?
        .ok_or_else(|| {
            ArkretRouteError::coded(
                StatusCode::UNAUTHORIZED,
                arkret_wire::ErrorCode::UNAUTHENTICATED,
                "account handoff is expired, revoked, or unknown",
            )
        })?;
    if grant.allowed_operations != ACCOUNT_HANDOFF_ALLOWED_OPERATIONS {
        repo.cancel().await.ok();
        return Err(ArkretRouteError::Forbidden(
            "account handoff has a non-canonical operation set".to_owned(),
        ));
    }
    repo.cancel().await.ok();

    let dpop = dpop_header_from_request(req)
        .ok_or_else(|| proof_invalid("account handoff request requires a DPoP proof"))?;
    let htu = dpop_htu(&depot.url_builder()?.http_base(), req);
    let verification = depot
        .dpop_verifier()?
        .verify(&dpop, req.method().as_str(), &htu, now, Some(token))
        .await
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
    account_subject: arkret_identifiers::Hash,
    preferred_locale: Option<arkret_locale::UiLocale>,
) -> Result<AccountHandoffOutcome, ArkretRouteError> {
    let (grant, binding) = creation_binding(creation)?;
    let outcome = AccountHandoffOutcome {
        request_id: grant.request_id,
        account_handle,
        account_subject,
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

fn creation_binding(
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
            full_id,
        } => (
            grant,
            AccountHandoffBinding::Bound {
                principal_id,
                full_id,
            },
        ),
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
    service_account_id: Ulid,
) -> Result<arkret_identifiers::Hash, ArkretRouteError> {
    let value = serde_json::json!({
        "account_authority_id": account_authority_id,
        "service_account_id": service_account_id.to_string(),
    });
    let mut bytes = b"ak.account-subject.v1\n".to_vec();
    bytes.extend(
        arkret_canonical::canonical_json_bytes(&value)
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?,
    );
    sha256_hash(&bytes)
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
        arkret_wire::ErrorCode::SIGNATURE_INVALID,
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

fn identity_abandonment_error(
    reason_code: &'static str,
    message: impl Into<String>,
) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        format!("reason_code={reason_code}; {}", message.into()),
    )
}

#[cfg(test)]
mod tests {
    use coauth_data::{AuthorizationCode, Pkce, SystemClock};
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_iana::oauth::{OAuthClientAuthenticationMethod, PkceCodeChallengeMethod};
    use coauth_jose::jwa::AsymmetricSigningKey;
    use coauth_jose::jwk::{JsonWebKeyPublicParameters, PublicJsonWebKey};
    use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
    use coauth_oauth_types::pkce::CodeChallengeMethodExt as _;
    use coauth_oauth_types::requests::{GrantType, ResponseMode};
    use coauth_oauth_types::scope::{OPENID, Scope};
    use diesel_async::RunQueryDsl as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand_core::OsRng;

    use super::*;
    use crate::handlers::test_utils::{
        RequestBuilderExt as _, ResponseExt as _, TEST_PRINCIPAL_SERVER_AUDIENCE, TestState, setup,
        unique_test_nonce,
    };
    use crate::services::dpop::DpopClaims;

    const HANDOFF_PATH: &str = "/_arkret/gate/account/authentication-handoffs";

    /// Seeded local-issuer state for one account-handoff exchange: a public
    /// OIDC client, a user with a browser session, an `openid` OAuth session,
    /// and a fulfilled authorization grant ready to be consumed.
    struct LocalHandoffSeed {
        client_id: String,
        authorization_code: String,
        code_verifier: String,
        redirect_uri: String,
        state: String,
        nonce: String,
        authorization_grant_id: Ulid,
    }

    async fn seed_local_handoff(state: &TestState, label: &str) -> LocalHandoffSeed {
        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng();
        let clock = SystemClock::default();
        let redirect_uri: url::Url = "https://client.example/callback".parse().unwrap();
        let client = repo
            .oauth_client()
            .add(
                &mut rng,
                &clock,
                vec![redirect_uri.clone()],
                None,
                None,
                None,
                vec![GrantType::AuthorizationCode],
                Some(format!("{label} client")),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(OAuthClientAuthenticationMethod::None),
                None,
                None,
            )
            .await
            .unwrap();
        let user = repo
            .user()
            .add(&mut rng, &clock, label.to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user, None)
            .await
            .unwrap();
        let scope = Scope::from_iter([OPENID]);
        let session = repo
            .oauth_session()
            .add_from_browser_session(&mut rng, &clock, &client, &browser_session, scope.clone())
            .await
            .unwrap();
        // PKCE verifiers must be 43-128 unreserved characters. Pad to a fixed
        // width that clears the lower bound for every label this helper is
        // called with: letting the label length decide made the shortest one
        // ("localok", 41 characters) fail `TooShort` while the others passed.
        let code_verifier = format!("{label}-verifier-{:0<64}", "");
        let code_challenge = PkceCodeChallengeMethod::S256
            .compute_challenge(&code_verifier)
            .unwrap()
            .into_owned();
        let authorization_code = format!("{label}-authorization-code");
        let grant = repo
            .oauth_authorization_grant()
            .add(
                &mut rng,
                &clock,
                &client,
                redirect_uri,
                scope,
                Some(AuthorizationCode {
                    code: authorization_code.clone(),
                    pkce: Some(Pkce {
                        challenge_method: PkceCodeChallengeMethod::S256,
                        challenge: code_challenge,
                    }),
                }),
                Some(format!("{label}-state")),
                Some(format!("{label}-nonce")),
                ResponseMode::Query,
                false,
                None,
                Some("en".to_owned()),
            )
            .await
            .unwrap();
        let grant = repo
            .oauth_authorization_grant()
            .fulfill(&clock, &session, grant)
            .await
            .unwrap();
        repo.save().await.unwrap();

        LocalHandoffSeed {
            client_id: client.client_id,
            authorization_code,
            code_verifier,
            redirect_uri: "https://client.example/callback".to_owned(),
            state: format!("{label}-state"),
            nonce: format!("{label}-nonce"),
            authorization_grant_id: grant.id,
        }
    }

    fn dpop_proof(signing: &SigningKey, jti: String) -> String {
        let verifying = signing.verifying_key();
        let public = PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(&verifying))
            .with_alg(JsonWebSignatureAlg::Ed25519);
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Ed25519)
            .with_typ("dpop+jwt".to_owned())
            .with_jwk(public);
        let signer = AsymmetricSigningKey::ed25519(signing.clone());
        let claims = DpopClaims {
            jti,
            htm: "POST".to_owned(),
            htu: format!("https://example.com{HANDOFF_PATH}"),
            iat: chrono::Utc::now().timestamp(),
            ath: None,
            nonce: None,
        };
        Jwt::sign(header, claims, &signer)
            .expect("DPoP sign")
            .into_string()
    }

    fn test_request_id(tag: u64) -> arkret_identifiers::RequestId {
        arkret_identifiers::RequestId::new(format!("ak:request:00000000-0000-7000-8000-{tag:012x}"))
            .unwrap()
    }

    fn local_handoff_request(
        state: &TestState,
        seed: &LocalHandoffSeed,
        signing: &SigningKey,
        request_id: arkret_identifiers::RequestId,
        jti: String,
        audience: &str,
        code_verifier: Option<&str>,
        state_value: Option<&str>,
    ) -> hyper::Request<String> {
        let proof = arkret_models_identity::UnsignedAccountHandoffAuthenticationProof {
            challenge: seed.nonce.clone(),
            audience: arkret_identifiers::DidCoreId::new(audience).unwrap(),
            issuer: state.url_builder.oidc_issuer().to_string(),
            client_id: seed.client_id.clone(),
            redirect_uri: seed.redirect_uri.clone(),
            state: state_value.unwrap_or(&seed.state).to_owned(),
            nonce: seed.nonce.clone(),
            authorization_code: seed.authorization_code.clone(),
            code_verifier: code_verifier.unwrap_or(&seed.code_verifier).to_owned(),
        };
        let unsigned =
            arkret_models_identity::UnsignedAccountHandoffRequestBody::new(request_id, proof)
                .unwrap();
        let signature = signing.sign(&unsigned.canonical_signing_bytes().unwrap());
        let body = unsigned
            .attach_signature(
                arkret_wire::Base64UrlString::new(Base64UrlUnpadded::encode_string(
                    &signature.to_bytes(),
                ))
                .unwrap(),
            )
            .unwrap();
        hyper::Request::post(HANDOFF_PATH)
            .header("dpop", dpop_proof(signing, jti))
            .json(body)
    }

    /// A `TestState` wired with the single configured principal server the
    /// audience resolution requires, or `None` when no test database is
    /// available.
    async fn local_handoff_state()
    -> Option<(TestState, coauth_storage_postgres::test_utils::TestDatabase)> {
        let database = coauth_storage_postgres::test_utils::setup_test_pool().await?;
        let state = TestState::from_pool_with_principal_server(database.clone())
            .await
            .unwrap();
        Some((state, database))
    }

    async fn grant_stage_label(state: &TestState, grant_id: Ulid) -> String {
        let mut repo = state.repository().await.unwrap();
        let grant = repo
            .oauth_authorization_grant()
            .lookup(grant_id)
            .await
            .unwrap()
            .expect("authorization grant should exist");
        repo.cancel().await.unwrap();
        match grant.stage {
            coauth_data::AuthorizationGrantStage::Pending => "pending".to_owned(),
            coauth_data::AuthorizationGrantStage::Fulfilled { .. } => "fulfilled".to_owned(),
            coauth_data::AuthorizationGrantStage::Exchanged { .. } => "exchanged".to_owned(),
            coauth_data::AuthorizationGrantStage::Cancelled { .. } => "cancelled".to_owned(),
        }
    }

    async fn table_count(state: &TestState, table: &str) -> i64 {
        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            count: i64,
        }
        let mut conn = state.repository_factory.pool().get().await.unwrap();
        diesel::sql_query(format!("SELECT COUNT(*) AS count FROM {table}"))
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .count
    }

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
                audience: arkret_identifiers::DidCoreId::new("ak:did_core:web:principal.example")
                    .unwrap(),
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

    /// Local-issuer handoff creation succeeds with an HTTP client that
    /// rejects every request, proving the flow performs zero issuer
    /// self-calls (discovery / token / userinfo) and mints no intermediate
    /// OAuth tokens.
    #[tokio::test]
    async fn local_handoff_succeeds_without_any_outbound_http() {
        setup();
        let Some((mut state, _database)) = local_handoff_state().await else {
            return;
        };
        state.http_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all("http://127.0.0.1:9").unwrap())
            .build()
            .unwrap();
        let seed = seed_local_handoff(&state, "localok").await;
        let signing = SigningKey::generate(&mut OsRng);
        let request_id = test_request_id(unique_test_nonce());

        let response = state
            .request(local_handoff_request(
                &state,
                &seed,
                &signing,
                request_id.clone(),
                format!("local-ok-jti-{}", unique_test_nonce()),
                TEST_PRINCIPAL_SERVER_AUDIENCE,
                None,
                None,
            ))
            .await;

        response.assert_status(StatusCode::OK);
        let outcome: serde_json::Value = response.json();
        assert_eq!(
            outcome["request_id"].as_str(),
            Some(request_id.as_str()),
            "outcome should echo the request id: {outcome}"
        );
        assert!(
            outcome["account_handoff_grant"].as_str().is_some(),
            "outcome should carry the handoff grant: {outcome}"
        );

        // The authorization code was consumed, but no intermediate OAuth
        // tokens were generated, and the attempt was committed exactly once.
        assert_eq!(
            grant_stage_label(&state, seed.authorization_grant_id).await,
            "exchanged"
        );
        assert_eq!(table_count(&state, "oauth_access_tokens").await, 0);
        assert_eq!(table_count(&state, "oauth_refresh_tokens").await, 0);
        assert_eq!(
            table_count(&state, "account_handoff_creation_attempts").await,
            1
        );
        assert_eq!(table_count(&state, "account_handoff_grants").await, 1);
        assert_eq!(table_count(&state, "identity_creation_leases").await, 1);
    }

    /// An exact retry of a committed request replays the stored canonical
    /// outcome byte for byte, without re-consuming anything.
    #[tokio::test]
    async fn local_handoff_exact_replay_returns_identical_outcome() {
        setup();
        let Some((state, _database)) = local_handoff_state().await else {
            return;
        };
        let seed = seed_local_handoff(&state, "localreplay").await;
        let signing = SigningKey::generate(&mut OsRng);
        let request_id = test_request_id(unique_test_nonce());
        let jti = format!("local-replay-jti-{}", unique_test_nonce());

        let first = state
            .request(local_handoff_request(
                &state,
                &seed,
                &signing,
                request_id.clone(),
                jti.clone(),
                TEST_PRINCIPAL_SERVER_AUDIENCE,
                None,
                None,
            ))
            .await;
        first.assert_status(StatusCode::OK);

        let second = state
            .request(local_handoff_request(
                &state,
                &seed,
                &signing,
                request_id,
                jti,
                TEST_PRINCIPAL_SERVER_AUDIENCE,
                None,
                None,
            ))
            .await;
        second.assert_status(StatusCode::OK);

        assert_eq!(
            first.body(),
            second.body(),
            "exact replay must return the byte-identical canonical outcome"
        );
        assert_eq!(
            table_count(&state, "account_handoff_creation_attempts").await,
            1
        );
        assert_eq!(table_count(&state, "account_handoff_grants").await, 1);
    }

    /// A failure after the attempt reservation (here: PKCE verifier
    /// mismatch) rolls the whole transaction back: the authorization code
    /// stays consumable, no attempt/handoff/lease row is left behind, and the
    /// same request id can be retried successfully.
    #[tokio::test]
    async fn local_handoff_mid_failure_leaves_no_durable_trace() {
        setup();
        let Some((state, _database)) = local_handoff_state().await else {
            return;
        };
        let seed = seed_local_handoff(&state, "localfail").await;
        let signing = SigningKey::generate(&mut OsRng);
        let request_id = test_request_id(unique_test_nonce());
        let jti = format!("local-fail-jti-{}", unique_test_nonce());

        let failed = state
            .request(local_handoff_request(
                &state,
                &seed,
                &signing,
                request_id.clone(),
                jti.clone(),
                TEST_PRINCIPAL_SERVER_AUDIENCE,
                Some("wrong-verifier-wrong-verifier-wrong-verifie"),
                None,
            ))
            .await;
        failed.assert_status(StatusCode::UNAUTHORIZED);
        let envelope: serde_json::Value = failed.json();
        assert_eq!(
            envelope["error"]["code"].as_str(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );

        assert_eq!(
            grant_stage_label(&state, seed.authorization_grant_id).await,
            "fulfilled",
            "the authorization code must stay unconsumed after a failed attempt"
        );
        assert_eq!(
            table_count(&state, "account_handoff_creation_attempts").await,
            0
        );
        assert_eq!(table_count(&state, "account_handoff_grants").await, 0);
        assert_eq!(table_count(&state, "identity_creation_leases").await, 0);

        // The same request id is not fenced: a corrected retry succeeds.
        let retried = state
            .request(local_handoff_request(
                &state,
                &seed,
                &signing,
                request_id,
                jti,
                TEST_PRINCIPAL_SERVER_AUDIENCE,
                None,
                None,
            ))
            .await;
        retried.assert_status(StatusCode::OK);
        assert_eq!(
            grant_stage_label(&state, seed.authorization_grant_id).await,
            "exchanged"
        );
    }

    /// Two concurrent handoffs over the same authorization code (different
    /// request ids and DPoP JTIs) serialize on the grant row lock: exactly
    /// one wins, and the loser gets the same `proof_invalid` envelope the old
    /// self-call path produced for an already-exchanged code.
    #[tokio::test]
    async fn local_handoff_concurrent_code_consumption_has_single_winner() {
        setup();
        let Some((state, _database)) = local_handoff_state().await else {
            return;
        };
        let seed = seed_local_handoff(&state, "localrace").await;
        let signing = SigningKey::generate(&mut OsRng);

        let first = state.request(local_handoff_request(
            &state,
            &seed,
            &signing,
            test_request_id(unique_test_nonce()),
            format!("local-race-jti-a-{}", unique_test_nonce()),
            TEST_PRINCIPAL_SERVER_AUDIENCE,
            None,
            None,
        ));
        let second = state.request(local_handoff_request(
            &state,
            &seed,
            &signing,
            test_request_id(unique_test_nonce()),
            format!("local-race-jti-b-{}", unique_test_nonce()),
            TEST_PRINCIPAL_SERVER_AUDIENCE,
            None,
            None,
        ));
        let (first, second) = tokio::join!(first, second);

        let statuses = [first.status(), second.status()];
        let ok_count = statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count();
        let rejected = [first, second]
            .into_iter()
            .filter(|response| response.status() == StatusCode::UNAUTHORIZED)
            .count();
        assert_eq!(ok_count, 1, "exactly one handoff must win: {statuses:?}");
        assert_eq!(
            rejected, 1,
            "the loser must be rejected with the proof_invalid envelope: {statuses:?}"
        );
        assert_eq!(
            grant_stage_label(&state, seed.authorization_grant_id).await,
            "exchanged"
        );
        assert_eq!(table_count(&state, "account_handoff_grants").await, 1);
        assert_eq!(table_count(&state, "identity_creation_leases").await, 1);
    }

    /// Error parity with the removed self-call path: binding failures surface
    /// as 401 `proof_invalid`, and an unconfigured audience as 400
    /// `audience_mismatch`.
    #[tokio::test]
    async fn local_handoff_binding_failures_match_self_call_baseline() {
        setup();
        let Some((state, _database)) = local_handoff_state().await else {
            return;
        };
        let seed = seed_local_handoff(&state, "localbind").await;
        let signing = SigningKey::generate(&mut OsRng);

        // Unknown authorization code.
        let unknown_code_seed = LocalHandoffSeed {
            authorization_code: "never-issued-code".to_owned(),
            ..seed_clone(&seed)
        };
        let response = state
            .request(local_handoff_request(
                &state,
                &unknown_code_seed,
                &signing,
                test_request_id(unique_test_nonce()),
                format!("local-bind-jti-a-{}", unique_test_nonce()),
                TEST_PRINCIPAL_SERVER_AUDIENCE,
                None,
                None,
            ))
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        let envelope: serde_json::Value = response.json();
        assert_eq!(
            envelope["error"]["code"].as_str(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );

        // Callback state mismatch.
        let response = state
            .request(local_handoff_request(
                &state,
                &seed,
                &signing,
                test_request_id(unique_test_nonce()),
                format!("local-bind-jti-b-{}", unique_test_nonce()),
                TEST_PRINCIPAL_SERVER_AUDIENCE,
                None,
                Some("attacker-supplied-state"),
            ))
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        let envelope: serde_json::Value = response.json();
        assert_eq!(
            envelope["error"]["code"].as_str(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );

        // Unconfigured audience.
        let response = state
            .request(local_handoff_request(
                &state,
                &seed,
                &signing,
                test_request_id(unique_test_nonce()),
                format!("local-bind-jti-c-{}", unique_test_nonce()),
                "ak:did_core:webvh:zUnconfiguredAudience",
                None,
                None,
            ))
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let envelope: serde_json::Value = response.json();
        assert_eq!(
            envelope["error"]["code"].as_str(),
            Some(arkret_wire::ErrorCode::AUDIENCE_MISMATCH)
        );

        // Every rejection rolled back: the code is still consumable.
        assert_eq!(
            grant_stage_label(&state, seed.authorization_grant_id).await,
            "fulfilled"
        );
        assert_eq!(
            table_count(&state, "account_handoff_creation_attempts").await,
            0
        );
    }

    fn seed_clone(seed: &LocalHandoffSeed) -> LocalHandoffSeed {
        LocalHandoffSeed {
            client_id: seed.client_id.clone(),
            authorization_code: seed.authorization_code.clone(),
            code_verifier: seed.code_verifier.clone(),
            redirect_uri: seed.redirect_uri.clone(),
            state: seed.state.clone(),
            nonce: seed.nonce.clone(),
            authorization_grant_id: seed.authorization_grant_id,
        }
    }
}
