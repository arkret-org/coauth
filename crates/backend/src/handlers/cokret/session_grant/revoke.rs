use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Duration, Utc};
use coauth_data::oauth::SessionGrantFilter;
use coauth_data::{Pagination, RepositoryAccess, SessionGrant};
use coauth_jose::jwt::Jwt;
use cokret_core::error::{
    ERROR_CODE_AUDIENCE_MISMATCH, ERROR_CODE_DID_PROOF_REQUIRED, ERROR_CODE_INVALID_PARAM,
    ERROR_CODE_PROOF_INVALID, ERROR_CODE_SESSION_GRANT_NOT_FOUND,
    ERROR_CODE_SESSION_REVOKE_SELECTOR_CONFLICT,
};
use cokret_core::{
    AccountLifecycleProof, DeviceId, Did, GrantId, SessionRevokeOutcome, SessionRevokeRequestBody,
};
use salvo::prelude::*;

use super::*;
use crate::handlers::cokret::*;
use crate::services::did_binding_proof::verify_detached_jws_with_sdk;
use crate::services::third_party_invite::NonceStore;

const SESSION_REVOKE_PROOF_MAX_WINDOW_SECS: i64 = 300;

fn shared_session_revoke_nonce_store() -> &'static Arc<NonceStore> {
    static STORE: OnceLock<Arc<NonceStore>> = OnceLock::new();
    STORE.get_or_init(|| Arc::new(NonceStore::new()))
}

fn empty_session_revoke_body() -> SessionRevokeRequestBody {
    SessionRevokeRequestBody {
        target_grant_id: None,
        target_device_id: None,
        all_sessions: None,
        proof: None,
    }
}

fn session_grant_not_found() -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::NOT_FOUND,
        ERROR_CODE_SESSION_GRANT_NOT_FOUND,
        "session grant is unknown, inactive, or not owned by the current principal",
    )
}

fn selector_conflict(message: impl Into<String>) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        ERROR_CODE_SESSION_REVOKE_SELECTOR_CONFLICT,
        message,
    )
}

fn lifecycle_proof_required(message: impl Into<String>) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        ERROR_CODE_DID_PROOF_REQUIRED,
        message,
    )
}

fn lifecycle_proof_invalid(message: impl Into<String>) -> CokretRouteError {
    CokretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        ERROR_CODE_PROOF_INVALID,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn bearer_session_grant(req: &Request) -> Result<&str, CokretRouteError> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| CokretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let auth_str = auth_header
        .to_str()
        .map_err(|_| CokretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CokretRouteError::Unauthorized("invalid authorization header".to_owned()))
}

async fn parse_session_revoke_body(
    req: &mut Request,
) -> Result<SessionRevokeRequestBody, CokretRouteError> {
    let has_json_content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    let content_length = req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());

    if content_length == Some(0) || (!has_json_content_type && content_length.is_none()) {
        return Ok(empty_session_revoke_body());
    }

    let body: Option<SessionRevokeRequestBody> = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;
    Ok(body.unwrap_or_else(empty_session_revoke_body))
}

enum RevokeSelector {
    Current,
    Grant(GrantId),
    Device(DeviceId),
    All,
}

fn revoke_selector(body: &SessionRevokeRequestBody) -> Result<RevokeSelector, CokretRouteError> {
    if body.all_sessions == Some(false) {
        return Err(selector_conflict(
            "all_sessions selector must be omitted or set to true",
        ));
    }

    let mut selector_count = 0;
    if body.target_grant_id.is_some() {
        selector_count += 1;
    }
    if body.target_device_id.is_some() {
        selector_count += 1;
    }
    if body.all_sessions == Some(true) {
        selector_count += 1;
    }
    if selector_count > 1 {
        return Err(selector_conflict(
            "target_grant_id, target_device_id, and all_sessions are mutually exclusive",
        ));
    }

    if let Some(target_grant_id) = body.target_grant_id.clone() {
        Ok(RevokeSelector::Grant(target_grant_id))
    } else if let Some(target_device_id) = body.target_device_id.clone() {
        Ok(RevokeSelector::Device(target_device_id))
    } else if body.all_sessions == Some(true) {
        Ok(RevokeSelector::All)
    } else {
        Ok(RevokeSelector::Current)
    }
}

fn verification_method_did(verification_method: &str) -> &str {
    let without_fragment = verification_method
        .split_once('#')
        .map_or(verification_method, |(did, _)| did);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(did, _)| did)
}

fn grant_payload(grant: &SessionGrant) -> Option<SessionGrantPayload> {
    Jwt::<SessionGrantPayload>::try_from(grant.grant_jwt.as_str())
        .ok()
        .map(|jwt| jwt.payload().clone())
}

fn grant_is_agent_delegated_to_controller(grant: &SessionGrant, controller_did: &str) -> bool {
    let Some(payload) = grant_payload(grant) else {
        return false;
    };
    if payload.proof_kind != Some(cokret_core::SessionGrantProofKind::AgentKeyProof) {
        return false;
    }
    payload
        .scope_details
        .get("controller_did")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == controller_did)
}

fn grant_is_owned_by_current_principal(grant: &SessionGrant, principal_did: &str) -> bool {
    grant.subject == principal_did || grant_is_agent_delegated_to_controller(grant, principal_did)
}

fn validate_lifecycle_proof_kind(proof_kind: &str) -> Result<(), CokretRouteError> {
    match proof_kind {
        "did_bound_signature" | "paired_device_proof" | "agent_key_proof" => Ok(()),
        other => Err(lifecycle_proof_invalid(format!(
            "unsupported lifecycle proof_kind {other}"
        ))),
    }
}

fn validate_lifecycle_proof_window(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), CokretRouteError> {
    if expires_at <= issued_at {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof expires_at must be after issued_at",
        ));
    }
    if expires_at - issued_at > Duration::seconds(SESSION_REVOKE_PROOF_MAX_WINDOW_SECS) {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof validity window exceeds 300 seconds",
        ));
    }
    if issued_at > now + Duration::seconds(30) {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof issued_at is in the future",
        ));
    }
    if expires_at <= now {
        return Err(lifecycle_proof_invalid("lifecycle proof has expired"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_cross_session_lifecycle_proof(
    http_client: &reqwest::Client,
    url_builder: &coauth_data::UrlBuilder,
    cokret_config: &coauth_config::CokretConfig,
    key_store: &coauth_keystore::Keystore,
    repo: &mut coauth_data::BoxRepository,
    did_resolver: &dyn crate::services::did_resolver::DidResolverService,
    body: &SessionRevokeRequestBody,
    proof: &AccountLifecycleProof,
    current_grant: &SessionGrant,
    current_device_id: &DeviceId,
    service_did: &Did,
    now: DateTime<Utc>,
) -> Result<(), CokretRouteError> {
    validate_lifecycle_proof_kind(&proof.proof_kind)?;
    validate_lifecycle_proof_window(proof.issued_at, proof.expires_at, now)?;

    if proof.audience != current_grant.audience {
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_AUDIENCE_MISMATCH,
            "session revoke lifecycle proof audience must match the current session grant audience",
        ));
    }

    let actor_id = Did::new(current_grant.subject.clone()).map_err(|error| {
        CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_INVALID_PARAM,
            format!("current session grant subject is not a DID: {error}"),
        )
    })?;
    let expected_digest = AccountLifecycleProof::session_revoke_request_digest(
        &actor_id,
        service_did,
        current_device_id,
        body.target_grant_id.as_ref(),
        body.target_device_id.as_ref(),
        body.all_sessions.unwrap_or(false),
    )
    .map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "session revoke request digest canonicalization failed: {error}"
        )))
    })?;
    if proof.request_canonical_digest != expected_digest {
        return Err(lifecycle_proof_invalid(
            "request_canonical_digest does not match the presented session revoke request",
        ));
    }

    let payload = proof.canonical_signing_bytes().map_err(|error| {
        CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "session revoke lifecycle proof canonicalization failed: {error}"
        )))
    })?;

    let resolution = did_resolver
        .resolve_did_document(
            http_client,
            url_builder,
            cokret_config,
            key_store,
            repo,
            &current_grant.subject,
        )
        .await
        .map_err(|error| {
            lifecycle_proof_invalid(format!("DID document resolution failed: {error}"))
        })?;
    if let Some(rejection) = resolution.identity_fact_rejection() {
        return Err(lifecycle_proof_invalid(format!(
            "DID resolver result cannot back a full identity fact: {}",
            rejection.as_str()
        )));
    }
    if resolution.document.verification_method.is_empty() {
        return Err(lifecycle_proof_invalid(
            "DID document has no verificationMethod entries",
        ));
    }

    let verification_method = verify_detached_jws_with_sdk(
        &proof.signature,
        &payload,
        &resolution.document.verification_method,
    )
    .map_err(|error| lifecycle_proof_invalid(format!("lifecycle proof JWS invalid: {error}")))?;
    if let Some(expected_method) = proof
        .verification_method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && expected_method != verification_method.as_str()
    {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof verification_method does not match the detached JWS kid",
        ));
    }
    if verification_method_did(&verification_method) != current_grant.subject {
        return Err(lifecycle_proof_invalid(
            "lifecycle proof verification_method principal does not match the current session grant subject",
        ));
    }

    let replay_key = format!(
        "{}|{}|{}|{}|{}|{}",
        cokret_core::SESSION_REVOKE_OPERATION_ID,
        current_grant.subject,
        current_device_id,
        proof.audience,
        proof.challenge,
        proof.request_canonical_digest
    );
    shared_session_revoke_nonce_store()
        .check_and_record(&replay_key, proof.expires_at, now)
        .map_err(|()| lifecycle_proof_invalid("lifecycle proof challenge has already been used"))?;

    Ok(())
}

async fn revoke_one_active_grant(
    repo: &mut coauth_data::BoxRepository,
    clock: &dyn coauth_data::Clock,
    grant: SessionGrant,
) -> Result<SessionGrant, CokretRouteError> {
    if !grant.is_active(clock) {
        return Err(session_grant_not_found());
    }
    repo.oauth_session_grant()
        .revoke(clock, grant)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))
}

async fn revoke_owned_active_grants(
    repo: &mut coauth_data::BoxRepository,
    clock: &dyn coauth_data::Clock,
    current_principal_did: &str,
    filter_device_id: Option<&str>,
) -> Result<Vec<SessionGrant>, CokretRouteError> {
    let mut revoked = Vec::new();
    let mut seen = BTreeSet::new();
    let mut after = None;
    let now = clock.now();

    loop {
        let mut filter = SessionGrantFilter::new().active_at(now);
        if let Some(device_id) = filter_device_id {
            filter = filter.for_device(device_id);
        }
        let pagination = after.map_or_else(
            || Pagination::first(100),
            |cursor| Pagination::first(100).after(cursor),
        );
        let page = repo
            .oauth_session_grant()
            .list(filter, pagination)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        if page.edges.is_empty() {
            break;
        }

        for edge in &page.edges {
            seen.insert(edge.cursor);
        }

        let has_next = page.has_next_page;
        let grants_to_revoke = page
            .edges
            .into_iter()
            .filter_map(|edge| {
                if grant_is_owned_by_current_principal(&edge.node, current_principal_did) {
                    Some(edge.node)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for grant in grants_to_revoke {
            revoked.push(revoke_one_active_grant(repo, clock, grant).await?);
        }

        if !has_next {
            break;
        }
        after = seen.iter().next_back().copied();
    }

    Ok(revoked)
}

fn revoked_outcome(grants: Vec<SessionGrant>) -> SessionRevokeOutcome {
    SessionRevokeOutcome {
        revoked_count: grants.len() as u64,
        revoked_grant_ids: grants.into_iter().map(|grant| grant.grant_id).collect(),
    }
}

#[handler]
pub async fn revoke_session_grant_endpoint(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionRevokeOutcome>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let clock = crate::handlers::make_clock();

    let presented_grant_jwt = bearer_session_grant(req)?.to_owned();
    let body = parse_session_revoke_body(req).await?;
    let selector = revoke_selector(&body)?;

    let service_did = Did::new(service_did_for(&url_builder, &cokret_config)).map_err(|error| {
        CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            ERROR_CODE_INVALID_PARAM,
            format!("configured service_did is invalid: {error}"),
        )
    })?;

    let mut repo = depot.repo().await?;
    let current_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&presented_grant_jwt)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .filter(|grant| grant.is_active(&clock))
        .ok_or_else(session_grant_not_found)?;

    let current_device_id = current_grant
        .device_id
        .as_ref()
        .map(|value| DeviceId::new(value.clone()))
        .transpose()
        .map_err(|error| {
            CokretRouteError::coded(
                StatusCode::BAD_REQUEST,
                ERROR_CODE_INVALID_PARAM,
                format!("current session grant device_id is invalid: {error}"),
            )
        })?;

    let proof_required = match &selector {
        RevokeSelector::Current => false,
        RevokeSelector::Grant(target_grant_id) => target_grant_id != &current_grant.grant_id,
        RevokeSelector::Device(_) | RevokeSelector::All => true,
    };
    if proof_required {
        let current_device_id = current_device_id.as_ref().ok_or_else(|| {
            lifecycle_proof_required(
                "cross-session revoke requires the current session grant to be device-bound",
            )
        })?;
        let proof = body.proof.as_ref().ok_or_else(|| {
            lifecycle_proof_required("cross-session revoke requires a fresh lifecycle proof")
        })?;
        verify_cross_session_lifecycle_proof(
            &http_client,
            &url_builder,
            &cokret_config,
            &key_store,
            &mut repo,
            &*did_resolver,
            &body,
            proof,
            &current_grant,
            current_device_id,
            &service_did,
            clock.now(),
        )
        .await?;
    }

    let current_principal_did = current_grant.subject.clone();
    let revoked = match selector {
        RevokeSelector::Current => {
            vec![revoke_one_active_grant(&mut repo, &clock, current_grant).await?]
        }
        RevokeSelector::Grant(target_grant_id) => {
            let target = repo
                .oauth_session_grant()
                .lookup_by_grant_id(&target_grant_id)
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
                .filter(|grant| grant.is_active(&clock))
                .filter(|grant| grant_is_owned_by_current_principal(grant, &current_principal_did))
                .ok_or_else(session_grant_not_found)?;
            vec![revoke_one_active_grant(&mut repo, &clock, target).await?]
        }
        RevokeSelector::Device(target_device_id) => {
            let revoked = revoke_owned_active_grants(
                &mut repo,
                &clock,
                &current_principal_did,
                Some(target_device_id.as_str()),
            )
            .await?;
            if revoked.is_empty() {
                return Err(session_grant_not_found());
            }
            revoked
        }
        RevokeSelector::All => {
            let revoked =
                revoke_owned_active_grants(&mut repo, &clock, &current_principal_did, None).await?;
            if revoked.is_empty() {
                return Err(session_grant_not_found());
            }
            revoked
        }
    };

    repo.save().await?;

    Ok(Json(revoked_outcome(revoked)))
}
