use std::sync::{Arc, OnceLock};

use arkret_identifiers::{DeviceId, Did, GrantId};
use arkret_models_collaboration::account_lifecycle::{
    AccountLifecycleProof, SessionRevokeOutcome, SessionRevokeRequestBody,
};
use chrono::{DateTime, Duration, Utc};
use coauth_data::oauth::SessionGrantFilter;
use coauth_data::{Pagination, RepositoryAccess, SessionGrant};
use coauth_jose::jwt::Jwt;
use salvo::prelude::*;

use super::*;
use crate::handlers::arkret::*;
use crate::services::did_binding_proof::verify_detached_jws_with_sdk;
use crate::services::nonce_store::NonceStore;

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
        applet_id: None,
        effective_scope: None,
        registration_epoch: None,
        service_id: None,
        capability_grant_refs: Vec::new(),
        proof: None,
    }
}

fn session_grant_not_found() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::SESSION_GRANT_NOT_FOUND,
        "session grant is unknown, inactive, or not owned by the current principal",
    )
}

fn selector_conflict(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        arkret_wire::ErrorCode::SESSION_REVOKE_SELECTOR_CONFLICT,
        message,
    )
}

fn lifecycle_proof_required(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ErrorCode::DID_PROOF_REQUIRED,
        message,
    )
}

fn lifecycle_proof_invalid(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::UNAUTHORIZED,
        arkret_wire::ReasonCode::PROOF_INVALID,
        format!("reason_code=proof_invalid; {}", message.into()),
    )
}

fn bearer_session_grant(req: &Request) -> Result<&str, ArkretRouteError> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .ok_or_else(|| ArkretRouteError::Unauthorized("missing authorization header".to_owned()))?;
    let auth_str = auth_header
        .to_str()
        .map_err(|_| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))?;
    auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ArkretRouteError::Unauthorized("invalid authorization header".to_owned()))
}

async fn parse_session_revoke_body(
    req: &mut Request,
) -> Result<SessionRevokeRequestBody, ArkretRouteError> {
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
        .map_err(|_| ArkretRouteError::BadRequest("invalid json body".to_owned()))?;
    Ok(body.unwrap_or_else(empty_session_revoke_body))
}

enum RevokeSelector {
    Current,
    Grant(GrantId),
    Device(DeviceId),
    All,
}

fn revoke_selector(body: &SessionRevokeRequestBody) -> Result<RevokeSelector, ArkretRouteError> {
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
    if session_revoke_has_applet_selector(body) {
        selector_count += 1;
    }
    if selector_count > 1 {
        return Err(selector_conflict(
            "target_grant_id, target_device_id, all_sessions and applet selector are mutually exclusive",
        ));
    }
    if session_revoke_has_applet_selector(body) {
        return Err(selector_conflict(
            "applet selector session revoke is not supported by this Account Authority endpoint",
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

fn session_revoke_has_applet_selector(body: &SessionRevokeRequestBody) -> bool {
    body.applet_id.is_some()
        || body.effective_scope.is_some()
        || body.registration_epoch.is_some()
        || body.service_id.is_some()
        || !body.capability_grant_refs.is_empty()
}

fn verification_method_did(verification_method: &str) -> &str {
    let without_fragment = verification_method
        .split_once('#')
        .map_or(verification_method, |(did, _)| did);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(did, _)| did)
}

fn grant_payload(grant: &SessionGrant) -> Option<SignedSessionGrantClaims> {
    Jwt::<SignedSessionGrantClaims>::try_from(grant.grant_jwt.as_str())
        .ok()
        .map(|jwt| jwt.payload().clone())
}

fn grant_is_agent_delegated_to_controller(grant: &SessionGrant, controller_id: &str) -> bool {
    let Some(payload) = grant_payload(grant) else {
        return false;
    };
    if payload.proof_kind != Some(arkret_models_identity::SessionGrantProofKind::AgentKeyProof) {
        return false;
    }
    payload
        .scope_details
        .as_ref()
        .and_then(|details| details.get("controller_id"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == controller_id)
}

fn grant_is_owned_by_current_principal(grant: &SessionGrant, principal_did: &str) -> bool {
    grant.subject == principal_did || grant_is_agent_delegated_to_controller(grant, principal_did)
}

fn validate_lifecycle_proof_kind(proof_kind: &str) -> Result<(), ArkretRouteError> {
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
) -> Result<(), ArkretRouteError> {
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
    arkret_config: &coauth_config::ArkretConfig,
    key_store: &coauth_keystore::Keystore,
    repo: &mut coauth_data::BoxRepository,
    did_resolver: &dyn crate::services::did_resolver::DidResolverService,
    binding_store: &crate::services::did_binding::DurableVerifiedDidBindingStore,
    body: &SessionRevokeRequestBody,
    proof: &AccountLifecycleProof,
    current_grant: &SessionGrant,
    current_device_id: &DeviceId,
    service_id: &Did,
    now: DateTime<Utc>,
) -> Result<(), ArkretRouteError> {
    validate_lifecycle_proof_kind(&proof.proof_kind)?;
    validate_lifecycle_proof_window(proof.issued_at, proof.expires_at, now)?;

    if proof.audience != current_grant.audience {
        return Err(ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::AUDIENCE_MISMATCH,
            "session revoke lifecycle proof audience must match the current session grant audience",
        ));
    }

    let actor_id = Did::new(current_grant.subject.clone()).map_err(|error| {
        ArkretRouteError::coded(
            StatusCode::BAD_REQUEST,
            arkret_wire::ErrorCode::INVALID_PARAM,
            format!("current session grant subject is not a DID: {error}"),
        )
    })?;
    let expected_digest = AccountLifecycleProof::session_revoke_request_digest(
        &actor_id,
        service_id,
        current_device_id,
        body.target_grant_id.as_ref(),
        body.target_device_id.as_ref(),
        body.all_sessions.unwrap_or(false),
        None,
    )
    .map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "session revoke request digest canonicalization failed: {error}"
        )))
    })?;
    if proof.request_canonical_digest != expected_digest {
        return Err(lifecycle_proof_invalid(
            "request_canonical_digest does not match the presented session revoke request",
        ));
    }

    let payload = proof.canonical_signing_bytes().map_err(|error| {
        ArkretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(format!(
            "session revoke lifecycle proof canonicalization failed: {error}"
        )))
    })?;

    // §4 row 7 — a cross-session revoke is a high-risk write, so it demands
    // `fresh_within(HIGH_RISK_MAX_AGE)` under the closed `Principal` purpose.
    // Degraded / fallback / unproven-controller evidence maps to
    // `Stale` / `Quarantined` and fails closed inside `authority_document`,
    // which replaces the previous `identity_fact_rejection` gate.
    let resolution = crate::services::did_binding::authority_document(
        http_client,
        url_builder,
        arkret_config,
        key_store,
        repo,
        did_resolver,
        binding_store,
        &current_grant.subject,
        arkret_identity::DidBindingPurpose::Principal,
        crate::services::did_binding::high_risk_freshness(),
        now,
    )
    .await
    .map_err(|error| {
        lifecycle_proof_invalid(format!(
            "no fresh accepted principal binding for the session subject: {error}"
        ))
    })?;
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
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION,
        current_grant.subject,
        current_device_id,
        proof.audience,
        proof.challenge,
        proof.request_canonical_digest
    );
    shared_session_revoke_nonce_store()
        .check_and_record(&replay_key, proof.expires_at, now)
        .map_err(|_| lifecycle_proof_invalid("lifecycle proof challenge has already been used"))?;

    Ok(())
}

async fn revoke_one_active_grant(
    repo: &mut coauth_data::BoxRepository,
    clock: &dyn coauth_data::Clock,
    grant: SessionGrant,
) -> Result<SessionGrant, ArkretRouteError> {
    if !grant.is_active(clock) {
        return Err(session_grant_not_found());
    }
    repo.oauth_session_grant()
        .revoke(clock, grant)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))
}

async fn revoke_owned_active_grants(
    repo: &mut coauth_data::BoxRepository,
    clock: &dyn coauth_data::Clock,
    current_principal_did: &str,
    filter_device_id: Option<&str>,
) -> Result<Vec<SessionGrant>, ArkretRouteError> {
    let mut revoked = Vec::new();
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
            .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?;
        if page.edges.is_empty() {
            break;
        }

        let has_next = page.has_next_page;
        let next_after = page.edges.last().map(|edge| edge.cursor);
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
        after = next_after;
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
) -> Result<Json<SessionRevokeOutcome>, ArkretRouteError> {
    let url_builder = depot.url_builder()?;
    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let http_client = depot.http_client()?;
    let did_resolver = depot.did_resolver_service()?;
    let binding_store = depot.verified_did_binding_store()?;
    let clock = crate::handlers::make_clock();

    let presented_grant_jwt = bearer_session_grant(req)?.to_owned();
    let body = parse_session_revoke_body(req).await?;
    let selector = revoke_selector(&body)?;

    let service_id = service_id_for(&arkret_config);

    let mut repo = depot.repo().await?;
    let current_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&presented_grant_jwt)
        .await
        .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
        .filter(|grant| grant.is_active(&clock))
        .ok_or_else(session_grant_not_found)?;

    let current_device_id = current_grant
        .device_id
        .as_ref()
        .map(|value| DeviceId::new(value.clone()))
        .transpose()
        .map_err(|error| {
            ArkretRouteError::coded(
                StatusCode::BAD_REQUEST,
                arkret_wire::ErrorCode::INVALID_PARAM,
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
            &arkret_config,
            &key_store,
            &mut repo,
            &*did_resolver,
            binding_store.as_ref(),
            &body,
            proof,
            &current_grant,
            current_device_id,
            &service_id,
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
                .map_err(|error| ArkretRouteError::Internal(Box::new(error)))?
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

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use coauth_config::{ArkretConfig, DeploymentProfileConfig, PrincipalMethodConfig};
    use coauth_keystore::{JsonWebKeySet, Keystore, PrivateKey};
    use coauth_oauth_types::scope::Scope;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    fn test_keystore() -> Keystore {
        let mut rng = ChaChaRng::seed_from_u64(0x4e17);
        let ed25519 = coauth_keystore::JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid("test-ed25519");
        Keystore::new(JsonWebKeySet::new(vec![ed25519]))
    }

    fn personal_did_web_config() -> ArkretConfig {
        ArkretConfig {
            deployment_profile: DeploymentProfileConfig::PersonalNode,
            principal_method: PrincipalMethodConfig::DidWeb,
            runtime_service_identity: coauth_config::RuntimeServiceIdentity::fixture(
                "did:web:auth.example",
            ),
            ..ArkretConfig::default()
        }
    }

    fn agent_session_grant(controller_id: &str) -> SessionGrant {
        let now = Utc::now();
        let material = mint_agent_session_grant(
            &personal_did_web_config(),
            &test_keystore(),
            "did:web:agent.example",
            &DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000006").unwrap(),
            "did:web:soland.example".to_owned(),
            vec!["ak.self.events.stream.subscribe".to_owned()],
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            "{\"kty\":\"OKP\"}".to_owned(),
            serde_json::json!({
                "controller_id": controller_id,
                "resources": {
                    "realm_refs": ["ak:realm:team"],
                },
            }),
            now,
            now + Duration::minutes(15),
        )
        .expect("agent grant should mint");

        SessionGrant {
            id: ulid::Ulid::from_string("01J44Q10GR4AMTFZEEF936DTCM").unwrap(),
            grant_id: material.grant_id,
            browser_session_id: None,
            issuer: material.issuer,
            subject: material.subject,
            device_id: material.device_id,
            applet_id: None,
            effective_scope: None,
            registration_epoch: None,
            service_id: None,
            capability_grant_refs: Vec::new(),
            audience: material.audience,
            scope: Scope::from_iter(["ak.self.events.stream.subscribe".parse().unwrap()]),
            grant_jwt: material.grant_jwt,
            session_public_key: material.session_public_key,
            credential_class: material.credential_class,
            recovery_session_id: material.recovery_session_id,
            recovery_policy_id: material.recovery_policy_id,
            recovery_policy_version: material.recovery_policy_version,
            device_authorization_event_id: material.device_authorization_event_id,
            model_generation_ref: material.model_generation_ref,
            created_at: now,
            expires_at: now + Duration::minutes(15),
            revoked_at: None,
        }
    }

    #[test]
    fn agent_key_proof_grant_is_owned_by_accountable_controller_only() {
        let grant = agent_session_grant("did:web:controller.example");

        assert_eq!(
            grant.device_id.as_deref(),
            Some("ak:device:0196419b-0000-7000-8000-000000000006")
        );

        assert!(grant_is_agent_delegated_to_controller(
            &grant,
            "did:web:controller.example"
        ));
        assert!(grant_is_owned_by_current_principal(
            &grant,
            "did:web:controller.example"
        ));
        assert!(!grant_is_agent_delegated_to_controller(
            &grant,
            "did:web:other-controller.example"
        ));
        assert!(!grant_is_owned_by_current_principal(
            &grant,
            "did:web:other-controller.example"
        ));
    }

    #[test]
    fn malformed_or_non_agent_grant_is_not_controller_delegated() {
        let mut grant = agent_session_grant("did:web:controller.example");
        grant.grant_jwt = "header.payload.signature".to_owned();

        assert!(!grant_is_agent_delegated_to_controller(
            &grant,
            "did:web:controller.example"
        ));
    }
}
