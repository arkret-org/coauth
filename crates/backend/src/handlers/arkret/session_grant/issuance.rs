use arkret_canonical::{format_timestamp_canonical, normalize_timestamp_canonical};
use arkret_identifiers::{DeviceId, GrantId, new_prefixed_uuid7};
use chrono::{DateTime, Utc};
use coauth_config::ArkretConfig;
#[cfg(test)]
use coauth_data::UrlBuilder;
use coauth_data::oauth::NewSessionGrant;
use coauth_data::{BrowserSession, Clock, RepositoryAccess, SessionGrant};
use coauth_jose::jwk::PublicJsonWebKey;
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::Keystore;
use coauth_oauth_types::scope::{Scope, ScopeToken};
#[cfg(test)]
use rand_core::CryptoRngCore;
use rand_core::RngCore;
use ulid::Ulid;

use super::*;
use crate::handlers::arkret::*;

fn new_session_grant_id() -> GrantId {
    GrantId::new(new_prefixed_uuid7("ak:grant:"))
        .expect("generated ak:grant uuidv7 id must be valid")
}

// Test-only convenience wrapper (re-exported under `#[cfg(test)]` from the
// session_grant module); production paths call the audience-explicit forms.
#[cfg(test)]
pub(crate) fn issue_session_grant(
    _rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    subject: &str,
    scopes: Vec<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience(
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        required_audience_for(url_builder, arkret_config),
        scopes,
        Some(subject),
        "test-grant-binding-jkt".to_owned(),
    )
}

// `subject_override` binds the grant to the persisted principal DID verified
// for the target Principal Server audience. Issuance never fabricates a
// service-local DID when that binding is absent.
pub(crate) fn issue_session_grant_for_audience(
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: String,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience_inner(
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        audience,
        scopes,
        subject_override,
        dpop_jkt,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn issue_test_session_grant_for_audience(
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: String,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience_inner(
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        audience,
        scopes,
        subject_override,
        dpop_jkt,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_session_grant_for_audience_inner(
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: String,
    enforce_principal_did_method: bool,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let subject = subject_override
        .map(ToOwned::to_owned)
        .ok_or(SessionGrantError::PrincipalUnknown)?;
    if enforce_principal_did_method {
        ensure_principal_did_method_allowed(arkret_config, &subject)?;
    }
    let session_public_key = serde_json::to_string(&session_public_key)?;

    let now = normalize_timestamp_canonical(clock.now());
    let expires_at = now + arkret_config.session_grant_ttl;
    let grant_id = new_session_grant_id();
    let device_id = primary_device_id_from_tokens(scopes.iter().map(String::as_str));
    let issuer = issuer_did_for(arkret_config);
    let cnf = SessionGrantCnf {
        jkt: dpop_jkt.clone(),
    };
    let payload = SignedSessionGrantClaims {
        kind: "ak.session.grant".to_owned(),
        grant_id: grant_id.clone(),
        subject: arkret_identifiers::Did::new(subject.clone())
            .map_err(|_| SessionGrantError::PrincipalUnknown)?,
        audience: audience.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: browser_session.id.to_string(),
        cnf,
        credential_class: arkret_models_identity::SessionGrantCredentialClass::Standard,
        recovery_binding: None,
        device_binding: None,
        proof_kind: None,
        scope_details: None,
    };
    payload.validate()?;

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id);
    let signer = key_store.signer_for_algorithm(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &*signer)?.into_string();

    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key,
        credential_class: "standard".to_owned(),
        recovery_session_id: None,
        recovery_policy_id: None,
        recovery_policy_version: None,
        device_authorization_event_id: None,
        model_generation_ref: None,
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        issuer: issuer.to_string(),
        subject,
        device_id,
        audience,
        scopes,
        dpop_jkt: Some(dpop_jkt),
    })
}

pub(crate) fn mint_promoted_recovery_session_grant(
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    prior_claims: &SignedSessionGrantClaims,
    session_public_key: String,
    device_binding: arkret_models_identity::SessionGrantDeviceBinding,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let now = normalize_timestamp_canonical(clock.now());
    let expires_at = now + arkret_config.session_grant_ttl;
    let grant_id = new_session_grant_id();
    let device_scope = format!(
        "urn:arkret:client:device:{}",
        device_binding.device_id.as_str()
    );
    let scopes = vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(), device_scope];
    let payload = SignedSessionGrantClaims {
        kind: "ak.session.grant".to_owned(),
        grant_id: grant_id.clone(),
        subject: prior_claims.subject.clone(),
        audience: prior_claims.audience.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: prior_claims.session_id.clone(),
        cnf: prior_claims.cnf.clone(),
        credential_class: arkret_models_identity::SessionGrantCredentialClass::Standard,
        recovery_binding: None,
        device_binding: Some(device_binding.clone()),
        proof_kind: prior_claims.proof_kind,
        scope_details: None,
    };
    payload.validate()?;

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id);
    let signer = key_store.signer_for_algorithm(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &*signer)?.into_string();
    let model_generation_ref = serde_json::to_value(&device_binding.model_generation_ref)?;

    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key,
        credential_class: "standard".to_owned(),
        recovery_session_id: None,
        recovery_policy_id: None,
        recovery_policy_version: None,
        device_authorization_event_id: Some(
            device_binding.authorization_event_id.as_str().to_owned(),
        ),
        model_generation_ref: Some(model_generation_ref),
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        issuer: issuer_did_for(arkret_config).to_string(),
        subject: prior_claims.subject.as_str().to_owned(),
        device_id: Some(device_binding.device_id.as_str().to_owned()),
        audience: prior_claims.audience.clone(),
        scopes,
        dpop_jkt: Some(prior_claims.cnf.jkt.clone()),
    })
}

pub(crate) async fn persist_session_grant_with_browser_session_id<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    browser_session_id: Option<Ulid>,
    material: &SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    let scope: Scope = material
        .scopes
        .iter()
        .map(|scope| scope.parse::<ScopeToken>())
        .collect::<Result<Scope, _>>()
        // This can only fail if an internal caller constructed an invalid scope
        // string before signing the JWT.
        .expect("session grant scopes must be valid OAuth scope tokens");

    repo.oauth_session_grant()
        .add(
            rng,
            clock,
            NewSessionGrant {
                grant_id: material.grant_id.clone(),
                browser_session_id,
                issuer: &material.issuer,
                subject: &material.subject,
                device_id: material.device_id.as_deref(),
                applet_id: None,
                effective_scope: None,
                registration_epoch: None,
                service_id: None,
                capability_grant_refs: Vec::new(),
                audience: &material.audience,
                scope,
                grant_jwt: &material.grant_jwt,
                session_public_key: &material.session_public_key,
                credential_class: &material.credential_class,
                recovery_session_id: material.recovery_session_id.as_deref(),
                recovery_policy_id: material.recovery_policy_id.as_deref(),
                recovery_policy_version: material.recovery_policy_version,
                device_authorization_event_id: material.device_authorization_event_id.as_deref(),
                model_generation_ref: material.model_generation_ref.clone(),
                expires_at: material.expires_at_timestamp,
            },
        )
        .await
}

pub(crate) async fn persist_session_grant<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    browser_session: &BrowserSession,
    material: &SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    persist_session_grant_with_browser_session_id(
        repo,
        rng,
        clock,
        Some(browser_session.id),
        material,
    )
    .await
}

pub(crate) async fn persist_unbound_session_grant<R>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    material: &SessionGrantMaterial,
) -> Result<SessionGrant, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    persist_session_grant_with_browser_session_id(repo, rng, clock, None, material).await
}

/// Mint a signed agent `ak.session.grant` JWT bound to the agent principal as
/// subject and the runtime's DPoP key (`cnf.jkt`). No browser session is
/// involved; `session_id` carries the grant id so the payload shape stays
/// uniform without repeating the agent principal DID outside `subject`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_agent_session_grant(
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    agent_id: &str,
    device_id: &DeviceId,
    audience: String,
    scopes: Vec<String>,
    dpop_jkt: String,
    session_public_key: String,
    scope_details: serde_json::Value,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let now = normalize_timestamp_canonical(now);
    let expires_at = normalize_timestamp_canonical(expires_at);
    ensure_principal_did_method_allowed(arkret_config, agent_id)?;
    let issuer = issuer_did_for(arkret_config);
    let grant_id = new_session_grant_id();
    let cnf = SessionGrantCnf {
        jkt: dpop_jkt.clone(),
    };
    let session_id = grant_id.to_string();
    let scope_details = compact_agent_scope_details(scope_details);
    let payload = SignedSessionGrantClaims {
        kind: "ak.session.grant".to_owned(),
        grant_id: grant_id.clone(),
        subject: arkret_identifiers::Did::new(agent_id.to_owned())
            .map_err(|_| SessionGrantError::PrincipalUnknown)?,
        audience: audience.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id,
        cnf,
        credential_class: arkret_models_identity::SessionGrantCredentialClass::Standard,
        recovery_binding: None,
        device_binding: None,
        proof_kind: Some(arkret_models_identity::SessionGrantProofKind::AgentKeyProof),
        scope_details: Some(scope_details),
    };
    payload.validate()?;

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id);
    let signer = key_store.signer_for_algorithm(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &*signer)?.into_string();

    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key,
        credential_class: "standard".to_owned(),
        recovery_session_id: None,
        recovery_policy_id: None,
        recovery_policy_version: None,
        device_authorization_event_id: None,
        model_generation_ref: None,
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        issuer: issuer.to_string(),
        subject: agent_id.to_owned(),
        device_id: Some(device_id.to_string()),
        audience,
        scopes,
        dpop_jkt: Some(dpop_jkt),
    })
}

fn compact_agent_scope_details(mut scope_details: serde_json::Value) -> serde_json::Value {
    if let Some(object) = scope_details.as_object_mut() {
        object.remove("agent_id");
        object.remove("principal_id");
        object.remove("subject");
        object.remove("audience");
    }
    scope_details
}
