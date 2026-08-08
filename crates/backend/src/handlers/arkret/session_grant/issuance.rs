use arkret_canonical::{format_timestamp_canonical, normalize_timestamp_canonical};
use arkret_identifiers::{DeviceId, Did, EventId, SessionGrantId};
use arkret_wire::DidUrl;
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SESSION_GRANT_CREDENTIAL_KIND, SESSION_GRANT_ISSUANCE_SCHEMA,
    SessionGrantCnf, SessionGrantCredentialClass, SessionGrantHolderBinding,
    SessionGrantIssuancePreimage, SessionGrantProofKind, SignedSessionGrantClaims,
};
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

// Test-only convenience wrapper (re-exported under `#[cfg(test)]` from the
// session_grant module); production paths call the audience-explicit forms.
#[cfg(test)]
pub(crate) fn issue_session_grant(
    _rng: &mut (dyn CryptoRngCore + Send),
    issuance_seed: &SessionGrantIssuanceSeed,
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    subject: &str,
    scopes: Vec<String>,
    proof_kind: SessionGrantProofKind,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience(
        issuance_seed,
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        required_audience_for(url_builder, arkret_config),
        scopes,
        Some(subject),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        proof_kind,
    )
}

// `subject_override` binds the grant to the persisted principal DID verified
// for the target Principal Server audience. Issuance never fabricates a
// service-local DID when that binding is absent.
pub(crate) fn issue_session_grant_for_audience(
    issuance_seed: &SessionGrantIssuanceSeed,
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: String,
    proof_kind: SessionGrantProofKind,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience_inner(
        issuance_seed,
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        audience,
        scopes,
        subject_override,
        dpop_jkt,
        proof_kind,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn issue_test_session_grant_for_audience(
    issuance_seed: &SessionGrantIssuanceSeed,
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: String,
    proof_kind: SessionGrantProofKind,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience_inner(
        issuance_seed,
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        audience,
        scopes,
        subject_override,
        dpop_jkt,
        proof_kind,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_session_grant_for_audience_inner(
    issuance_seed: &SessionGrantIssuanceSeed,
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    _browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: String,
    proof_kind: SessionGrantProofKind,
    enforce_principal_did_method: bool,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let subject = subject_override
        .map(ToOwned::to_owned)
        .ok_or(SessionGrantError::PrincipalUnknown)?;
    if enforce_principal_did_method {
        ensure_principal_did_method_allowed(arkret_config, &subject)?;
    }
    let session_public_key =
        CanonicalSessionPublicJwk::new(serde_json::to_string(&session_public_key)?)?;

    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    let device_id = primary_device_id_from_tokens(scopes.iter().map(String::as_str))
        .ok_or(SessionGrantError::MissingDeviceBinding)?;
    let issuer = issuer_did_for(arkret_config);
    let cnf = SessionGrantCnf {
        jkt: dpop_jkt.clone(),
    };
    let subject = Did::new(subject.clone()).map_err(|_| SessionGrantError::PrincipalUnknown)?;
    let audience_did = Did::new(audience.clone())?;
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let session_id = issuance_seed.session_id.clone();
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer: issuer.clone(),
        issuance_nonce: issuance_nonce.clone(),
        subject: subject.clone(),
        session_public_key: session_public_key.clone(),
        audience: audience_did.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        cnf: cnf.clone(),
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: Some(SessionGrantHolderBinding::HumanDevice {
            device_binding: device_id.clone(),
        }),
        bootstrap_binding: None,
        recovery_binding: None,
        device_binding: None,
        proof_kind: Some(proof_kind),
        scope_details: None,
    };
    let issuance_preimage = preimage.canonical_bytes()?;
    let issuance_digest = preimage.issuance_digest()?;
    let grant_id = preimage.grant_id()?;
    let payload = SignedSessionGrantClaims {
        kind: SESSION_GRANT_CREDENTIAL_KIND.to_owned(),
        grant_id: grant_id.clone(),
        issuer: preimage.issuer,
        issuance_nonce: preimage.issuance_nonce,
        subject: preimage.subject,
        session_public_key: preimage.session_public_key.clone(),
        audience: preimage.audience,
        scopes: preimage.scopes,
        not_before: preimage.not_before,
        expires_at: preimage.expires_at,
        session_id: preimage.session_id,
        cnf: preimage.cnf,
        credential_class: preimage.credential_class,
        holder_binding: preimage.holder_binding,
        bootstrap_binding: preimage.bootstrap_binding,
        recovery_binding: preimage.recovery_binding,
        device_binding: preimage.device_binding,
        proof_kind: preimage.proof_kind,
        scope_details: preimage.scope_details,
    };
    payload.validate()?;

    let (alg, key) = reserved_signing_key(key_store, &issuance_seed.signing_key_id)
        .ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = issuance_seed.signing_key_id.clone();
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id.clone());
    let signer = key.params().signing_key_for_alg(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &signer)?.into_string();

    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key: session_public_key.into_string(),
        credential_class: "standard".to_owned(),
        recovery_session_id: None,
        recovery_policy_id: None,
        recovery_policy_version: None,
        device_authorization_event_id: None,
        model_generation_ref: None,
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer: issuer.to_string(),
        subject,
        device_id: Some(device_id),
        audience,
        scopes,
        dpop_jkt: Some(dpop_jkt),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
    })
}

pub(crate) fn mint_promoted_recovery_session_grant(
    issuance_seed: &SessionGrantIssuanceSeed,
    clock: &dyn Clock,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    prior_claims: &SignedSessionGrantClaims,
    session_public_key: String,
    device_binding: arkret_models_identity::SessionGrantDeviceBinding,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    let device_scope = format!(
        "urn:arkret:client:device:{}",
        device_binding.device_id.as_str()
    );
    let scopes = vec![PRINCIPAL_SERVER_SESSION_BIND_SCOPE.to_owned(), device_scope];
    let issuer = issuer_did_for(arkret_config);
    let session_public_key = CanonicalSessionPublicJwk::new(session_public_key)?;
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let session_id = prior_claims.session_id.clone();
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer: issuer.clone(),
        issuance_nonce: issuance_nonce.clone(),
        subject: prior_claims.subject.clone(),
        session_public_key: session_public_key.clone(),
        audience: prior_claims.audience.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        cnf: prior_claims.cnf.clone(),
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: Some(SessionGrantHolderBinding::HumanDevice {
            device_binding: device_binding.device_id.as_str().to_owned(),
        }),
        bootstrap_binding: None,
        recovery_binding: None,
        device_binding: Some(device_binding.clone()),
        proof_kind: prior_claims.proof_kind,
        scope_details: None,
    };
    let issuance_preimage = preimage.canonical_bytes()?;
    let issuance_digest = preimage.issuance_digest()?;
    let grant_id = preimage.grant_id()?;
    let payload = SignedSessionGrantClaims {
        kind: SESSION_GRANT_CREDENTIAL_KIND.to_owned(),
        grant_id: grant_id.clone(),
        issuer: preimage.issuer,
        issuance_nonce: preimage.issuance_nonce,
        subject: preimage.subject,
        session_public_key: preimage.session_public_key.clone(),
        audience: preimage.audience,
        scopes: preimage.scopes,
        not_before: preimage.not_before,
        expires_at: preimage.expires_at,
        session_id: preimage.session_id,
        cnf: preimage.cnf,
        credential_class: preimage.credential_class,
        holder_binding: preimage.holder_binding,
        bootstrap_binding: preimage.bootstrap_binding,
        recovery_binding: preimage.recovery_binding,
        device_binding: preimage.device_binding,
        proof_kind: preimage.proof_kind,
        scope_details: preimage.scope_details,
    };
    payload.validate()?;

    let (alg, key) = reserved_signing_key(key_store, &issuance_seed.signing_key_id)
        .ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = issuance_seed.signing_key_id.clone();
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id.clone());
    let signer = key.params().signing_key_for_alg(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &signer)?.into_string();
    let model_generation_ref = serde_json::to_value(&device_binding.model_generation_ref)?;

    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key: session_public_key.into_string(),
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
        not_before_timestamp: now,
        issuer: issuer.to_string(),
        subject: prior_claims.subject.as_str().to_owned(),
        device_id: Some(device_binding.device_id.as_str().to_owned()),
        audience: prior_claims.audience.clone(),
        scopes,
        dpop_jkt: Some(prior_claims.cnf.jkt.clone()),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
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

pub(crate) fn new_session_grant_record(
    browser_session_id: Option<Ulid>,
    material: &SessionGrantMaterial,
) -> NewSessionGrant<'_> {
    let scope: Scope = material
        .scopes
        .iter()
        .map(|scope| scope.parse::<ScopeToken>())
        .collect::<Result<Scope, _>>()
        .expect("signed session grant scopes must be valid OAuth scope tokens");

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
        session_id: &material.session_id,
        issuance_nonce: &material.issuance_nonce,
        issuance_preimage: &material.issuance_preimage,
        issuance_digest: material.issuance_digest,
        signing_key_id: &material.signing_key_id,
        session_public_key: &material.session_public_key,
        credential_class: &material.credential_class,
        recovery_session_id: material.recovery_session_id.as_deref(),
        recovery_policy_id: material.recovery_policy_id.as_deref(),
        recovery_policy_version: material.recovery_policy_version,
        device_authorization_event_id: material.device_authorization_event_id.as_deref(),
        model_generation_ref: material.model_generation_ref.clone(),
        not_before: material.not_before_timestamp,
        expires_at: material.expires_at_timestamp,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_session_grant_issuance<R>(
    repo: &mut R,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn Clock,
    operation_id: Ulid,
    authorization_ref: &str,
    authorization_checkpoint: &serde_json::Value,
    proof_expires_at: DateTime<Utc>,
    canonical_outcome: &[u8],
    browser_session_id: Option<Ulid>,
    material: &SessionGrantMaterial,
) -> Result<coauth_data::SessionGrantCommitOutcome, R::Error>
where
    R: RepositoryAccess + ?Sized,
{
    use sha2::Digest as _;

    let response_digest: [u8; 32] = sha2::Sha256::digest(canonical_outcome).into();
    repo.oauth_session_grant()
        .commit_issuance(
            rng,
            clock,
            operation_id,
            coauth_data::SessionGrantProofAuthorization {
                authorization_ref,
                checkpoint: authorization_checkpoint,
                proof_expires_at,
            },
            coauth_data::SessionGrantExactOutcome {
                canonical_response: canonical_outcome,
                response_digest,
            },
            new_session_grant_record(browser_session_id, material),
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
    issuance_seed: &SessionGrantIssuanceSeed,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    agent_id: &str,
    device_id: &DeviceId,
    audience: String,
    scopes: Vec<String>,
    dpop_jkt: String,
    session_public_key: String,
    scope_details: serde_json::Value,
    agent_key_authorization_ref: EventId,
    verification_method: DidUrl,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    ensure_principal_did_method_allowed(arkret_config, agent_id)?;
    let issuer = issuer_did_for(arkret_config);
    let cnf = SessionGrantCnf {
        jkt: dpop_jkt.clone(),
    };
    let session_id = issuance_seed.session_id.clone();
    let scope_details = compact_agent_scope_details(scope_details);
    let session_public_key = CanonicalSessionPublicJwk::new(session_public_key)?;
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let subject = Did::new(agent_id.to_owned()).map_err(|_| SessionGrantError::PrincipalUnknown)?;
    let audience_did = Did::new(audience.clone())?;
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer: issuer.clone(),
        issuance_nonce: issuance_nonce.clone(),
        subject: subject.clone(),
        session_public_key: session_public_key.clone(),
        audience: audience_did,
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id,
        cnf: cnf.clone(),
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: Some(SessionGrantHolderBinding::AgentRuntime {
            agent_id: subject,
            device_id: device_id.clone(),
            agent_key_authorization_ref,
            verification_method,
        }),
        bootstrap_binding: None,
        recovery_binding: None,
        device_binding: None,
        proof_kind: Some(SessionGrantProofKind::AgentKeyProof),
        scope_details: Some(scope_details),
    };
    let issuance_preimage = preimage.canonical_bytes()?;
    let issuance_digest = preimage.issuance_digest()?;
    let grant_id = preimage.grant_id()?;
    let payload = SignedSessionGrantClaims {
        kind: SESSION_GRANT_CREDENTIAL_KIND.to_owned(),
        grant_id: grant_id.clone(),
        issuer: preimage.issuer,
        issuance_nonce: preimage.issuance_nonce,
        subject: preimage.subject,
        session_public_key: preimage.session_public_key.clone(),
        audience: preimage.audience,
        scopes: preimage.scopes,
        not_before: preimage.not_before,
        expires_at: preimage.expires_at,
        session_id: preimage.session_id,
        cnf: preimage.cnf,
        credential_class: preimage.credential_class,
        holder_binding: preimage.holder_binding,
        bootstrap_binding: preimage.bootstrap_binding,
        recovery_binding: preimage.recovery_binding,
        device_binding: preimage.device_binding,
        proof_kind: preimage.proof_kind,
        scope_details: preimage.scope_details,
    };
    payload.validate()?;

    let (alg, key) = reserved_signing_key(key_store, &issuance_seed.signing_key_id)
        .ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = issuance_seed.signing_key_id.clone();
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id.clone());
    let signer = key.params().signing_key_for_alg(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &signer)?.into_string();

    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key: session_public_key.into_string(),
        credential_class: "standard".to_owned(),
        recovery_session_id: None,
        recovery_policy_id: None,
        recovery_policy_version: None,
        device_authorization_event_id: None,
        model_generation_ref: None,
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer: issuer.to_string(),
        subject: agent_id.to_owned(),
        device_id: Some(device_id.to_string()),
        audience,
        scopes,
        dpop_jkt: Some(dpop_jkt),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
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

fn reserved_signing_key<'a>(
    key_store: &'a Keystore,
    signing_key_id: &str,
) -> Option<(
    coauth_iana::jose::JsonWebSignatureAlg,
    &'a coauth_keystore::JsonWebKey<coauth_keystore::PrivateKey>,
)> {
    use coauth_iana::jose::JsonWebSignatureAlg;

    [
        JsonWebSignatureAlg::Ed25519,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps256,
    ]
    .into_iter()
    .find_map(|alg| {
        key_store
            .signing_key_for_algorithm(&alg)
            .filter(|key| key.kid() == Some(signing_key_id))
            .map(|key| (alg, key))
    })
}
