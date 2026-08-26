use arkret_canonical::format_timestamp_canonical;
use arkret_identifiers::{DeviceId, DidCoreId, EventId};
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SESSION_GRANT_CREDENTIAL_KIND, SESSION_GRANT_ISSUANCE_SCHEMA,
    SessionGrantCredentialClass, SessionGrantDeviceBinding, SessionGrantHolderBinding,
    SessionGrantIssuancePreimage, SessionGrantProofKind, SignedSessionGrantClaims,
};
use arkret_wire::DidUrl;
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
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    subject: &str,
    principal_authority: &arkret_wire::PrincipalAuthorityKey,
    device_id: DeviceId,
    scopes: Vec<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut nonce = [0_u8; 32];
    rng.fill_bytes(&mut nonce);
    let (_, signing_key) = crate::services::preferred_service_signing_key(key_store)
        .ok_or(SessionGrantError::NoSigningKey)?;
    let signing_key_id = signing_key.kid().ok_or(SessionGrantError::NoSigningKey)?;
    let issuance_seed = SessionGrantIssuanceSeed::new(
        arkret_models_identity::SessionGrantIssuanceNonce::from_bytes(nonce).to_string(),
        browser_session.id.to_string(),
        now,
        now + arkret_config.session_grant_ttl,
        signing_key_id,
    )?;
    let device_binding = SessionGrantDeviceBinding {
        device_id: device_id.clone(),
        authorization_event_id: EventId::new(
            "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        )
        .expect("test authorization Event id"),
        model_generation_ref: 1,
    };
    issue_session_grant_for_audience(
        &issuance_seed,
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        required_audience_for(url_builder, arkret_config),
        device_id,
        scopes,
        Some(subject),
        principal_authority,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        device_binding,
        SessionGrantProofKind::AccountHandoff,
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
    device_id: DeviceId,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    principal_authority: &arkret_wire::PrincipalAuthorityKey,
    dpop_jkt: String,
    device_binding: SessionGrantDeviceBinding,
    proof_kind: SessionGrantProofKind,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let _ = (clock, browser_session);
    let subject = subject_override
        .map(ToOwned::to_owned)
        .ok_or(SessionGrantError::PrincipalUnknown)?;
    let session_public_key =
        CanonicalSessionPublicJwk::new(serde_json::to_string(&session_public_key)?)?;

    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    let issuer = service_id_for(arkret_config);
    let subject_id =
        DidCoreId::new(subject.clone()).map_err(|_| SessionGrantError::PrincipalUnknown)?;
    let audience_id = DidCoreId::new(audience.clone())?;
    principal_authority.validate()?;
    if principal_authority.principal_id != subject_id
        || principal_authority.principal_server_id != audience_id
    {
        return Err(SessionGrantError::PrincipalUnknown);
    }
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let session_id = issuance_seed.session_id.clone();
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer: issuer.clone(),
        issuance_nonce: issuance_nonce.clone(),
        subject: subject_id.clone(),
        session_public_key: session_public_key.clone(),
        audience: audience_id.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::HumanDevice {
            device_binding: device_id.to_string(),
        },
        device_binding: Some(device_binding),
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
        credential_class: preimage.credential_class,
        holder_binding: preimage.holder_binding,
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
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer,
        subject,
        device_id: Some(device_id.to_string()),
        audience: audience_id.to_string(),
        scopes,
        dpop_jkt: Some(dpop_jkt),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn issue_recovery_session_grant_for_audience(
    issuance_seed: &SessionGrantIssuanceSeed,
    arkret_config: &ArkretConfig,
    key_store: &Keystore,
    session_public_key: PublicJsonWebKey,
    audience: String,
    device_id: DeviceId,
    scopes: Vec<String>,
    subject: &str,
    principal_authority: &arkret_wire::PrincipalAuthorityKey,
    dpop_jkt: String,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let session_public_key =
        CanonicalSessionPublicJwk::new(serde_json::to_string(&session_public_key)?)?;
    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    if expires_at - now > chrono::Duration::minutes(15) {
        return Err(arkret_wire::WireError::Protocol(
            "recovery session grant TTL exceeds 15 minutes".to_owned(),
        )
        .into());
    }
    let issuer = service_id_for(arkret_config);
    let subject_id =
        DidCoreId::new(subject.to_owned()).map_err(|_| SessionGrantError::PrincipalUnknown)?;
    let audience_id = DidCoreId::new(audience)?;
    principal_authority.validate()?;
    if principal_authority.principal_id != subject_id
        || principal_authority.principal_server_id != audience_id
    {
        return Err(SessionGrantError::PrincipalUnknown);
    }
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let session_id = issuance_seed.session_id.clone();
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer: issuer.clone(),
        issuance_nonce: issuance_nonce.clone(),
        subject: subject_id,
        session_public_key: session_public_key.clone(),
        audience: audience_id.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        credential_class: SessionGrantCredentialClass::RecoverySession,
        holder_binding: SessionGrantHolderBinding::RecoveryCandidateDevice {
            device_id: device_id.clone(),
        },
        device_binding: None,
        proof_kind: Some(SessionGrantProofKind::AccountHandoff),
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
        credential_class: preimage.credential_class,
        holder_binding: preimage.holder_binding,
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
        credential_class: "recovery_session".to_owned(),
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer,
        subject: subject.to_owned(),
        device_id: Some(device_id.to_string()),
        audience: audience_id.to_string(),
        scopes,
        dpop_jkt: Some(dpop_jkt),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
    })
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
    device_id: DeviceId,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    principal_authority: &arkret_wire::PrincipalAuthorityKey,
    dpop_jkt: String,
    device_binding: SessionGrantDeviceBinding,
    proof_kind: SessionGrantProofKind,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience(
        issuance_seed,
        clock,
        arkret_config,
        key_store,
        browser_session,
        session_public_key,
        audience,
        device_id,
        scopes,
        subject_override,
        principal_authority,
        dpop_jkt,
        device_binding,
        proof_kind,
    )
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
    // The repository has no single-call insert: a grant only becomes durable as
    // the committed outcome of a reserved operation. Internal browser-session
    // entry points (password, passkey, debug seeds) therefore reserve and commit
    // here rather than carrying a second persistence path that bypasses the
    // ledger.
    //
    // The already-signed material is its own stable request identity — the
    // `grant_id` is the digest of the exact issuance preimage — so an exact
    // retry of the same logical login converges on one grant instead of minting
    // a second one.
    let request_identity = format!("internal-issue:{}", material.grant_id);
    let issuance_preimage: SessionGrantIssuancePreimage =
        serde_json::from_slice(&material.issuance_preimage)
            .expect("signed session grant material carries a validated issuance preimage");
    let reserved = repo
        .oauth_session_grant()
        .reserve_operation(
            rng,
            clock,
            coauth_data::NewSessionGrantOperation {
                issuer: material.issuer.clone(),
                operation: coauth_data::SessionGrantOperationDescriptor::Issue,
                proof_kind: issuance_preimage.proof_kind,
                request_identity: &request_identity,
                canonical_intent_digest: material.issuance_digest,
                canonical_intent: &material.issuance_preimage,
                target_session_grant_id: None,
                issuance_nonce: Some(&material.issuance_nonce),
                session_id: Some(&material.session_id),
                grant_not_before: Some(material.not_before_timestamp),
                grant_expires_at: Some(material.expires_at_timestamp),
                signing_key_id: Some(&material.signing_key_id),
                retained_until: material.expires_at_timestamp + chrono::Duration::days(7),
            },
        )
        .await?;

    let operation_id = match reserved {
        coauth_data::SessionGrantReserveOutcome::Reserved(operation)
        | coauth_data::SessionGrantReserveOutcome::Pending(operation) => operation.id,
        coauth_data::SessionGrantReserveOutcome::Replay(operation)
        | coauth_data::SessionGrantReserveOutcome::Conflict(operation)
        | coauth_data::SessionGrantReserveOutcome::Indeterminate(operation) => operation.id,
    };

    let checkpoint = serde_json::json!({
        "kind": "internal_browser_session_issue",
        "grant_id": material.grant_id,
    });
    let committed = repo
        .oauth_session_grant()
        .commit_issuance(
            rng,
            clock,
            operation_id,
            coauth_data::SessionGrantProofAuthorization {
                authorization_ref: &request_identity,
                checkpoint: &checkpoint,
                proof_expires_at: material.expires_at_timestamp,
            },
            coauth_data::SessionGrantExactOutcome {
                canonical_response: &material.issuance_preimage,
                response_digest: material.issuance_digest,
            },
            new_session_grant_record(browser_session_id, material),
        )
        .await?;

    match committed {
        coauth_data::SessionGrantCommitOutcome::Committed(grant) => Ok(grant),
        coauth_data::SessionGrantCommitOutcome::Replay(operation)
        | coauth_data::SessionGrantCommitOutcome::Indeterminate(operation) => {
            // Each internal login signs fresh material, so its `grant_id` — and
            // therefore its request identity — is unique to this attempt. A
            // replay or tombstone here means the caller reused signed material
            // across two logical issuances, which would hand out one grant under
            // two identities.
            panic!(
                "internal browser-session issuance reused signed material: operation {} already \
                 holds an outcome for grant {}",
                operation.id, material.grant_id
            )
        }
    }
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

#[cfg(test)]
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
    scope_details: serde_json::Map<String, serde_json::Value>,
    agent_key_authorization_ref: EventId,
    verification_method: DidUrl,
    _now: DateTime<Utc>,
    _expires_at: DateTime<Utc>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    let issuer = service_id_for(arkret_config);
    let session_id = issuance_seed.session_id.clone();
    let scope_details = compact_agent_scope_details(scope_details);
    let session_public_key = CanonicalSessionPublicJwk::new(session_public_key)?;
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let subject =
        DidCoreId::new(agent_id.to_owned()).map_err(|_| SessionGrantError::PrincipalUnknown)?;
    let audience_id = DidCoreId::new(audience.clone())?;
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer: issuer.clone(),
        issuance_nonce: issuance_nonce.clone(),
        subject: subject.clone(),
        session_public_key: session_public_key.clone(),
        audience: audience_id,
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::AgentRuntime {
            agent_id: subject,
            device_id: device_id.clone(),
            agent_key_authorization_ref,
            verification_method,
        },
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
        credential_class: preimage.credential_class,
        holder_binding: preimage.holder_binding,
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
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer,
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

fn compact_agent_scope_details(
    mut scope_details: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    scope_details.remove("agent_id");
    scope_details.remove("principal_id");
    scope_details.remove("subject");
    scope_details.remove("audience");
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
