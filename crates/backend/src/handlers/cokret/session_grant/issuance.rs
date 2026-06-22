use chrono::{DateTime, Utc};
use coauth_config::CokretConfig;
use coauth_data::oauth::NewSessionGrant;
use coauth_data::{BrowserSession, Clock, RepositoryAccess, SessionGrant, UrlBuilder};
use coauth_jose::jwk::PublicJsonWebKey;
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::Keystore;
use oauth_types::scope::{Scope, ScopeToken};
use rand_core::{CryptoRngCore, RngCore};

use super::*;
use crate::handlers::cokret::*;

pub(crate) fn issue_session_grant(
    _rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    scopes: Vec<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience(
        clock,
        url_builder,
        cokret_config,
        key_store,
        browser_session,
        session_public_key,
        required_audience_for(url_builder, cokret_config),
        scopes,
        None,
        None,
    )
}

// `subject_override` lets callers bind the grant to a non-default DID — e.g.
// an OIDC bridge that just minted a `did:webvh:…` for the user on the target
// principal server, where falling back to `user_did_for` would diverge from
// the `viewer.did` returned in the same response and the principal server
// would reject the exchange with `session grant subject does not match
// principal_did`.
pub(crate) fn issue_session_grant_for_audience(
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: Option<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience_inner(
        clock,
        url_builder,
        cokret_config,
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
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: Option<String>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    issue_session_grant_for_audience_inner(
        clock,
        url_builder,
        cokret_config,
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
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    browser_session: &BrowserSession,
    session_public_key: PublicJsonWebKey,
    audience: String,
    scopes: Vec<String>,
    subject_override: Option<&str>,
    dpop_jkt: Option<String>,
    enforce_principal_did_method: bool,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let subject = subject_override.map_or_else(
        || user_did_for(url_builder, cokret_config, &browser_session.user),
        ToOwned::to_owned,
    );
    if enforce_principal_did_method {
        ensure_principal_did_method_allowed(cokret_config, &subject)?;
    }
    let session_public_key = serde_json::to_string(&session_public_key)?;

    let now = clock.now();
    let expires_at = now + cokret_config.session_grant_ttl;
    let device_id = primary_device_id_from_tokens(scopes.iter().map(String::as_str));
    let issuer = issuer_did_for(url_builder, cokret_config);
    let cnf = dpop_jkt
        .as_ref()
        .map(|jkt| SessionGrantConfirmation { jkt: jkt.clone() });
    let claims = SessionGrantPayloadClaims {
        kind: "ck.session.grant".to_owned(),
        issuer: issuer.clone(),
        subject: subject.clone(),
        service_account_id: browser_session.user.id.to_string(),
        session_public_key: session_public_key.clone(),
        audience: audience.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        revocation_ref: format!("ck:session:{}", browser_session.id),
        device_id: device_id.clone(),
        session_id: browser_session.id.to_string(),
        browser_session_id: browser_session.id.to_string(),
        cnf: cnf.clone(),
        proof_kind: None,
        scope_details: serde_json::Value::Null,
    };
    let payload_digest = session_grant_claims_hash(&claims)?;

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let payload = SessionGrantPayload {
        kind: claims.kind,
        issuer: claims.issuer,
        subject: claims.subject,
        service_account_id: claims.service_account_id,
        session_public_key: claims.session_public_key,
        audience: claims.audience,
        scopes: claims.scopes,
        not_before: claims.not_before,
        expires_at: claims.expires_at,
        revocation_ref: claims.revocation_ref,
        device_id: claims.device_id,
        session_id: claims.session_id,
        browser_session_id: claims.browser_session_id,
        cnf: claims.cnf,
        proof_kind: claims.proof_kind,
        scope_details: claims.scope_details,
        proof: SessionGrantProof {
            kind: "ck.session.grant.proof.v1".to_owned(),
            alg: alg.to_string(),
            key_id: key_id.clone(),
            canonicalization: "json-c14n-object-key-sort-v1".to_owned(),
            payload_digest_alg: "sha-256".to_owned(),
            payload_digest,
        },
    };
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id);
    let signer = key_store.signer_for_algorithm(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &*signer)?.into_string();

    Ok(SessionGrantMaterial {
        grant_jwt,
        session_public_key,
        expires_at: expires_at.to_rfc3339(),
        expires_at_timestamp: expires_at,
        issuer,
        subject,
        device_id,
        audience,
        scopes,
        dpop_jkt,
    })
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
                browser_session_id: browser_session.id,
                issuer: &material.issuer,
                subject: &material.subject,
                device_id: material.device_id.as_deref(),
                audience: &material.audience,
                scope,
                grant_jwt: &material.grant_jwt,
                session_public_key: &material.session_public_key,
                expires_at: material.expires_at_timestamp,
            },
        )
        .await
}

/// Mint a signed agent `ck.session.grant` JWT bound to the agent principal as
/// subject and the runtime's DPoP key (`cnf.jkt`). No browser session is
/// involved; `session_id` / `browser_session_id` carry the agent principal so
/// the payload shape stays uniform, and `revocation_ref` is keyed by the agent
/// principal for the soland-side freshness recheck.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_agent_session_grant(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    key_store: &Keystore,
    agent_principal_id: &str,
    audience: String,
    scopes: Vec<String>,
    dpop_jkt: String,
    session_public_key: String,
    scope_details: serde_json::Value,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    ensure_principal_did_method_allowed(cokret_config, agent_principal_id)?;
    let issuer = issuer_did_for(url_builder, cokret_config);
    let cnf = Some(SessionGrantConfirmation {
        jkt: dpop_jkt.clone(),
    });
    let claims = SessionGrantPayloadClaims {
        kind: "ck.session.grant".to_owned(),
        issuer: issuer.clone(),
        subject: agent_principal_id.to_owned(),
        service_account_id: agent_principal_id.to_owned(),
        session_public_key: session_public_key.clone(),
        audience: audience.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        revocation_ref: format!("ck:agent_session:{agent_principal_id}"),
        device_id: None,
        session_id: agent_principal_id.to_owned(),
        browser_session_id: agent_principal_id.to_owned(),
        cnf: cnf.clone(),
        proof_kind: Some(cokret_core::SessionGrantProofKind::AgentKeyProof),
        scope_details,
    };
    let payload_digest = session_grant_claims_hash(&claims)?;

    let (alg, key) = preferred_signing_key(key_store).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = key.kid().ok_or(SessionGrantError::NoSigningKey)?.to_owned();
    let payload = SessionGrantPayload {
        kind: claims.kind,
        issuer: claims.issuer,
        subject: claims.subject,
        service_account_id: claims.service_account_id,
        session_public_key: claims.session_public_key,
        audience: claims.audience,
        scopes: claims.scopes,
        not_before: claims.not_before,
        expires_at: claims.expires_at,
        revocation_ref: claims.revocation_ref,
        device_id: claims.device_id,
        session_id: claims.session_id,
        browser_session_id: claims.browser_session_id,
        cnf: claims.cnf,
        proof_kind: claims.proof_kind,
        scope_details: claims.scope_details,
        proof: SessionGrantProof {
            kind: "ck.session.grant.proof.v1".to_owned(),
            alg: alg.to_string(),
            key_id: key_id.clone(),
            canonicalization: "json-c14n-object-key-sort-v1".to_owned(),
            payload_digest_alg: "sha-256".to_owned(),
            payload_digest,
        },
    };
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id);
    let signer = key_store.signer_for_algorithm(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &*signer)?.into_string();

    Ok(SessionGrantMaterial {
        grant_jwt,
        session_public_key,
        expires_at: expires_at.to_rfc3339(),
        expires_at_timestamp: expires_at,
        issuer,
        subject: agent_principal_id.to_owned(),
        device_id: None,
        audience,
        scopes,
        dpop_jkt: Some(dpop_jkt),
    })
}
