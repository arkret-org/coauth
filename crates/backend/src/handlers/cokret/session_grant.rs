use chrono::{DateTime, Duration, Utc};
use coauth_config::CokretConfig;
use coauth_data::oauth::{NewSessionGrant, SessionGrantFilter};
use coauth_data::{
    BrowserSession, Clock, NewUserPrimaryHandlePreference, Pagination, RepositoryAccess,
    SessionGrant, UrlBuilder, User,
};
use coauth_jose::constraints::Constrainable;
use coauth_jose::jwk::{PublicJsonWebKey, PublicJsonWebKeySet};
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::Keystore;
use oauth_types::scope::{Scope, ScopeToken};
use rand_core::{CryptoRngCore, RngCore};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use ulid::Ulid;

use super::*;
use crate::handlers::common::DepotExt;

#[derive(Debug, Clone)]
pub struct SessionGrantMaterial {
    pub grant_jwt: String,
    pub session_public_key: String,
    pub expires_at: String,
    pub expires_at_timestamp: DateTime<Utc>,
    pub issuer: String,
    pub subject: String,
    pub device_id: Option<String>,
    pub audience: String,
    pub scopes: Vec<String>,
    /// RFC 7638 JWK SHA-256 thumbprint (base64url) of the DPoP proof the
    /// grant is bound to, when issuance happened on a request that
    /// carried a `DPoP` header. `None` for unbound minting paths such as
    /// internal admin minting or debug seeds without a `dpop_jwk`.
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionGrantTarget {
    pub audience: String,
    pub principal_server_name: Option<String>,
    pub principal_server_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub issuer: String,
    pub subject: String,
    pub service_account_id: String,
    pub session_public_key: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revocation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub session_id: String,
    pub browser_session_id: String,
    /// RFC 9449 §6 confirmation — when the grant was issued bound to a
    /// DPoP proof, `cnf.jkt` carries the RFC 7638 SHA-256 thumbprint
    /// (base64url) of the proof's public key. The refresh path requires
    /// any follow-up proof to recompute the same thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<SessionGrantConfirmation>,
    pub proof: SessionGrantProof,
}

/// RFC 9449 / RFC 7800 confirmation claim, carrying the JWK thumbprint
/// that binds an access token (here a session grant) to the holder's
/// proof-of-possession key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantConfirmation {
    /// `jkt` — base64url SHA-256 JWK thumbprint per RFC 7638.
    pub jkt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantProof {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: String,
    pub key_id: String,
    pub canonicalization: String,
    pub payload_digest_alg: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionGrantPayloadClaims {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) service_account_id: String,
    pub(crate) session_public_key: String,
    pub(crate) audience: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) not_before: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) revocation_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device_id: Option<String>,
    pub(crate) session_id: String,
    pub(crate) browser_session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cnf: Option<SessionGrantConfirmation>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionGrantRecord {
    id: String,
    browser_session_id: String,
    issuer: String,
    subject: String,
    device_id: Option<String>,
    audience: String,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct SessionGrantListOutcome {
    grants: Vec<SessionGrantRecord>,
}

#[derive(Debug, Serialize)]
struct SessionGrantRevokeOutcome {
    grant: SessionGrantRecord,
}

#[derive(Debug, Deserialize)]
struct SessionGrantIntrospectionRequestBody {
    id: Option<String>,
    grant_jwt: Option<String>,
    audience: Option<String>,
    proof: Option<SessionGrantIntrospectionProofInput>,
}

#[derive(Debug, Deserialize)]
struct SessionGrantIntrospectionProofInput {
    challenge: String,
    proof_jwt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionGrantIntrospectionProofClaims {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) grant_id: String,
    pub(crate) grant_jwt_hash: String,
    pub(crate) audience: String,
    pub(crate) challenge: String,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SessionGrantIntrospectionStatus {
    Active,
    Revoked,
    Expired,
    Locked,
    Suspended,
    AudienceMismatch,
    ProofRequired,
    InvalidProof,
    NotFound,
}

#[derive(Debug, Serialize)]
struct SessionGrantIntrospectionGrant {
    id: String,
    issuer: String,
    subject: String,
    service_account_id: String,
    device_id: Option<String>,
    audience: String,
    scopes: Vec<String>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    revocation_ref: String,
    // Server-to-server only: the Principal Server validating this grant needs
    // the session signing key to verify RFC 9421 PoP presentations on
    // `/_cokret/self/*` (api-conventions.md §3.2). The account-facing
    // `SessionGrantRecord` deliberately keeps this hidden.
    session_public_key: String,
}

#[derive(Debug, Serialize)]
struct SessionGrantIntrospectionOutcome {
    active: bool,
    status: SessionGrantIntrospectionStatus,
    proof_required: bool,
    one_time_use_consumed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<SessionGrantIntrospectionGrant>,
}

impl From<SessionGrant> for SessionGrantRecord {
    fn from(value: SessionGrant) -> Self {
        Self {
            id: value.id.to_string(),
            browser_session_id: value.browser_session_id.to_string(),
            issuer: value.issuer,
            subject: value.subject,
            device_id: value.device_id,
            audience: value.audience,
            scopes: value
                .scope
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            created_at: value.created_at,
            expires_at: value.expires_at,
            revoked_at: value.revoked_at,
        }
    }
}

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
    let subject = subject_override.map_or_else(
        || user_did_for(url_builder, cokret_config, &browser_session.user),
        ToOwned::to_owned,
    );
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

#[handler]
pub async fn list_session_grants(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantListOutcome>, CokretRouteError> {
    let clock = crate::handlers::make_clock();
    let subject = req.query::<String>("subject");
    let device_id = req.query::<String>("device_id");
    let audience = req.query::<String>("audience");
    let mut filter = SessionGrantFilter::new();

    if let Some(subject) = subject.as_deref() {
        filter = filter.for_subject(subject);
    }

    if let Some(device_id) = device_id.as_deref() {
        filter = filter.for_device(device_id);
    }

    if let Some(audience) = audience.as_deref() {
        filter = filter.for_audience(audience);
    }

    if let Some(browser_session_id) = req.query::<String>("browser_session_id") {
        let browser_session_id = Ulid::from_string(&browser_session_id)
            .map_err(|_| CokretRouteError::BadRequest("invalid browser_session_id".into()))?;
        filter = filter.for_browser_session(browser_session_id);
    }

    if req.query::<bool>("active_only").unwrap_or(false) {
        filter = filter.active_at(clock.now());
    }

    let _ = require_session_grant_caller(req, depot).await?;
    let mut repo = depot.repo().await?;
    let page = repo
        .oauth_session_grant()
        .list(filter, Pagination::first(100))
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantListOutcome {
        grants: page
            .edges
            .into_iter()
            .map(|edge| edge.node.into())
            .collect(),
    }))
}

#[handler]
pub async fn revoke_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantRevokeOutcome>, CokretRouteError> {
    let clock = crate::handlers::make_clock();
    let raw_id = req
        .param::<String>("id")
        .ok_or_else(|| CokretRouteError::BadRequest("missing session grant id".into()))?;
    let id = Ulid::from_string(&raw_id)
        .map_err(|_| CokretRouteError::BadRequest("invalid session grant id".into()))?;

    // Revocation is destructive — server_name scope is not enough.
    match require_session_grant_caller(req, depot).await? {
        SessionGrantAuthz::Admin => {}
        SessionGrantAuthz::PrincipalServer => {
            return Err(CokretRouteError::Forbidden(
                "session-grant revocation requires admin scope".to_owned(),
            ));
        }
    }

    let mut repo = depot.repo().await?;
    let grant = repo
        .oauth_session_grant()
        .lookup(id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or(CokretRouteError::NotFound)?;

    let grant = repo
        .oauth_session_grant()
        .revoke(&clock, grant)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantRevokeOutcome {
        grant: grant.into(),
    }))
}

fn introspection_grant_record(grant: &SessionGrant) -> SessionGrantIntrospectionGrant {
    SessionGrantIntrospectionGrant {
        id: grant.id.to_string(),
        issuer: grant.issuer.clone(),
        subject: grant.subject.clone(),
        service_account_id: grant.subject.rsplit_once(":users:").map_or_else(
            || grant.browser_session_id.to_string(),
            |(_, id)| id.to_owned(),
        ),
        device_id: grant.device_id.clone(),
        audience: grant.audience.clone(),
        scopes: grant
            .scope
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        expires_at: grant.expires_at,
        revoked_at: grant.revoked_at,
        revocation_ref: format!("ck:session:{}", grant.browser_session_id),
        session_public_key: grant.session_public_key.clone(),
    }
}

pub(crate) fn introspection_status(
    grant: &SessionGrant,
    user: Option<&User>,
    now: DateTime<Utc>,
    audience: Option<&str>,
) -> SessionGrantIntrospectionStatus {
    if audience.is_some_and(|audience| audience != grant.audience) {
        return SessionGrantIntrospectionStatus::AudienceMismatch;
    }

    if grant.revoked_at.is_some() {
        return SessionGrantIntrospectionStatus::Revoked;
    }

    if grant.expires_at <= now {
        return SessionGrantIntrospectionStatus::Expired;
    }

    if let Some(user) = user {
        if user.locked_at.is_some() {
            return SessionGrantIntrospectionStatus::Locked;
        }

        if user.deactivated_at.is_some() {
            return SessionGrantIntrospectionStatus::Suspended;
        }
    }

    SessionGrantIntrospectionStatus::Active
}

pub(crate) fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(grant_jwt.as_bytes()))
    )
}

fn verify_session_grant_introspection_proof(
    grant: &SessionGrant,
    proof: Option<&SessionGrantIntrospectionProofInput>,
    now: DateTime<Utc>,
) -> SessionGrantIntrospectionStatus {
    let Some(proof) = proof else {
        return SessionGrantIntrospectionStatus::ProofRequired;
    };
    if proof.challenge.trim().is_empty() || proof.proof_jwt.trim().is_empty() {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    let Ok(jwt) = Jwt::<SessionGrantIntrospectionProofClaims>::try_from(proof.proof_jwt.as_str())
    else {
        return SessionGrantIntrospectionStatus::InvalidProof;
    };
    let Ok(public_key) = serde_json::from_str::<PublicJsonWebKey>(&grant.session_public_key) else {
        return SessionGrantIntrospectionStatus::InvalidProof;
    };
    let jwks = PublicJsonWebKeySet::new(vec![public_key]);
    if jwt.verify_with_jwks(&jwks).is_err() {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    let claims = jwt.payload();
    let max_future_skew = Duration::try_seconds(30).unwrap();
    if claims.kind != "ck.session_grant.introspection_proof.v1"
        || claims.grant_id != grant.id.to_string()
        || claims.grant_jwt_hash != session_grant_jwt_hash(&grant.grant_jwt)
        || claims.audience != grant.audience
        || claims.challenge != proof.challenge
        || claims.expires_at <= now
        || claims.issued_at > now + max_future_skew
    {
        return SessionGrantIntrospectionStatus::InvalidProof;
    }

    SessionGrantIntrospectionStatus::Active
}

#[handler]
pub async fn introspect_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<SessionGrantIntrospectionOutcome>, CokretRouteError> {
    let body: SessionGrantIntrospectionRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;

    // Exactly one of `id` / `grant_jwt` identifies the grant. Reject both
    // missing AND both present, rather than silently preferring `id` and
    // ignoring `grant_jwt` — an ambiguous selector should be a hard error so a
    // caller never believes it introspected the JWT it sent.
    // The body parsed fine; it just fails the `oneOf` selector constraint, so
    // this is a schema_violation (not bad_json, which means unparseable JSON).
    match (body.id.is_some(), body.grant_jwt.is_some()) {
        (false, false) => {
            return Err(CokretRouteError::coded(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "exactly one of id or grant_jwt is required",
            ));
        }
        (true, true) => {
            return Err(CokretRouteError::coded(
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "id and grant_jwt are mutually exclusive",
            ));
        }
        _ => {}
    }

    let _ = require_session_grant_caller(req, depot).await?;
    let clock = crate::handlers::make_clock();
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let mut repo = depot.repo().await?;

    let grant = if let Some(id) = body.id.as_deref() {
        let id = Ulid::from_string(id)
            .map_err(|_| CokretRouteError::BadRequest("invalid session grant id".into()))?;
        repo.oauth_session_grant()
            .lookup(id)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    } else if let Some(grant_jwt) = body.grant_jwt.as_deref() {
        repo.oauth_session_grant()
            .lookup_by_grant_jwt(grant_jwt)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };

    let Some(grant) = grant else {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Ok(Json(SessionGrantIntrospectionOutcome {
            active: false,
            status: SessionGrantIntrospectionStatus::NotFound,
            proof_required: true,
            one_time_use_consumed: false,
            grant: None,
        }));
    };

    let user = if let Some(user_id) =
        parse_local_user_did_for(&url_builder, &cokret_config, &grant.subject)
    {
        repo.user()
            .lookup(user_id)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    } else {
        None
    };
    let mut status =
        introspection_status(&grant, user.as_ref(), clock.now(), body.audience.as_deref());
    let proof_required = status == SessionGrantIntrospectionStatus::Active;
    if proof_required {
        status = verify_session_grant_introspection_proof(&grant, body.proof.as_ref(), clock.now());
    }
    let mut active = status == SessionGrantIntrospectionStatus::Active;

    // The grant's authentication context (browser session) being logged out
    // MUST make the grant read inactive here, even if this grant row was not
    // individually revoked — otherwise a grant rotated out just before logout
    // could keep introspecting `active` until self-expiry. Auth Server fail
    // closed per account-lifecycle §4.1.
    if active {
        let logged_out = repo
            .browser_session()
            .lookup(grant.browser_session_id)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
            .map_or(true, |session| session.finished_at.is_some());
        if logged_out {
            status = SessionGrantIntrospectionStatus::Revoked;
            active = false;
        }
    }

    let grant_record = (status != SessionGrantIntrospectionStatus::NotFound
        && status != SessionGrantIntrospectionStatus::AudienceMismatch)
        .then(|| introspection_grant_record(&grant));

    // Introspection is READ-ONLY. The session grant is the (minutes-to-hours,
    // multi-day-via-rotation) refresh credential: the legitimate device
    // re-exchanges it for fresh short bearers, each presenting a fresh holder
    // proof, so it MUST remain valid within its TTL. Consumption/rotation is the
    // `session-grants/refresh` endpoint's job (revoke-old + issue-new), NOT
    // introspection's — revoking here made the grant single-use at the first
    // Principal Server exchange and silently broke the refresh chain.
    repo.cancel()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(SessionGrantIntrospectionOutcome {
        active,
        status,
        proof_required,
        one_time_use_consumed: false,
        grant: grant_record,
    }))
}

#[derive(Debug, Deserialize)]
pub struct PatchPrimaryHandlePreferenceRequestBody {
    #[serde(
        default,
        deserialize_with = "serde_with::rust::double_option::deserialize"
    )]
    pub primary_handle: Option<Option<String>>,
}

#[derive(Debug, Serialize)]
pub struct PrimaryHandlePreferenceOutcome {
    pub primary_handle: Option<String>,
    pub effective_at: DateTime<Utc>,
    pub source_claim_id: Option<String>,
    pub source_claim_digest: Option<String>,
}

/// `PATCH /_coauth/root/identity/primary-handle` — self-service holder
/// preference for DID `metadata.primary_handle`.
///
/// Body shape: `{ "primary_handle": "alice:example.com" }` to set, or
/// `{ "primary_handle": null }` to clear. Setting requires a current
/// `claim_issued` handle-audit event for the same holder and handle.
#[handler]
pub async fn patch_primary_handle_preference(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PrimaryHandlePreferenceOutcome>, CokretRouteError> {
    let body: PatchPrimaryHandlePreferenceRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".into()))?;
    let requested = body
        .primary_handle
        .ok_or_else(|| CokretRouteError::BadRequest("missing primary_handle".to_owned()))?;

    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();
    let activity_tracker = crate::handlers::account::extract_bound_activity_tracker(req, depot);
    let session_info = crate::handlers::account::extract_session_info(req, depot);
    let repo = depot.repo().await?;
    let (requester, mut repo) =
        crate::handlers::account::get_requester(&clock, &activity_tracker, repo, &session_info)
            .await?;

    let user = requester
        .entity
        .browser_session()
        .map(|session| session.user.clone())
        .ok_or_else(|| CokretRouteError::Unauthorized("browser session required".to_owned()))?;

    let claim = if let Some(handle) = requested.as_deref() {
        require_canonical_handle(handle)?;
        Some(
            repo.user_primary_handle_preference()
                .verified_handle_claim(user.id, handle, clock.now())
                .await
                .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
                .ok_or_else(|| {
                    CokretRouteError::BadRequest(
                        "primary_handle_not_verified_for_holder".to_owned(),
                    )
                })?,
        )
    } else {
        None
    };

    let preference = repo
        .user_primary_handle_preference()
        .set(
            &mut rng,
            &*clock,
            NewUserPrimaryHandlePreference::self_service(
                user.id,
                requested.clone(),
                claim.as_ref(),
                user.id,
            ),
        )
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(PrimaryHandlePreferenceOutcome {
        primary_handle: preference.handle,
        effective_at: preference.effective_at,
        source_claim_id: preference.source_claim_id.map(|id| id.to_string()),
        source_claim_digest: preference.source_claim_digest,
    }))
}

// ── DPoP-bound session-grant refresh + debug seed ──────────────
//
// These two handlers were added in G3.C1 to complete the device-bound
// session-grant story: `refresh_session_grant` rotates an existing
// DPoP-bound grant onto a new access token (keeping `cnf.jkt` constant),
// and `debug_issue_dpop_grant` is the cotest harness seam that mints a
// fully signed grant without going through OIDC.

#[derive(Debug, Deserialize)]
pub struct RefreshSessionGrantRequestBody {
    /// The session grant currently associated with the device. Single-use
    /// — after a successful refresh the old grant is revoked.
    pub grant_jwt: String,
    /// Optional audience override; defaults to the grant's audience.
    #[serde(default)]
    pub audience: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RefreshSessionGrantOneShotOutcome {
    pub grant_id: String,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub expires_at: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub dpop_jkt: String,
    pub previous_grant_id: String,
}

/// `POST /_cokret/gate/account/session-grants/refresh` — exchange a near-expiry
/// DPoP-bound session grant for a fresh one. The caller MUST present:
///
/// * A `DPoP` header that proves possession of the same key the existing grant is bound to
///   (`cnf.jkt` on the old grant must match the new proof's `jkt`).
/// * A request body carrying the prior grant JWT.
///
/// On success the old grant is revoked (single-use semantics — its
/// `revoked_at` is persisted) and a new grant is issued with the same
/// `cnf.jkt`, a rotated id, and a fresh expiry.
#[handler]
pub async fn refresh_session_grant(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RefreshSessionGrantOneShotOutcome>, CokretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let clock = crate::handlers::make_clock();
    let mut rng = crate::handlers::make_rng();

    // 1. DPoP proof must be present — the refresh endpoint is the canonical proof-of-possession
    //    check.
    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        // Holder proof (the device's DPoP) is the authorization for this
        // operation; its absence is an auth failure, not a malformed body.
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            "did_proof_required",
            "session-grant holder proof (DPoP) required",
        )
    })?;

    let body: RefreshSessionGrantRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;

    if body.grant_jwt.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    // 2. Parse + load the existing grant. We never verify the JWT signature here — the persisted
    //    row IS the source of truth — but we DO read the `cnf.jkt` claim out of the JWT payload to
    //    bind the proof.
    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| CokretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let prior_payload = jwt.payload().clone();
    let expected_jkt = prior_payload
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.clone())
        .ok_or_else(|| {
            CokretRouteError::BadRequest("grant_jwt is not DPoP-bound (cnf.jkt missing)".to_owned())
        })?;

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&body.grant_jwt)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::coded(
                StatusCode::NOT_FOUND,
                "session_grant_not_found",
                "no session grant matches the presented grant_jwt",
            )
        })?;

    // Single-use enforcement: a previously consumed grant can never be rotated
    // again. Re-use of a consumed grant is a credential-compromise signal (the
    // wire code is `grant_already_consumed`; this protocol rotates DPoP-bound
    // session grants, not OAuth refresh tokens — see account-lifecycle §4.1).
    if prior_grant.revoked_at.is_some() {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            "grant_already_consumed",
            "session grant already consumed; its rotation chain cannot continue",
        ));
    }

    // 3. Verify the DPoP proof against this exact endpoint, with the prior grant_jwt as the bound
    //    access token (so `ath` MUST match).
    let verifier = DpopVerifier::shared();
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, now, Some(&body.grant_jwt))
        .await
        .map_err(|error| {
            CokretRouteError::coded(StatusCode::UNAUTHORIZED, "invalid_signature", error.to_string())
        })?;

    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        CokretRouteError::coded(StatusCode::UNAUTHORIZED, "invalid_signature", error.to_string())
    })?;

    // 4. Resolve the underlying browser session so the new grant lives under the same
    //    authentication context.
    let browser_session = repo
        .browser_session()
        .lookup(prior_grant.browser_session_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::Internal(Box::<dyn std::error::Error + Send + Sync>::from(
                "session grant references missing browser session",
            ))
        })?;

    // The browser session is the authentication context the grant chain hangs
    // off. Logout finishes it (sets `finished_at`) but does NOT eagerly revoke
    // outstanding grants — so without this check a logged-out device that still
    // holds the DPoP key could keep rotating its grant and stay signed in
    // forever, defeating logout. Refuse rotation once the session is finished:
    // re-authentication (a fresh browser session) is then required.
    if browser_session.finished_at.is_some() {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            "session_logged_out",
            "underlying browser session is logged out; rotation chain cannot be resumed",
        ));
    }

    // 5. Mint a new grant with the same subject + scope + audience. The
    // audience MUST NOT change across rotation: a client holding a grant for
    // one Principal Server must not be able to rotate it into a grant for a
    // different audience (which it could then exchange there). Ignore any
    // client-supplied audience; reject an explicit mismatch defensively.
    if let Some(requested) = body.audience.as_deref()
        && requested != prior_grant.audience
    {
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            "audience_mismatch",
            "session-grant rotation MUST NOT change the bound audience",
        ));
    }

    // 5. Single-use rotation gate (CAS). Atomically consume the prior grant
    // BEFORE minting its successor: `revoke_if_active` sets `revoked_at` only
    // if it is still NULL and reports whether THIS call won. Two concurrent
    // rotations of the same parent contend on the row lock, so exactly one
    // wins and the loser is rejected with `grant_already_consumed` — without
    // this, both could read the parent active and each insert an active child,
    // violating single-use rotation (account-lifecycle §4.1). Doing the consume
    // first (rather than after the insert) means the loser never mints a grant
    // it would have to throw away, and the consume + insert commit atomically
    // in this one transaction.
    let consumed = repo
        .oauth_session_grant()
        .revoke_if_active(&*clock, prior_grant.id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
    if !consumed {
        repo.cancel()
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        return Err(CokretRouteError::coded(
            StatusCode::BAD_REQUEST,
            "grant_already_consumed",
            "session grant already consumed; its rotation chain cannot continue",
        ));
    }

    // 6. Mint a new grant with the same subject + scope + audience.
    let audience = prior_grant.audience.clone();
    let scopes: Vec<String> = prior_grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let new_material = issue_session_grant_for_audience(
        &*clock,
        &url_builder,
        &cokret_config,
        &key_store,
        &browser_session,
        verification.jwk.clone(),
        audience,
        scopes,
        Some(&prior_grant.subject),
        Some(verification.jkt.clone()),
    )
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    let persisted = persist_session_grant(
        &mut repo,
        &mut rng,
        &*clock,
        &browser_session,
        &new_material,
    )
    .await
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(RefreshSessionGrantOneShotOutcome {
        grant_id: persisted.id.to_string(),
        grant_jwt: new_material.grant_jwt,
        session_public_key: new_material.session_public_key,
        expires_at: new_material.expires_at,
        audience: new_material.audience,
        scopes: new_material.scopes,
        dpop_jkt: verification.jkt,
        // The prior grant was atomically consumed by the CAS above.
        previous_grant_id: prior_grant.id.to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct RevokeSessionGrantOutcome {
    pub revoked: bool,
    pub browser_session_finished: bool,
}

/// `POST /_cokret/gate/account/session-grants/revoke` — hard-logout / explicit
/// revocation of a DPoP-bound session grant (account-lifecycle §4.1).
///
/// The caller proves possession of the key bound into the grant's `cnf.jkt`
/// (same holder proof as rotation), then we:
/// 1. revoke the presented grant (single-use; its rotation chain cannot
///    continue because each rotation already revokes its predecessor), and
/// 2. **finish the underlying browser session**, so no future holder proof —
///    even with the correct device key — can rotate a fresh grant under it
///    (`session_logged_out` on `refresh`). Re-authentication is then required.
#[handler]
pub async fn revoke_session_grant_via_holder_proof(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RevokeSessionGrantOutcome>, CokretRouteError> {
    use crate::services::dpop::{DpopVerifier, dpop_header_from_request, dpop_htu};

    let url_builder = depot.url_builder()?;
    let clock = crate::handlers::make_clock();

    let dpop_header = dpop_header_from_request(req).ok_or_else(|| {
        // Holder proof (the device's DPoP) is the authorization for this
        // operation; its absence is an auth failure, not a malformed body.
        CokretRouteError::coded(
            StatusCode::UNAUTHORIZED,
            "did_proof_required",
            "session-grant holder proof (DPoP) required",
        )
    })?;
    let body: RefreshSessionGrantRequestBody = req
        .parse_json()
        .await
        .map_err(|_| CokretRouteError::BadRequest("invalid json body".to_owned()))?;
    if body.grant_jwt.trim().is_empty() {
        return Err(CokretRouteError::BadRequest("missing grant_jwt".to_owned()));
    }

    let jwt: Jwt<'_, SessionGrantPayload> = Jwt::try_from(body.grant_jwt.as_str())
        .map_err(|_| CokretRouteError::BadRequest("grant_jwt is not parseable".to_owned()))?;
    let expected_jkt = jwt
        .payload()
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.clone())
        .ok_or_else(|| {
            CokretRouteError::BadRequest("grant_jwt is not DPoP-bound (cnf.jkt missing)".to_owned())
        })?;

    let mut repo = depot.repo().await?;
    let prior_grant = repo
        .oauth_session_grant()
        .lookup_by_grant_jwt(&body.grant_jwt)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .ok_or_else(|| {
            CokretRouteError::coded(
                StatusCode::NOT_FOUND,
                "session_grant_not_found",
                "no session grant matches the presented grant_jwt",
            )
        })?;

    // Proof-of-possession: the caller MUST hold the key the grant is bound to.
    let verifier = DpopVerifier::shared();
    let now = clock.now();
    let htm = req.method().as_str().to_ascii_uppercase();
    let public_base = url_builder.http_base();
    let htu = dpop_htu(&public_base, req);
    let verification = verifier
        .verify(&dpop_header, &htm, &htu, now, Some(&body.grant_jwt))
        .await
        .map_err(|error| {
            CokretRouteError::coded(StatusCode::UNAUTHORIZED, "invalid_signature", error.to_string())
        })?;
    DpopVerifier::require_matching_jkt(&verification.jkt, &expected_jkt).map_err(|error| {
        CokretRouteError::coded(StatusCode::UNAUTHORIZED, "invalid_signature", error.to_string())
    })?;

    let revoked = if prior_grant.revoked_at.is_none() {
        repo.oauth_session_grant()
            .revoke(&*clock, prior_grant.clone())
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        true
    } else {
        false
    };

    // Terminate the authentication context so the rotation chain cannot be
    // resumed by any holder proof (account-lifecycle §4.1). Bind the looked-up
    // session to an owned value first so the sub-repo borrow is released before
    // the follow-up `finish` re-borrows `repo`.
    let active_session = repo
        .browser_session()
        .lookup(prior_grant.browser_session_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
        .filter(|session| session.finished_at.is_none());
    let browser_session_finished = if let Some(session) = active_session {
        repo.browser_session()
            .finish(&*clock, session)
            .await
            .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;
        true
    } else {
        false
    };

    repo.save()
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?;

    Ok(Json(RevokeSessionGrantOutcome {
        revoked,
        browser_session_finished,
    }))
}
