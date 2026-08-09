use arkret_identifiers::SessionGrantId;
use arkret_models_collaboration::account_lifecycle::SessionRevokeOutcome as WireSessionRevokeOutcome;
use arkret_models_identity::{
    SessionGrantCredentialClass, SessionGrantHolderBinding, SessionGrantIssuancePreimage,
    SessionGrantProofKind, SignedSessionGrantClaims,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::oauth::{
    MIN_SESSION_GRANT_OPERATION_RETENTION_SECONDS, NewSessionGrant, NewSessionGrantOperation,
    SessionGrantCommitOutcome, SessionGrantExactOutcome, SessionGrantFilter,
    SessionGrantLifecycleState, SessionGrantOperation, SessionGrantOperationDescriptor,
    SessionGrantOperationKind, SessionGrantOperationState, SessionGrantProofAuthorization,
    SessionGrantRefreshOutcome, SessionGrantRepository, SessionGrantReserveOutcome,
    SessionGrantRevokeOutcome, SessionGrantRevokeSelector, SessionGrantRevokeTarget,
};
use coauth_data::pagination::{Node, PaginationDirection};
use coauth_data::{Clock, Page, Pagination, SessionGrant, new_id};
use coauth_oauth_types::scope::{Scope, ScopeToken};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{oauth_session_grant_operations, oauth_session_grants, user_sessions};
use crate::session_grant_codec::session_grant_id_from_bytes;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`SessionGrantRepository`].
pub struct PgOAuthSessionGrantRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgOAuthSessionGrantRepository<'c> {
    /// Create a repository backed by the provided PostgreSQL connection.
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

fn proof_kind_wire(value: SessionGrantProofKind) -> Result<String, DatabaseError> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(DatabaseError::invalid_operation)
}

fn proof_kind_from_wire(value: &str) -> Result<SessionGrantProofKind, serde_json::Error> {
    serde_json::from_value(Value::String(value.to_owned()))
}

fn operation_state_from_wire(value: &str) -> Result<SessionGrantOperationState, &'static str> {
    match value {
        "reserved" => Ok(SessionGrantOperationState::Reserved),
        "authorized" => Ok(SessionGrantOperationState::Authorized),
        "committed" => Ok(SessionGrantOperationState::Committed),
        "evicted" => Ok(SessionGrantOperationState::Evicted),
        _ => Err("unknown session-grant operation state"),
    }
}

fn lifecycle_from_wire(value: &str) -> Result<SessionGrantLifecycleState, &'static str> {
    match value {
        "active" => Ok(SessionGrantLifecycleState::Active),
        "revoked" => Ok(SessionGrantLifecycleState::Revoked),
        "superseded" => Ok(SessionGrantLifecycleState::Superseded),
        _ => Err("unknown session-grant lifecycle state"),
    }
}

fn fixed_digest(value: &[u8], label: &'static str) -> Result<[u8; 32], std::io::Error> {
    value.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} must contain exactly 32 bytes"),
        )
    })
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_session_grant_operations)]
struct SessionGrantOperationRow {
    id: Uuid,
    issuer: String,
    operation_kind: String,
    proof_kind: Option<String>,
    request_identity: String,
    canonical_intent_digest: Vec<u8>,
    canonical_intent: Option<Vec<u8>>,
    operation_selector: Option<Value>,
    issuance_nonce: Option<String>,
    session_id: Option<String>,
    grant_not_before: Option<DateTime<Utc>>,
    grant_expires_at: Option<DateTime<Utc>>,
    signing_key_id: Option<String>,
    state: String,
    proof_authorization_ref: Option<String>,
    proof_authorization_checkpoint: Option<Value>,
    proof_expires_at: Option<DateTime<Utc>>,
    outcome_digest: Option<Vec<u8>>,
    canonical_outcome: Option<Vec<u8>>,
    target_grant_id: Option<Vec<u8>>,
    result_grant_id: Option<Vec<u8>>,
    affected_grant_ids: Vec<Option<Vec<u8>>>,
    retained_until: DateTime<Utc>,
    committed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl TryFrom<SessionGrantOperationRow> for SessionGrantOperation {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionGrantOperationRow) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let inconsistent = |column, source: Box<dyn std::error::Error + Send + Sync>| {
            DatabaseInconsistencyError::on("oauth_session_grant_operations")
                .column(column)
                .row(id)
                .source(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    source.to_string(),
                ))
        };
        let operation_kind = SessionGrantOperationKind::try_from(value.operation_kind.as_str())
            .map_err(|error| inconsistent("operation_kind", Box::new(error)))?;
        let operation = match operation_kind {
            SessionGrantOperationKind::Issue if value.operation_selector.is_none() => {
                SessionGrantOperationDescriptor::Issue
            }
            SessionGrantOperationKind::Refresh => {
                #[derive(serde::Deserialize)]
                struct RefreshSelector {
                    predecessor_grant_id: SessionGrantId,
                }
                let selector: RefreshSelector =
                    serde_json::from_value(value.operation_selector.clone().ok_or_else(|| {
                        inconsistent(
                            "operation_selector",
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "refresh operation selector is missing",
                            )),
                        )
                    })?)
                    .map_err(|error| inconsistent("operation_selector", Box::new(error)))?;
                SessionGrantOperationDescriptor::Refresh {
                    predecessor_grant_id: selector.predecessor_grant_id,
                }
            }
            SessionGrantOperationKind::Revoke => SessionGrantOperationDescriptor::Revoke {
                selector: serde_json::from_value(value.operation_selector.clone().ok_or_else(
                    || {
                        inconsistent(
                            "operation_selector",
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "revoke operation selector is missing",
                            )),
                        )
                    },
                )?)
                .map_err(|error| inconsistent("operation_selector", Box::new(error)))?,
            },
            SessionGrantOperationKind::Issue => {
                return Err(inconsistent(
                    "operation_selector",
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "issue operation selector must be absent",
                    )),
                ));
            }
        };
        let proof_kind = value
            .proof_kind
            .as_deref()
            .map(proof_kind_from_wire)
            .transpose()
            .map_err(|error| inconsistent("proof_kind", Box::new(error)))?;
        let canonical_intent_digest =
            fixed_digest(&value.canonical_intent_digest, "canonical_intent_digest")
                .map_err(|error| inconsistent("canonical_intent_digest", Box::new(error)))?;
        let outcome_digest = value
            .outcome_digest
            .as_deref()
            .map(|digest| fixed_digest(digest, "outcome_digest"))
            .transpose()
            .map_err(|error| inconsistent("outcome_digest", Box::new(error)))?;
        let target_grant_id = value
            .target_grant_id
            .as_deref()
            .map(session_grant_id_from_bytes)
            .transpose()
            .map_err(|error| inconsistent("target_grant_id", Box::new(error)))?;
        let result_grant_id = value
            .result_grant_id
            .as_deref()
            .map(session_grant_id_from_bytes)
            .transpose()
            .map_err(|error| inconsistent("result_grant_id", Box::new(error)))?;
        let affected_grant_ids = value
            .affected_grant_ids
            .iter()
            .map(|stored| {
                stored.as_deref().ok_or_else(|| {
                    arkret_identifiers::IdentifierError::InvalidId(
                        "affected grant id must not be NULL".to_owned(),
                    )
                })
            })
            .map(|stored| stored.and_then(session_grant_id_from_bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| inconsistent("affected_grant_ids", Box::new(error)))?;
        let state = operation_state_from_wire(&value.state).map_err(|message| {
            inconsistent(
                "state",
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    message,
                )),
            )
        })?;

        Ok(Self {
            id,
            issuer: value.issuer,
            operation,
            proof_kind,
            request_identity: value.request_identity,
            canonical_intent_digest,
            canonical_intent: value.canonical_intent,
            issuance_nonce: value.issuance_nonce,
            session_id: value.session_id,
            grant_not_before: value.grant_not_before,
            grant_expires_at: value.grant_expires_at,
            signing_key_id: value.signing_key_id,
            state,
            proof_authorization_ref: value.proof_authorization_ref,
            proof_authorization_checkpoint: value.proof_authorization_checkpoint,
            proof_expires_at: value.proof_expires_at,
            outcome_digest,
            canonical_outcome: value.canonical_outcome,
            target_grant_id,
            result_grant_id,
            affected_grant_ids,
            retained_until: value.retained_until,
            created_at: value.created_at,
            committed_at: value.committed_at,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = oauth_session_grant_operations)]
struct NewSessionGrantOperationRow<'a> {
    id: Uuid,
    issuer: &'a str,
    operation_kind: &'a str,
    proof_kind: Option<&'a str>,
    request_identity: &'a str,
    canonical_intent_digest: Vec<u8>,
    canonical_intent: Option<&'a [u8]>,
    operation_selector: Option<Value>,
    issuance_nonce: Option<String>,
    session_id: Option<String>,
    grant_not_before: Option<DateTime<Utc>>,
    grant_expires_at: Option<DateTime<Utc>>,
    signing_key_id: Option<&'a str>,
    state: &'static str,
    target_grant_id: Option<Vec<u8>>,
    retained_until: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_session_grants)]
struct SessionGrantLookup {
    id: Uuid,
    grant_id: Vec<u8>,
    issuance_operation_id: Uuid,
    user_session_id: Option<Uuid>,
    issuer: String,
    subject: String,
    device_id: Option<String>,
    applet_id: Option<String>,
    effective_scope: Option<Value>,
    registration_epoch: Option<String>,
    service_id: Option<String>,
    capability_grant_refs: Vec<String>,
    audience: String,
    scope_list: Vec<String>,
    grant_jwt: String,
    session_id: String,
    issuance_nonce: String,
    issuance_preimage: Vec<u8>,
    issuance_digest: Vec<u8>,
    signing_key_id: String,
    session_public_key: String,
    credential_class: String,
    expires_at: DateTime<Utc>,
    lifecycle_state: String,
    revoked_at: Option<DateTime<Utc>>,
    superseded_at: Option<DateTime<Utc>>,
    successor_grant_id: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
}

impl Node<Ulid> for SessionGrantLookup {
    fn cursor(&self) -> Ulid {
        self.id.into()
    }
}

impl TryFrom<SessionGrantLookup> for SessionGrant {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: SessionGrantLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.id);
        let grant_id = session_grant_id_from_bytes(&value.grant_id).map_err(|error| {
            DatabaseInconsistencyError::on("oauth_session_grants")
                .column("grant_id")
                .row(id)
                .source(error)
        })?;
        let scope: Result<Scope, _> = value
            .scope_list
            .iter()
            .map(|s| s.parse::<ScopeToken>())
            .collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("oauth_session_grants")
                .column("scope_list")
                .row(id)
                .source(e)
        })?;
        let issuance_digest =
            fixed_digest(&value.issuance_digest, "issuance_digest").map_err(|error| {
                DatabaseInconsistencyError::on("oauth_session_grants")
                    .column("issuance_digest")
                    .row(id)
                    .source(error)
            })?;
        let lifecycle_state = lifecycle_from_wire(&value.lifecycle_state).map_err(|message| {
            DatabaseInconsistencyError::on("oauth_session_grants")
                .column("lifecycle_state")
                .row(id)
                .source(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    message,
                ))
        })?;
        let successor_grant_id = value
            .successor_grant_id
            .as_deref()
            .map(session_grant_id_from_bytes)
            .transpose()
            .map_err(|error| {
                DatabaseInconsistencyError::on("oauth_session_grants")
                    .column("successor_grant_id")
                    .row(id)
                    .source(error)
            })?;

        Ok(Self {
            id,
            grant_id,
            browser_session_id: value.user_session_id.map(Into::into),
            issuer: value.issuer,
            subject: value.subject,
            device_id: value.device_id,
            applet_id: value.applet_id,
            effective_scope: value.effective_scope,
            registration_epoch: value.registration_epoch,
            service_id: value.service_id,
            capability_grant_refs: value.capability_grant_refs,
            audience: value.audience,
            scope,
            grant_jwt: value.grant_jwt,
            session_id: value.session_id,
            issuance_nonce: value.issuance_nonce,
            issuance_preimage: value.issuance_preimage,
            issuance_digest,
            signing_key_id: value.signing_key_id,
            session_public_key: value.session_public_key,
            credential_class: value.credential_class,
            created_at: value.created_at,
            expires_at: value.expires_at,
            lifecycle_state,
            revoked_at: value.revoked_at,
            superseded_at: value.superseded_at,
            successor_grant_id,
            issuance_operation_id: value.issuance_operation_id.into(),
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = oauth_session_grants)]
struct NewSessionGrantRow<'a> {
    id: Uuid,
    grant_id: Vec<u8>,
    issuance_operation_id: Uuid,
    user_session_id: Option<Uuid>,
    issuer: &'a str,
    subject: &'a str,
    device_id: Option<&'a str>,
    applet_id: Option<&'a str>,
    effective_scope: Option<Value>,
    registration_epoch: Option<&'a str>,
    service_id: Option<&'a str>,
    capability_grant_refs: Vec<String>,
    audience: &'a str,
    scope_list: Vec<String>,
    grant_jwt: &'a str,
    session_id: &'a str,
    issuance_nonce: &'a str,
    issuance_preimage: &'a [u8],
    issuance_digest: Vec<u8>,
    signing_key_id: &'a str,
    session_public_key: &'a str,
    credential_class: &'a str,
    expires_at: DateTime<Utc>,
    lifecycle_state: &'static str,
    created_at: DateTime<Utc>,
}

fn validate_grant_material(
    operation: &SessionGrantOperation,
    grant: &NewSessionGrant<'_>,
) -> Result<(), DatabaseError> {
    let preimage: SessionGrantIssuancePreimage = serde_json::from_slice(grant.issuance_preimage)
        .map_err(|_| DatabaseError::invalid_operation())?;
    preimage
        .validate()
        .map_err(|_| DatabaseError::invalid_operation())?;
    let canonical_preimage = preimage
        .canonical_bytes()
        .map_err(|_| DatabaseError::invalid_operation())?;

    let mut jwt_parts = grant.grant_jwt.split('.');
    let header_segment = jwt_parts
        .next()
        .ok_or_else(DatabaseError::invalid_operation)?;
    let claims_segment = jwt_parts
        .next()
        .ok_or_else(DatabaseError::invalid_operation)?;
    let signature_segment = jwt_parts
        .next()
        .ok_or_else(DatabaseError::invalid_operation)?;
    if signature_segment.is_empty() || jwt_parts.next().is_some() {
        return Err(DatabaseError::invalid_operation());
    }
    let header_bytes = arkret_canonical::base64url_decode(header_segment)
        .map_err(|_| DatabaseError::invalid_operation())?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| DatabaseError::invalid_operation())?;
    let header_kid = header
        .as_object()
        .and_then(|header| header.get("kid"))
        .and_then(Value::as_str)
        .ok_or_else(DatabaseError::invalid_operation)?;
    let claims_bytes = arkret_canonical::base64url_decode(claims_segment)
        .map_err(|_| DatabaseError::invalid_operation())?;
    let claims: SignedSessionGrantClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| DatabaseError::invalid_operation())?;
    claims
        .validate()
        .map_err(|_| DatabaseError::invalid_operation())?;

    let claim_preimage = claims.issuance_preimage();
    let scope_list = grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect::<Vec<_>>();
    let credential_class = serde_json::to_value(preimage.credential_class)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(DatabaseError::invalid_operation)?;
    let constraints = [
        (
            "operation_issuance_nonce",
            operation.issuance_nonce.as_deref() == Some(grant.issuance_nonce),
        ),
        (
            "operation_session_id",
            operation.session_id.as_deref() == Some(grant.session_id),
        ),
        (
            "operation_not_before",
            operation.grant_not_before == Some(grant.not_before),
        ),
        (
            "operation_expires_at",
            operation.grant_expires_at == Some(grant.expires_at),
        ),
        (
            "operation_signing_key",
            operation.signing_key_id.as_deref() == Some(grant.signing_key_id),
        ),
        (
            "grant_id_digest",
            grant.grant_id.issuance_digest() == grant.issuance_digest,
        ),
        (
            "preimage_digest",
            arkret_canonical::sha256_bytes(grant.issuance_preimage) == grant.issuance_digest,
        ),
        (
            "session_id_domain",
            grant.session_id != grant.grant_id.as_str(),
        ),
        (
            "canonical_preimage",
            canonical_preimage == grant.issuance_preimage,
        ),
        ("claims_preimage", claims.issuance_preimage() == preimage),
        (
            "claims_grant_id_derivation",
            claim_preimage.grant_id().ok().as_ref() == Some(&grant.grant_id),
        ),
        ("header_kid", header_kid == grant.signing_key_id),
        (
            "preimage_issuer",
            preimage.issuer.to_string() == grant.issuer,
        ),
        ("operation_issuer", operation.issuer == grant.issuer),
        (
            "preimage_subject",
            preimage.subject.to_string() == grant.subject,
        ),
        (
            "preimage_audience",
            preimage.audience.to_string() == grant.audience,
        ),
        (
            "preimage_issuance_nonce",
            preimage.issuance_nonce.as_str() == grant.issuance_nonce,
        ),
        (
            "preimage_session_key",
            preimage.session_public_key.as_str() == grant.session_public_key,
        ),
        ("preimage_scopes", preimage.scopes == scope_list),
        (
            "preimage_not_before",
            preimage.not_before == grant.not_before,
        ),
        (
            "preimage_expires_at",
            preimage.expires_at == grant.expires_at,
        ),
        (
            "preimage_session_id",
            preimage.session_id == grant.session_id,
        ),
        (
            "credential_class",
            credential_class == grant.credential_class,
        ),
        ("claims_grant_id", claims.grant_id == grant.grant_id),
        (
            "issue_proof_kind",
            operation.operation.kind() != SessionGrantOperationKind::Issue
                || operation.proof_kind == preimage.proof_kind,
        ),
        (
            "non_issue_proof_kind",
            operation.operation.kind() == SessionGrantOperationKind::Issue
                || operation.proof_kind.is_none(),
        ),
    ];
    if let Some((constraint, _)) = constraints.iter().find(|(_, valid)| !valid) {
        tracing::error!(constraint, "session grant material constraint failed");
        return Err(DatabaseError::invalid_operation());
    }
    if preimage.credential_class != SessionGrantCredentialClass::Standard {
        return Err(DatabaseError::invalid_operation());
    }
    let bound_device_id = if let Some(binding) = preimage.device_binding.as_ref() {
        Some(binding.device_id.as_str())
    } else {
        Some(match &preimage.holder_binding {
            SessionGrantHolderBinding::HumanDevice { device_binding } => device_binding.as_str(),
            SessionGrantHolderBinding::AgentRuntime { device_id, .. } => device_id.as_str(),
        })
    };
    if grant.device_id != bound_device_id {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

fn validate_refresh_chain(
    predecessor: &SessionGrant,
    successor: &NewSessionGrant<'_>,
) -> Result<(), DatabaseError> {
    let predecessor_preimage: SessionGrantIssuancePreimage =
        serde_json::from_slice(&predecessor.issuance_preimage)
            .map_err(|_| DatabaseError::invalid_operation())?;
    let successor_preimage: SessionGrantIssuancePreimage =
        serde_json::from_slice(successor.issuance_preimage)
            .map_err(|_| DatabaseError::invalid_operation())?;
    let common_binding_mismatch = predecessor_preimage.issuer != successor_preimage.issuer
        || predecessor_preimage.subject != successor_preimage.subject
        || predecessor_preimage.audience != successor_preimage.audience
        || predecessor_preimage.session_id != successor_preimage.session_id
        || predecessor_preimage.cnf != successor_preimage.cnf
        || successor_preimage
            .scopes
            .iter()
            .any(|scope| !predecessor_preimage.scopes.contains(scope));
    if common_binding_mismatch {
        return Err(DatabaseError::invalid_operation());
    }

    if predecessor_preimage.credential_class != SessionGrantCredentialClass::Standard
        || successor_preimage.credential_class != SessionGrantCredentialClass::Standard
        || predecessor_preimage.holder_binding != successor_preimage.holder_binding
        || predecessor_preimage.device_binding != successor_preimage.device_binding
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

fn new_grant_row<'a>(
    id: Ulid,
    operation_id: Ulid,
    created_at: DateTime<Utc>,
    grant: &'a NewSessionGrant<'a>,
) -> NewSessionGrantRow<'a> {
    NewSessionGrantRow {
        id: Uuid::from(id),
        grant_id: grant.grant_id.token_bytes().to_vec(),
        issuance_operation_id: Uuid::from(operation_id),
        user_session_id: grant.browser_session_id.map(Uuid::from),
        issuer: grant.issuer,
        subject: grant.subject,
        device_id: grant.device_id,
        applet_id: grant.applet_id,
        effective_scope: grant.effective_scope.clone(),
        registration_epoch: grant.registration_epoch,
        service_id: grant.service_id,
        capability_grant_refs: grant.capability_grant_refs.clone(),
        audience: grant.audience,
        scope_list: grant
            .scope
            .iter()
            .map(|token| token.as_str().to_owned())
            .collect(),
        grant_jwt: grant.grant_jwt,
        session_id: grant.session_id,
        issuance_nonce: grant.issuance_nonce,
        issuance_preimage: grant.issuance_preimage,
        issuance_digest: grant.issuance_digest.to_vec(),
        signing_key_id: grant.signing_key_id,
        session_public_key: grant.session_public_key,
        credential_class: grant.credential_class,
        expires_at: grant.expires_at,
        lifecycle_state: "active",
        created_at,
    }
}

fn owned_grant(
    id: Ulid,
    operation_id: Ulid,
    created_at: DateTime<Utc>,
    grant: NewSessionGrant<'_>,
) -> SessionGrant {
    SessionGrant {
        id,
        grant_id: grant.grant_id,
        browser_session_id: grant.browser_session_id,
        issuer: grant.issuer.to_owned(),
        subject: grant.subject.to_owned(),
        device_id: grant.device_id.map(ToOwned::to_owned),
        applet_id: grant.applet_id.map(ToOwned::to_owned),
        effective_scope: grant.effective_scope,
        registration_epoch: grant.registration_epoch.map(ToOwned::to_owned),
        service_id: grant.service_id.map(ToOwned::to_owned),
        capability_grant_refs: grant.capability_grant_refs,
        audience: grant.audience.to_owned(),
        scope: grant.scope,
        grant_jwt: grant.grant_jwt.to_owned(),
        session_id: grant.session_id.to_owned(),
        issuance_nonce: grant.issuance_nonce.to_owned(),
        issuance_preimage: grant.issuance_preimage.to_vec(),
        issuance_digest: grant.issuance_digest,
        signing_key_id: grant.signing_key_id.to_owned(),
        session_public_key: grant.session_public_key.to_owned(),
        credential_class: grant.credential_class.to_owned(),
        created_at,
        expires_at: grant.expires_at,
        lifecycle_state: SessionGrantLifecycleState::Active,
        revoked_at: None,
        superseded_at: None,
        successor_grant_id: None,
        issuance_operation_id: operation_id,
    }
}

async fn load_operation_for_update(
    conn: &mut diesel_async::AsyncPgConnection,
    operation_id: Ulid,
) -> Result<SessionGrantOperation, DatabaseError> {
    oauth_session_grant_operations::table
        .find(Uuid::from(operation_id))
        .for_update()
        .select(SessionGrantOperationRow::as_select())
        .first::<SessionGrantOperationRow>(conn)
        .await
        .optional()?
        .ok_or_else(DatabaseError::invalid_operation)?
        .try_into()
        .map_err(Into::into)
}

async fn load_grant_by_protocol_id(
    conn: &mut diesel_async::AsyncPgConnection,
    grant_id: &SessionGrantId,
) -> Result<Option<SessionGrant>, DatabaseError> {
    oauth_session_grants::table
        .filter(oauth_session_grants::grant_id.eq(grant_id.token_bytes().to_vec()))
        .select(SessionGrantLookup::as_select())
        .first::<SessionGrantLookup>(conn)
        .await
        .optional()?
        .map(SessionGrant::try_from)
        .transpose()
        .map_err(Into::into)
}

async fn load_grant_by_protocol_id_for_update(
    conn: &mut diesel_async::AsyncPgConnection,
    grant_id: &SessionGrantId,
) -> Result<Option<SessionGrant>, DatabaseError> {
    oauth_session_grants::table
        .filter(oauth_session_grants::grant_id.eq(grant_id.token_bytes().to_vec()))
        .for_update()
        .select(SessionGrantLookup::as_select())
        .first::<SessionGrantLookup>(conn)
        .await
        .optional()?
        .map(SessionGrant::try_from)
        .transpose()
        .map_err(Into::into)
}

fn validate_exact_outcome(outcome: SessionGrantExactOutcome<'_>) -> Result<(), DatabaseError> {
    if outcome.canonical_response.is_empty()
        || arkret_canonical::sha256_bytes(outcome.canonical_response) != outcome.response_digest
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

fn authorization_matches(
    operation: &SessionGrantOperation,
    authorization: SessionGrantProofAuthorization<'_>,
) -> bool {
    operation.proof_authorization_ref.as_deref() == Some(authorization.authorization_ref)
        && operation.proof_authorization_checkpoint.as_ref() == Some(authorization.checkpoint)
        && operation.proof_expires_at == Some(authorization.proof_expires_at)
}

fn validate_authorization(
    operation: &SessionGrantOperation,
    authorization: SessionGrantProofAuthorization<'_>,
    now: DateTime<Utc>,
) -> Result<(), DatabaseError> {
    if authorization.authorization_ref.trim().is_empty()
        || operation.state == SessionGrantOperationState::Reserved
            && authorization.proof_expires_at <= now
        || matches!(
            operation.state,
            SessionGrantOperationState::Authorized | SessionGrantOperationState::Committed
        ) && !authorization_matches(operation, authorization)
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

#[cfg(test)]
mod authorization_checkpoint_tests {
    use super::*;

    fn operation(
        state: SessionGrantOperationState,
        authorization: SessionGrantProofAuthorization<'_>,
        now: DateTime<Utc>,
    ) -> SessionGrantOperation {
        SessionGrantOperation {
            id: Ulid::from(1_u128),
            issuer: "did:web:issuer.example".to_owned(),
            operation: SessionGrantOperationDescriptor::Issue,
            proof_kind: None,
            request_identity: "oidc-code-hash".to_owned(),
            canonical_intent_digest: [7; 32],
            canonical_intent: Some(br#"{"kind":"oidc"}"#.to_vec()),
            issuance_nonce: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_owned()),
            session_id: Some("session-1".to_owned()),
            grant_not_before: Some(now - chrono::Duration::try_minutes(10).unwrap()),
            grant_expires_at: Some(now + chrono::Duration::try_minutes(50).unwrap()),
            signing_key_id: Some("key-1".to_owned()),
            proof_authorization_ref: Some(authorization.authorization_ref.to_owned()),
            proof_authorization_checkpoint: Some(authorization.checkpoint.clone()),
            proof_expires_at: Some(authorization.proof_expires_at),
            outcome_digest: None,
            canonical_outcome: None,
            state,
            target_grant_id: None,
            result_grant_id: None,
            affected_grant_ids: Vec::new(),
            retained_until: now + chrono::Duration::try_days(7).unwrap(),
            created_at: now - chrono::Duration::try_minutes(10).unwrap(),
            committed_at: None,
        }
    }

    #[test]
    fn authorized_exact_checkpoint_can_finish_after_proof_expiry() {
        let now = Utc::now();
        let checkpoint = serde_json::json!({"kind":"oidc","subject":"did:web:alice.example"});
        let authorization = SessionGrantProofAuthorization {
            authorization_ref: "oidc:code-hash",
            checkpoint: &checkpoint,
            proof_expires_at: now - chrono::Duration::try_minutes(1).unwrap(),
        };
        let operation = operation(SessionGrantOperationState::Authorized, authorization, now);

        validate_authorization(&operation, authorization, now)
            .expect("an exact durable checkpoint remains resumable after five minutes");
    }

    #[test]
    fn reserved_operation_cannot_first_consume_expired_proof() {
        let now = Utc::now();
        let checkpoint = serde_json::json!({"kind":"oidc"});
        let authorization = SessionGrantProofAuthorization {
            authorization_ref: "oidc:code-hash",
            checkpoint: &checkpoint,
            proof_expires_at: now - chrono::Duration::try_seconds(1).unwrap(),
        };
        let operation = operation(SessionGrantOperationState::Reserved, authorization, now);

        assert!(validate_authorization(&operation, authorization, now).is_err());
    }

    #[test]
    fn authorized_resume_rejects_changed_checkpoint_after_expiry() {
        let now = Utc::now();
        let stored = serde_json::json!({"kind":"oidc","subject":"did:web:alice.example"});
        let changed = serde_json::json!({"kind":"oidc","subject":"did:web:bob.example"});
        let stored_authorization = SessionGrantProofAuthorization {
            authorization_ref: "oidc:code-hash",
            checkpoint: &stored,
            proof_expires_at: now - chrono::Duration::try_minutes(1).unwrap(),
        };
        let operation = operation(
            SessionGrantOperationState::Authorized,
            stored_authorization,
            now,
        );
        let changed_authorization = SessionGrantProofAuthorization {
            checkpoint: &changed,
            ..stored_authorization
        };

        assert!(validate_authorization(&operation, changed_authorization, now).is_err());
    }
}

async fn evict_operation(
    conn: &mut diesel_async::AsyncPgConnection,
    operation_id: Ulid,
) -> Result<SessionGrantOperation, DatabaseError> {
    diesel::update(oauth_session_grant_operations::table.find(Uuid::from(operation_id)))
        .set((
            oauth_session_grant_operations::state.eq("evicted"),
            oauth_session_grant_operations::canonical_intent.eq(None::<Vec<u8>>),
            oauth_session_grant_operations::operation_selector.eq(None::<Value>),
            oauth_session_grant_operations::issuance_nonce.eq(None::<String>),
            oauth_session_grant_operations::session_id.eq(None::<String>),
            oauth_session_grant_operations::grant_not_before.eq(None::<DateTime<Utc>>),
            oauth_session_grant_operations::grant_expires_at.eq(None::<DateTime<Utc>>),
            oauth_session_grant_operations::signing_key_id.eq(None::<String>),
            oauth_session_grant_operations::proof_authorization_ref.eq(None::<String>),
            oauth_session_grant_operations::proof_authorization_checkpoint.eq(None::<Value>),
            oauth_session_grant_operations::proof_expires_at.eq(None::<DateTime<Utc>>),
            oauth_session_grant_operations::outcome_digest.eq(None::<Vec<u8>>),
            oauth_session_grant_operations::canonical_outcome.eq(None::<Vec<u8>>),
        ))
        .execute(conn)
        .await?;
    load_operation_for_update(conn, operation_id).await
}

async fn lock_session_grant_subject(
    conn: &mut diesel_async::AsyncPgConnection,
    issuer: &str,
    subject: &str,
) -> Result<(), DatabaseError> {
    let key = crate::advisory_lock::advisory_lock_key(&format!(
        "coauth:session-grant-ledger:{issuer}:{subject}"
    ));
    diesel::sql_query("SELECT pg_advisory_xact_lock($1), true AS acquired")
        .bind::<diesel::sql_types::BigInt, _>(key)
        .get_result::<crate::advisory_lock::AdvisoryLockResult>(conn)
        .await?;
    Ok(())
}

async fn commit_operation_outcome(
    conn: &mut diesel_async::AsyncPgConnection,
    operation_id: Ulid,
    authorization: SessionGrantProofAuthorization<'_>,
    outcome: SessionGrantExactOutcome<'_>,
    target_grant_id: Option<&SessionGrantId>,
    result_grant_id: Option<&SessionGrantId>,
    affected_grant_ids: &[SessionGrantId],
    retained_until: DateTime<Utc>,
    committed_at: DateTime<Utc>,
) -> Result<(), DatabaseError> {
    let affected_grant_ids = affected_grant_ids
        .iter()
        .map(|id| Some(id.token_bytes().to_vec()))
        .collect::<Vec<_>>();
    let rows = diesel::update(
        oauth_session_grant_operations::table
            .find(Uuid::from(operation_id))
            .filter(oauth_session_grant_operations::state.ne("evicted")),
    )
    .set((
        oauth_session_grant_operations::state.eq("committed"),
        oauth_session_grant_operations::proof_authorization_ref
            .eq(Some(authorization.authorization_ref)),
        oauth_session_grant_operations::proof_authorization_checkpoint
            .eq(Some(authorization.checkpoint.clone())),
        oauth_session_grant_operations::proof_expires_at.eq(Some(authorization.proof_expires_at)),
        oauth_session_grant_operations::outcome_digest.eq(Some(outcome.response_digest.to_vec())),
        oauth_session_grant_operations::canonical_outcome
            .eq(Some(outcome.canonical_response.to_vec())),
        oauth_session_grant_operations::target_grant_id
            .eq(target_grant_id.map(|id| id.token_bytes().to_vec())),
        oauth_session_grant_operations::result_grant_id
            .eq(result_grant_id.map(|id| id.token_bytes().to_vec())),
        oauth_session_grant_operations::affected_grant_ids.eq(affected_grant_ids),
        oauth_session_grant_operations::retained_until.eq(retained_until),
        oauth_session_grant_operations::committed_at.eq(Some(committed_at)),
    ))
    .execute(conn)
    .await?;
    DatabaseError::ensure_affected_rows_usize(rows, 1)
}

macro_rules! apply_session_grant_filter {
    ($query:expr, $filter:expr) => {{
        let mut q = $query;

        if let Some(user_session_id) = $filter.browser_session_id() {
            q = q.filter(
                oauth_session_grants::user_session_id.eq(Some(Uuid::from(user_session_id))),
            );
        }

        if let Some(account_id) = $filter.account_id() {
            // Owning account is the `user_id` of the browser session the grant
            // is bound to. Push the ownership check down as a subquery on
            // `user_sessions` instead of paging the whole table and resolving
            // each owner in memory. Grants with `user_session_id IS NULL` are
            // excluded because the subquery never yields NULL.
            let owned_sessions = user_sessions::table
                .filter(user_sessions::user_id.eq(Uuid::from(account_id)))
                .select(user_sessions::id.nullable());
            q = q.filter(oauth_session_grants::user_session_id.eq_any(owned_sessions));
        }

        if let Some(subject) = $filter.subject() {
            q = q.filter(oauth_session_grants::subject.eq(subject));
        }

        if let Some(device_id) = $filter.device_id() {
            q = q.filter(oauth_session_grants::device_id.eq(device_id));
        }

        if let Some(applet_id) = $filter.applet_id() {
            q = q.filter(oauth_session_grants::applet_id.eq(applet_id));
        }

        if let Some(effective_scope) = $filter.effective_scope() {
            q = q.filter(oauth_session_grants::effective_scope.eq(effective_scope));
        }

        if let Some(registration_epoch) = $filter.registration_epoch() {
            q = q.filter(oauth_session_grants::registration_epoch.eq(registration_epoch));
        }

        if let Some(service_id) = $filter.service_id() {
            q = q.filter(oauth_session_grants::service_id.eq(service_id));
        }

        if let Some(audience) = $filter.audience() {
            q = q.filter(oauth_session_grants::audience.eq(audience));
        }

        if let Some(active_at) = $filter.active_at_value() {
            q = q
                .filter(oauth_session_grants::lifecycle_state.eq("active"))
                .filter(oauth_session_grants::expires_at.gt(active_at));
        }

        q
    }};
}

#[async_trait]
impl SessionGrantRepository for PgOAuthSessionGrantRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(name = "db.oauth_session_grant.reserve_operation", skip_all, err)]
    async fn reserve_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation: NewSessionGrantOperation<'_>,
    ) -> Result<SessionGrantReserveOutcome, Self::Error> {
        let now = clock.now();
        if operation.issuer.trim().is_empty()
            || operation.request_identity.trim().is_empty()
            || operation.canonical_intent.is_empty()
            || arkret_canonical::sha256_bytes(operation.canonical_intent)
                != operation.canonical_intent_digest
        {
            return Err(DatabaseError::invalid_operation());
        }
        let operation_kind = operation.operation.kind();
        let operation_selector = match &operation.operation {
            SessionGrantOperationDescriptor::Issue => None,
            SessionGrantOperationDescriptor::Refresh {
                predecessor_grant_id,
            } => Some(serde_json::json!({
                "predecessor_grant_id": predecessor_grant_id,
            })),
            SessionGrantOperationDescriptor::Revoke { selector } => Some(
                serde_json::to_value(selector).map_err(|_| DatabaseError::invalid_operation())?,
            ),
        };
        let proof_kind = operation.proof_kind.map(proof_kind_wire).transpose()?;
        if (operation_kind == SessionGrantOperationKind::Issue) != proof_kind.is_some() {
            return Err(DatabaseError::invalid_operation());
        }
        let grant_producing = operation_kind != SessionGrantOperationKind::Revoke;
        if grant_producing
            && (operation.grant_not_before.is_none()
                || operation.grant_expires_at <= operation.grant_not_before
                || operation
                    .signing_key_id
                    .is_none_or(|kid| kid.trim().is_empty()))
        {
            return Err(DatabaseError::invalid_operation());
        }
        let inherited_session_id = match operation_kind {
            SessionGrantOperationKind::Issue => {
                if operation.target_grant_id.is_some()
                    || operation.issuance_nonce.is_some() != operation.session_id.is_some()
                    || operation
                        .issuance_nonce
                        .is_some_and(|nonce| nonce.trim().is_empty())
                    || operation
                        .session_id
                        .is_some_and(|session_id| session_id.trim().is_empty())
                {
                    return Err(DatabaseError::invalid_operation());
                }
                operation.session_id.map(ToOwned::to_owned)
            }
            SessionGrantOperationKind::Refresh => {
                if operation.issuance_nonce.is_some() {
                    return Err(DatabaseError::invalid_operation());
                }
                let target = operation
                    .target_grant_id
                    .ok_or_else(DatabaseError::invalid_operation)?;
                let predecessor = load_grant_by_protocol_id(self.conn, target)
                    .await?
                    .ok_or_else(DatabaseError::invalid_operation)?;
                if predecessor.issuer != operation.issuer
                    || operation
                        .session_id
                        .is_some_and(|session_id| session_id != predecessor.session_id)
                {
                    return Err(DatabaseError::invalid_operation());
                }
                Some(predecessor.session_id)
            }
            SessionGrantOperationKind::Revoke => {
                if operation.issuance_nonce.is_some() || operation.session_id.is_some() {
                    return Err(DatabaseError::invalid_operation());
                }
                None
            }
        };
        let (issuance_nonce, session_id) = if grant_producing {
            let issuance_nonce = if let Some(nonce) = operation.issuance_nonce {
                nonce.to_owned()
            } else {
                let mut nonce = [0_u8; 32];
                rng.fill_bytes(&mut nonce);
                arkret_canonical::base64url_encode(nonce)
            };
            let session_id = inherited_session_id
                .unwrap_or_else(|| format!("session-chain:{}", new_id(now, rng)));
            (Some(issuance_nonce), Some(session_id))
        } else {
            (None, None)
        };
        let retained_until = operation
            .retained_until
            .max(now + chrono::Duration::seconds(MIN_SESSION_GRANT_OPERATION_RETENTION_SECONDS));
        let id = new_id(now, rng);
        let row = NewSessionGrantOperationRow {
            id: Uuid::from(id),
            issuer: operation.issuer,
            operation_kind: operation_kind.as_str(),
            proof_kind: proof_kind.as_deref(),
            request_identity: operation.request_identity,
            canonical_intent_digest: operation.canonical_intent_digest.to_vec(),
            canonical_intent: Some(operation.canonical_intent),
            operation_selector,
            issuance_nonce,
            session_id,
            grant_not_before: operation.grant_not_before,
            grant_expires_at: operation.grant_expires_at,
            signing_key_id: operation.signing_key_id,
            state: "reserved",
            target_grant_id: operation
                .target_grant_id
                .map(|id| id.token_bytes().to_vec()),
            retained_until,
            created_at: now,
        };
        let inserted = diesel::insert_into(oauth_session_grant_operations::table)
            .values(&row)
            .on_conflict_do_nothing()
            .execute(self.conn)
            .await?
            == 1;

        let stored = oauth_session_grant_operations::table
            .filter(oauth_session_grant_operations::issuer.eq(operation.issuer))
            .filter(oauth_session_grant_operations::operation_kind.eq(operation_kind.as_str()))
            .filter(oauth_session_grant_operations::proof_kind.eq(proof_kind.as_deref()))
            .filter(oauth_session_grant_operations::request_identity.eq(operation.request_identity))
            .select(SessionGrantOperationRow::as_select())
            .first::<SessionGrantOperationRow>(self.conn)
            .await?;
        let stored = SessionGrantOperation::try_from(stored)?;
        if inserted {
            return Ok(SessionGrantReserveOutcome::Reserved(stored));
        }
        if stored.state == SessionGrantOperationState::Evicted {
            return if stored.canonical_intent_digest == operation.canonical_intent_digest {
                Ok(SessionGrantReserveOutcome::Indeterminate(stored))
            } else {
                Ok(SessionGrantReserveOutcome::Conflict(stored))
            };
        }
        if stored.canonical_intent_digest != operation.canonical_intent_digest
            || stored.canonical_intent.as_deref() != Some(operation.canonical_intent)
            || stored.operation != operation.operation
            || stored.target_grant_id.as_ref() != operation.target_grant_id
        {
            return Ok(SessionGrantReserveOutcome::Conflict(stored));
        }
        if now >= stored.retained_until {
            let evicted = evict_operation(self.conn, stored.id).await?;
            return Ok(SessionGrantReserveOutcome::Indeterminate(evicted));
        }
        if stored.state != SessionGrantOperationState::Committed {
            return Ok(SessionGrantReserveOutcome::Pending(stored));
        }
        Ok(SessionGrantReserveOutcome::Replay(stored))
    }

    #[tracing::instrument(
        name = "db.oauth_session_grant.checkpoint_authorization",
        skip_all,
        err
    )]
    async fn checkpoint_authorization(
        &mut self,
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
    ) -> Result<SessionGrantOperation, Self::Error> {
        let now = clock.now();
        if authorization.authorization_ref.trim().is_empty() {
            return Err(DatabaseError::invalid_operation());
        }
        self.conn
            .transaction(async |conn| {
                let operation = load_operation_for_update(conn, operation_id).await?;
                if now >= operation.retained_until {
                    return evict_operation(conn, operation_id).await;
                }
                match operation.state {
                    SessionGrantOperationState::Evicted => Err(DatabaseError::invalid_operation()),
                    SessionGrantOperationState::Authorized
                    | SessionGrantOperationState::Committed => {
                        if authorization_matches(&operation, authorization) {
                            Ok(operation)
                        } else {
                            Err(DatabaseError::invalid_operation())
                        }
                    }
                    SessionGrantOperationState::Reserved => {
                        if authorization.proof_expires_at <= now {
                            return Err(DatabaseError::invalid_operation());
                        }
                        let retained_until =
                            operation.retained_until.max(authorization.proof_expires_at);
                        diesel::update(
                            oauth_session_grant_operations::table.find(Uuid::from(operation_id)),
                        )
                        .set((
                            oauth_session_grant_operations::state.eq("authorized"),
                            oauth_session_grant_operations::proof_authorization_ref
                                .eq(Some(authorization.authorization_ref)),
                            oauth_session_grant_operations::proof_authorization_checkpoint
                                .eq(Some(authorization.checkpoint.clone())),
                            oauth_session_grant_operations::proof_expires_at
                                .eq(Some(authorization.proof_expires_at)),
                            oauth_session_grant_operations::retained_until.eq(retained_until),
                        ))
                        .execute(conn)
                        .await?;
                        load_operation_for_update(conn, operation_id).await
                    }
                }
            })
            .await
    }

    #[tracing::instrument(name = "db.oauth_session_grant.commit_issuance", skip_all, err)]
    async fn commit_issuance(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        outcome: SessionGrantExactOutcome<'_>,
        grant: NewSessionGrant<'_>,
    ) -> Result<SessionGrantCommitOutcome, Self::Error> {
        validate_exact_outcome(outcome)?;
        let now = clock.now();
        let id = new_id(now, rng);
        self.conn
            .transaction(async move |conn| {
                let operation = load_operation_for_update(conn, operation_id).await?;
                if operation.state == SessionGrantOperationState::Evicted
                    || now >= operation.retained_until
                {
                    return Ok(SessionGrantCommitOutcome::Indeterminate(operation));
                }
                if operation
                    .grant_expires_at
                    .is_some_and(|expires_at| now >= expires_at)
                {
                    let operation = evict_operation(conn, operation_id).await?;
                    return Ok(SessionGrantCommitOutcome::Indeterminate(operation));
                }
                if operation.operation.kind() != SessionGrantOperationKind::Issue {
                    return Err(DatabaseError::invalid_operation());
                }
                if operation.state == SessionGrantOperationState::Committed {
                    return Ok(SessionGrantCommitOutcome::Replay(operation));
                }
                validate_authorization(&operation, authorization, now)?;
                validate_grant_material(&operation, &grant)?;
                lock_session_grant_subject(conn, grant.issuer, grant.subject).await?;
                let retained_until = operation.retained_until.max(authorization.proof_expires_at);
                let grant_id = grant.grant_id.clone();
                let row = new_grant_row(id, operation_id, now, &grant);
                diesel::insert_into(oauth_session_grants::table)
                    .values(&row)
                    .execute(conn)
                    .await?;
                commit_operation_outcome(
                    conn,
                    operation_id,
                    authorization,
                    outcome,
                    None,
                    Some(&grant_id),
                    &[],
                    retained_until,
                    now,
                )
                .await?;
                Ok(SessionGrantCommitOutcome::Committed(owned_grant(
                    id,
                    operation_id,
                    now,
                    grant,
                )))
            })
            .await
    }

    async fn commit_refresh(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        outcome: SessionGrantExactOutcome<'_>,
        predecessor_grant_id: &SessionGrantId,
        successor: NewSessionGrant<'_>,
    ) -> Result<SessionGrantRefreshOutcome, Self::Error> {
        validate_exact_outcome(outcome)?;
        let now = clock.now();
        let successor_row_id = new_id(now, rng);
        self.conn
            .transaction(async move |conn| {
                let operation = load_operation_for_update(conn, operation_id).await?;
                if operation.state == SessionGrantOperationState::Evicted
                    || now >= operation.retained_until
                {
                    return Ok(SessionGrantRefreshOutcome::Indeterminate(operation));
                }
                if operation
                    .grant_expires_at
                    .is_some_and(|expires_at| now >= expires_at)
                {
                    let operation = evict_operation(conn, operation_id).await?;
                    return Ok(SessionGrantRefreshOutcome::Indeterminate(operation));
                }
                if operation.operation.kind() != SessionGrantOperationKind::Refresh
                    || operation.target_grant_id.as_ref() != Some(predecessor_grant_id)
                {
                    return Err(DatabaseError::invalid_operation());
                }
                validate_authorization(&operation, authorization, now)?;
                if operation.state == SessionGrantOperationState::Committed {
                    return Ok(SessionGrantRefreshOutcome::Replay(operation));
                }

                validate_grant_material(&operation, &successor)?;
                lock_session_grant_subject(conn, successor.issuer, successor.subject).await?;
                let predecessor = load_grant_by_protocol_id_for_update(conn, predecessor_grant_id)
                    .await?
                    .ok_or_else(DatabaseError::invalid_operation)?;
                if predecessor.issuer != successor.issuer
                    || predecessor.subject != successor.subject
                    || predecessor.session_id != successor.session_id
                {
                    return Err(DatabaseError::invalid_operation());
                }
                validate_refresh_chain(&predecessor, &successor)?;
                if predecessor.lifecycle_state != SessionGrantLifecycleState::Active
                    || predecessor.expires_at <= now
                {
                    return Ok(SessionGrantRefreshOutcome::PredecessorTerminal(predecessor));
                }
                let successor_grant_id = successor.grant_id.clone();
                diesel::insert_into(oauth_session_grants::table)
                    .values(new_grant_row(
                        successor_row_id,
                        operation_id,
                        now,
                        &successor,
                    ))
                    .execute(conn)
                    .await?;
                let changed = diesel::update(
                    oauth_session_grants::table
                        .find(Uuid::from(predecessor.id))
                        .filter(oauth_session_grants::lifecycle_state.eq("active")),
                )
                .set((
                    oauth_session_grants::lifecycle_state.eq("superseded"),
                    oauth_session_grants::superseded_at.eq(Some(now)),
                    oauth_session_grants::successor_grant_id
                        .eq(Some(successor_grant_id.token_bytes().to_vec())),
                ))
                .execute(conn)
                .await?;
                DatabaseError::ensure_affected_rows_usize(changed, 1)?;

                let retained_until = operation.retained_until.max(authorization.proof_expires_at);
                commit_operation_outcome(
                    conn,
                    operation_id,
                    authorization,
                    outcome,
                    Some(predecessor_grant_id),
                    Some(&successor_grant_id),
                    &[],
                    retained_until,
                    now,
                )
                .await?;
                let predecessor = load_grant_by_protocol_id(conn, predecessor_grant_id)
                    .await?
                    .ok_or_else(DatabaseError::invalid_operation)?;
                Ok(SessionGrantRefreshOutcome::Committed {
                    predecessor,
                    successor: owned_grant(successor_row_id, operation_id, now, successor),
                })
            })
            .await
    }

    async fn commit_revoke(
        &mut self,
        clock: &dyn Clock,
        operation_id: Ulid,
        authorization: SessionGrantProofAuthorization<'_>,
        selector: SessionGrantRevokeSelector<'_>,
    ) -> Result<SessionGrantRevokeOutcome, Self::Error> {
        let now = clock.now();
        self.conn
            .transaction(async move |conn| {
                let operation = load_operation_for_update(conn, operation_id).await?;
                if operation.state == SessionGrantOperationState::Evicted
                    || now >= operation.retained_until
                {
                    return Ok(SessionGrantRevokeOutcome::Indeterminate(operation));
                }
                if operation.operation.kind() != SessionGrantOperationKind::Revoke {
                    return Err(DatabaseError::invalid_operation());
                }
                validate_authorization(&operation, authorization, now)?;
                if operation.state == SessionGrantOperationState::Committed {
                    return Ok(SessionGrantRevokeOutcome::Replay(operation));
                }

                let (subject, expected_selector) = match selector {
                    SessionGrantRevokeSelector::Grant(grant_id) => {
                        let grant = load_grant_by_protocol_id(conn, grant_id)
                            .await?
                            .ok_or_else(DatabaseError::invalid_operation)?;
                        if grant.issuer != operation.issuer {
                            return Err(DatabaseError::invalid_operation());
                        }
                        (
                            grant.subject,
                            SessionGrantRevokeTarget::Grant {
                                grant_id: grant_id.clone(),
                            },
                        )
                    }
                    SessionGrantRevokeSelector::Device { subject, device_id } => (
                        subject.to_owned(),
                        SessionGrantRevokeTarget::Device {
                            subject: subject.to_owned(),
                            device_id: device_id.to_owned(),
                        },
                    ),
                    SessionGrantRevokeSelector::AllForSubject { subject } => (
                        subject.to_owned(),
                        SessionGrantRevokeTarget::AllForSubject {
                            subject: subject.to_owned(),
                        },
                    ),
                };
                if operation.operation
                    != (SessionGrantOperationDescriptor::Revoke {
                        selector: expected_selector,
                    })
                {
                    return Err(DatabaseError::invalid_operation());
                }
                lock_session_grant_subject(conn, &operation.issuer, &subject).await?;

                let mut query = oauth_session_grants::table
                    .filter(oauth_session_grants::issuer.eq(&operation.issuer))
                    .filter(oauth_session_grants::subject.eq(&subject))
                    .into_boxed();
                match selector {
                    SessionGrantRevokeSelector::Grant(grant_id) => {
                        query = query.filter(
                            oauth_session_grants::grant_id.eq(grant_id.token_bytes().to_vec()),
                        );
                    }
                    SessionGrantRevokeSelector::Device { device_id, .. } => {
                        query = query.filter(oauth_session_grants::device_id.eq(Some(device_id)));
                    }
                    SessionGrantRevokeSelector::AllForSubject { .. } => {}
                }
                let candidates = query
                    .order(oauth_session_grants::grant_id.asc())
                    .select(SessionGrantLookup::as_select())
                    .load::<SessionGrantLookup>(conn)
                    .await?
                    .into_iter()
                    .map(SessionGrant::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut matched = Vec::with_capacity(candidates.len());
                for candidate in candidates {
                    matched.push(
                        load_grant_by_protocol_id_for_update(conn, &candidate.grant_id)
                            .await?
                            .ok_or_else(DatabaseError::invalid_operation)?,
                    );
                }
                let active_ids = matched
                    .iter()
                    .filter(|grant| {
                        grant.lifecycle_state == SessionGrantLifecycleState::Active
                            && grant.expires_at > now
                    })
                    .map(|grant| grant.grant_id.clone())
                    .collect::<Vec<_>>();
                if !active_ids.is_empty() {
                    let active_bytes = active_ids
                        .iter()
                        .map(|id| id.token_bytes().to_vec())
                        .collect::<Vec<_>>();
                    let changed = diesel::update(
                        oauth_session_grants::table
                            .filter(oauth_session_grants::grant_id.eq_any(active_bytes))
                            .filter(oauth_session_grants::lifecycle_state.eq("active")),
                    )
                    .set((
                        oauth_session_grants::lifecycle_state.eq("revoked"),
                        oauth_session_grants::revoked_at.eq(Some(now)),
                    ))
                    .execute(conn)
                    .await?;
                    DatabaseError::ensure_affected_rows_usize(changed, active_ids.len())?;
                }
                let retained_until = operation.retained_until.max(authorization.proof_expires_at);
                let wire_outcome = WireSessionRevokeOutcome {
                    revoked_count: u64::try_from(active_ids.len())
                        .map_err(|_| DatabaseError::invalid_operation())?,
                    revoked_grant_ids: active_ids.clone(),
                };
                let canonical_response = arkret_canonical::canonical_json_bytes(&wire_outcome)
                    .map_err(|_| DatabaseError::invalid_operation())?;
                let response_digest = arkret_canonical::sha256_bytes(&canonical_response);
                let target = match selector {
                    SessionGrantRevokeSelector::Grant(grant_id) => Some(grant_id),
                    _ => None,
                };
                commit_operation_outcome(
                    conn,
                    operation_id,
                    authorization,
                    SessionGrantExactOutcome {
                        canonical_response: &canonical_response,
                        response_digest,
                    },
                    target,
                    None,
                    &active_ids,
                    retained_until,
                    now,
                )
                .await?;
                let committed_operation = load_operation_for_update(conn, operation_id).await?;
                if active_ids.is_empty() {
                    return Ok(SessionGrantRevokeOutcome::AlreadyTerminal {
                        grants: matched,
                        operation: committed_operation,
                    });
                }
                let mut grants = Vec::with_capacity(active_ids.len());
                for grant_id in &active_ids {
                    grants.push(
                        load_grant_by_protocol_id(conn, grant_id)
                            .await?
                            .ok_or_else(DatabaseError::invalid_operation)?,
                    );
                }
                Ok(SessionGrantRevokeOutcome::Revoked {
                    grants,
                    revoked_at: now,
                    operation: committed_operation,
                })
            })
            .await
    }

    #[tracing::instrument(name = "db.oauth_session_grant.lookup", skip_all, err)]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<SessionGrant>, Self::Error> {
        let row = oauth_session_grants::table
            .find(Uuid::from(id))
            .select(SessionGrantLookup::as_select())
            .first::<SessionGrantLookup>(self.conn)
            .await
            .optional()?;

        row.map(SessionGrant::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.lookup_by_grant_id", skip_all, err)]
    async fn lookup_by_grant_id(
        &mut self,
        grant_id: &SessionGrantId,
    ) -> Result<Option<SessionGrant>, Self::Error> {
        let row = oauth_session_grants::table
            .filter(oauth_session_grants::grant_id.eq(grant_id.token_bytes().to_vec()))
            .select(SessionGrantLookup::as_select())
            .first::<SessionGrantLookup>(self.conn)
            .await
            .optional()?;

        row.map(SessionGrant::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.lookup_by_grant_jwt", skip_all, err)]
    async fn lookup_by_grant_jwt(
        &mut self,
        grant_jwt: &str,
    ) -> Result<Option<SessionGrant>, Self::Error> {
        let row = oauth_session_grants::table
            .filter(oauth_session_grants::grant_jwt.eq(grant_jwt))
            .select(SessionGrantLookup::as_select())
            .first::<SessionGrantLookup>(self.conn)
            .await
            .optional()?;

        row.map(SessionGrant::try_from)
            .transpose()
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.list", skip_all, err)]
    async fn list(
        &mut self,
        filter: SessionGrantFilter<'_>,
        pagination: Pagination,
    ) -> Result<Page<SessionGrant>, Self::Error> {
        let mut query = apply_session_grant_filter!(
            oauth_session_grants::table
                .select(SessionGrantLookup::as_select())
                .into_boxed(),
            filter
        );

        if let Some(after) = pagination.after {
            query = query.filter(oauth_session_grants::id.gt(Uuid::from(after)));
        }
        if let Some(before) = pagination.before {
            query = query.filter(oauth_session_grants::id.lt(Uuid::from(before)));
        }

        match pagination.direction {
            PaginationDirection::Forward => {
                query = query
                    .order(oauth_session_grants::id.asc())
                    .limit((pagination.count + 1) as i64);
            }
            PaginationDirection::Backward => {
                query = query
                    .order(oauth_session_grants::id.desc())
                    .limit((pagination.count + 1) as i64);
            }
        }

        let edges = query.load::<SessionGrantLookup>(self.conn).await?;
        pagination
            .process(edges)
            .try_map(SessionGrant::try_from)
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.revoke", skip_all, err)]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        grant: SessionGrant,
    ) -> Result<SessionGrant, Self::Error> {
        let revoked_at = clock.now();
        let rows_affected = diesel::update(
            oauth_session_grants::table
                .find(Uuid::from(grant.id))
                .filter(oauth_session_grants::lifecycle_state.eq("active")),
        )
        .set((
            oauth_session_grants::lifecycle_state.eq("revoked"),
            oauth_session_grants::revoked_at.eq(Some(revoked_at)),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        grant
            .revoke(revoked_at)
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(name = "db.oauth_session_grant.revoke_if_active", skip_all, err)]
    async fn revoke_if_active(&mut self, clock: &dyn Clock, id: Ulid) -> Result<bool, Self::Error> {
        let revoked_at = clock.now();
        // Conditional consume: the `revoked_at IS NULL` predicate makes this a
        // compare-and-swap. Under READ COMMITTED the UPDATE takes a row lock,
        // so a concurrent rotation of the same parent blocks here and then
        // re-evaluates the predicate against the committed row — seeing
        // `revoked_at` already set and matching 0 rows. Exactly one winner.
        let rows_affected = diesel::update(
            oauth_session_grants::table
                .filter(oauth_session_grants::id.eq(Uuid::from(id)))
                .filter(oauth_session_grants::lifecycle_state.eq("active")),
        )
        .set((
            oauth_session_grants::lifecycle_state.eq("revoked"),
            oauth_session_grants::revoked_at.eq(Some(revoked_at)),
        ))
        .execute(self.conn)
        .await?;

        Ok(rows_affected == 1)
    }

    #[tracing::instrument(
        name = "db.oauth_session_grant.cleanup_expired",
        skip_all,
        fields(
            since = since.map(tracing::field::display),
            until = %until,
            limit = limit,
        ),
        err,
    )]
    async fn cleanup_expired(
        &mut self,
        since: Option<DateTime<Utc>>,
        until: DateTime<Utc>,
        limit: usize,
    ) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
        let res: SessionGrantCleanupResult = diesel::sql_query(
            r"
                WITH to_delete AS (
                    SELECT id, expires_at
                    FROM oauth_session_grants
                    WHERE ($1::timestamptz IS NULL OR expires_at >= $1)
                      AND expires_at < $2
                      AND NOT EXISTS (
                          SELECT 1
                          FROM oauth_session_grant_operations AS replay
                          WHERE replay.retained_until >= $2
                            AND replay.state <> 'evicted'
                            AND (
                                replay.target_grant_id = oauth_session_grants.grant_id
                                OR replay.result_grant_id = oauth_session_grants.grant_id
                              OR oauth_session_grants.grant_id = ANY(replay.affected_grant_ids)
                            )
                      )
                    ORDER BY expires_at ASC
                    LIMIT $3
                    FOR UPDATE
                ),
                deleted AS (
                    DELETE FROM oauth_session_grants USING to_delete
                    WHERE oauth_session_grants.id = to_delete.id
                    RETURNING oauth_session_grants.expires_at
                )
                SELECT COUNT(*) as count, MAX(expires_at) as last_ts FROM deleted
            ",
        )
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>, _>(since)
        .bind::<diesel::sql_types::Timestamptz, _>(until)
        .bind::<diesel::sql_types::BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .get_result(self.conn)
        .await?;

        Ok((res.count.try_into().unwrap_or(usize::MAX), res.last_ts))
    }
}

#[derive(Debug, diesel::QueryableByName)]
struct SessionGrantCleanupResult {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_ts: Option<DateTime<Utc>>,
}
