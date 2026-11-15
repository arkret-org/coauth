use arkret_identifiers::{DidCoreId, SessionGrantId, SessionGrantSecret};
use arkret_models_collaboration::account_lifecycle::SessionRevokeResponseBody as WireSessionRevokeOutcome;
use arkret_models_identity::{
    SessionGrantCredentialClass, SessionGrantMetadata, SessionGrantProofKind,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::oauth::{
    MIN_SESSION_GRANT_OPERATION_RETENTION_SECONDS, NewSessionGrant, NewSessionGrantOperation,
    SessionGrantCommitOutcome, SessionGrantExactOutcome, SessionGrantFilter,
    SessionGrantLifecycleState, SessionGrantOperation, SessionGrantOperationDescriptor,
    SessionGrantOperationKind, SessionGrantOperationState, SessionGrantProofAuthorization,
    SessionGrantRefreshCommit, SessionGrantRefreshOutcome, SessionGrantRepository,
    SessionGrantReserveOutcome, SessionGrantRevokeOutcome, SessionGrantRevokeSelector,
    SessionGrantRevokeTarget,
};
use coauth_data::pagination::Node;
use coauth_data::{Clock, LocalAccountId, Page, Pagination, SessionGrant, new_id};
use coauth_oauth_types::scope::{Scope, ScopeToken};
use diesel::prelude::*;
use horme::{OptionalExtension, RunQueryDsl};
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{oauth_session_grant_operations, oauth_session_grants, user_sessions};
use crate::session_grant_codec::session_grant_id_from_uuid;
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`SessionGrantRepository`].
pub struct PgOAuthSessionGrantRepository<'c, P = diesel_async::AsyncPgConnection> {
    conn: &'c mut P,
}

impl<'c, P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    PgOAuthSessionGrantRepository<'c, P>
{
    /// Create a repository backed by the provided PostgreSQL connection.
    pub fn new(conn: &'c mut P) -> Self {
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

#[derive(Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_session_grant_operations)]
struct SessionGrantOperationRow {
    id: Uuid,
    issuer_id: DidCoreId,
    operation_kind: String,
    proof_kind: Option<String>,
    request_identity: String,
    canonical_intent_digest: Vec<u8>,
    canonical_intent: Option<Vec<u8>>,
    operation_selector: Option<Value>,
    reserved_grant_id: Option<Uuid>,
    reserved_credential_digest: Option<Vec<u8>>,
    reserved_session_grant: Option<String>,
    session_id: Option<String>,
    grant_not_before: Option<DateTime<Utc>>,
    grant_expires_at: Option<DateTime<Utc>>,
    state: String,
    proof_authorization_ref: Option<String>,
    proof_authorization_checkpoint: Option<Value>,
    proof_expires_at: Option<DateTime<Utc>>,
    outcome_digest: Option<Vec<u8>>,
    canonical_outcome: Option<Vec<u8>>,
    target_session_grant_id: Option<Uuid>,
    result_grant_id: Option<Uuid>,
    affected_grant_ids: Vec<Option<Uuid>>,
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
        let target_session_grant_id = value
            .target_session_grant_id
            .map(session_grant_id_from_uuid)
            .transpose()
            .map_err(|error| inconsistent("target_session_grant_id", Box::new(error)))?;
        let result_grant_id = value
            .result_grant_id
            .map(session_grant_id_from_uuid)
            .transpose()
            .map_err(|error| inconsistent("result_grant_id", Box::new(error)))?;
        let affected_grant_ids = value
            .affected_grant_ids
            .iter()
            .map(|stored| {
                stored.as_ref().copied().ok_or_else(|| {
                    arkret_identifiers::IdentifierError::InvalidId(
                        "affected grant id must not be NULL".to_owned(),
                    )
                })
            })
            .map(|stored| stored.and_then(session_grant_id_from_uuid))
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

        let reserved_credential_digest = value
            .reserved_credential_digest
            .as_deref()
            .map(|digest| fixed_digest(digest, "reserved_credential_digest"))
            .transpose()
            .map_err(|error| inconsistent("reserved_credential_digest", Box::new(error)))?;
        if let Some(secret) = &value.reserved_session_grant
            && reserved_credential_digest != Some(arkret_canonical::sha256_bytes(secret.as_bytes()))
        {
            return Err(inconsistent(
                "reserved_credential_digest",
                Box::new(std::io::Error::other(
                    "reserved credential does not match its immutable allocation fence",
                )),
            ));
        }
        Ok(Self {
            id,
            issuer_id: value.issuer_id,
            operation,
            proof_kind,
            request_identity: value.request_identity,
            canonical_intent_digest,
            canonical_intent: value.canonical_intent,
            reserved_grant_id: value
                .reserved_grant_id
                .map(session_grant_id_from_uuid)
                .transpose()
                .map_err(|error| inconsistent("reserved_grant_id", Box::new(error)))?,
            reserved_credential_digest,
            reserved_session_grant: value
                .reserved_session_grant
                .map(SessionGrantSecret::new)
                .transpose()
                .map_err(|error| inconsistent("reserved_session_grant", Box::new(error)))?,
            session_id: value.session_id,
            grant_not_before: value.grant_not_before,
            grant_expires_at: value.grant_expires_at,
            state,
            proof_authorization_ref: value.proof_authorization_ref,
            proof_authorization_checkpoint: value.proof_authorization_checkpoint,
            proof_expires_at: value.proof_expires_at,
            outcome_digest,
            canonical_outcome: value.canonical_outcome,
            target_session_grant_id,
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
    issuer_id: &'a DidCoreId,
    operation_kind: &'a str,
    proof_kind: Option<&'a str>,
    request_identity: &'a str,
    canonical_intent_digest: Vec<u8>,
    canonical_intent: Option<&'a [u8]>,
    operation_selector: Option<Value>,
    reserved_grant_id: Option<Uuid>,
    reserved_credential_digest: Option<Vec<u8>>,
    reserved_session_grant: Option<String>,
    session_id: Option<String>,
    grant_not_before: Option<DateTime<Utc>>,
    grant_expires_at: Option<DateTime<Utc>>,
    state: &'static str,
    target_session_grant_id: Option<Uuid>,
    retained_until: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Queryable, Selectable)]
#[diesel(table_name = oauth_session_grants)]
struct SessionGrantLookup {
    id: Uuid,
    grant_id: Uuid,
    issuance_operation_id: Uuid,
    user_session_id: Option<Uuid>,
    issuer_id: DidCoreId,
    subject_id: DidCoreId,
    local_account_id: String,
    device_id: Option<String>,
    audience_id: DidCoreId,
    scope_list: Vec<String>,
    session_grant: String,
    credential_digest: Vec<u8>,
    canonical_metadata: Vec<u8>,
    session_id: String,
    session_public_key: String,
    credential_class: String,
    expires_at: DateTime<Utc>,
    lifecycle_state: String,
    revoked_at: Option<DateTime<Utc>>,
    superseded_at: Option<DateTime<Utc>>,
    successor_grant_id: Option<Uuid>,
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
        let grant_id = session_grant_id_from_uuid(value.grant_id).map_err(|error| {
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
        let metadata: SessionGrantMetadata = serde_json::from_slice(&value.canonical_metadata)
            .map_err(|error| {
                DatabaseInconsistencyError::on("oauth_session_grants")
                    .column("canonical_metadata")
                    .row(id)
                    .source(error)
            })?;
        let session_grant =
            SessionGrantSecret::new(value.session_grant.clone()).map_err(|error| {
                DatabaseInconsistencyError::on("oauth_session_grants")
                    .column("session_grant")
                    .row(id)
                    .source(error)
            })?;
        if arkret_canonical::sha256_bytes(session_grant.as_str().as_bytes()).as_slice()
            != value.credential_digest.as_slice()
            || arkret_canonical::canonical_json_bytes(&metadata).map_err(|error| {
                DatabaseInconsistencyError::on("oauth_session_grants")
                    .column("canonical_metadata")
                    .row(id)
                    .source(error)
            })? != value.canonical_metadata
        {
            return Err(DatabaseInconsistencyError::on("oauth_session_grants")
                .column("canonical_metadata")
                .row(id)
                .source(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid exact credential digest or canonical metadata",
                )));
        }
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
            .map(session_grant_id_from_uuid)
            .transpose()
            .map_err(|error| {
                DatabaseInconsistencyError::on("oauth_session_grants")
                    .column("successor_grant_id")
                    .row(id)
                    .source(error)
            })?;

        let grant = Self {
            id,
            grant_id,
            browser_session_id: value.user_session_id.map(Into::into),
            issuer_id: value.issuer_id,
            subject_id: value.subject_id,
            local_account_id: LocalAccountId::new(value.local_account_id).map_err(|error| {
                DatabaseInconsistencyError::on("oauth_session_grants")
                    .column("local_account_id")
                    .row(id)
                    .source(error)
            })?,
            device_id: value.device_id,
            audience_id: value.audience_id,
            scope,
            session_grant,
            metadata,
            session_id: value.session_id,
            session_public_key: value.session_public_key,
            credential_class: value.credential_class,
            created_at: value.created_at,
            expires_at: value.expires_at,
            lifecycle_state,
            revoked_at: value.revoked_at,
            superseded_at: value.superseded_at,
            successor_grant_id,
            issuance_operation_id: value.issuance_operation_id.into(),
        };
        validate_grant_projection(&NewSessionGrant {
            grant_id: grant.grant_id.clone(),
            browser_session_id: grant.browser_session_id,
            issuer_id: &grant.issuer_id,
            subject_id: &grant.subject_id,
            local_account_id: &grant.local_account_id,
            device_id: grant.device_id.as_deref(),
            audience_id: &grant.audience_id,
            scope: grant.scope.clone(),
            session_grant: &grant.session_grant,
            metadata: &grant.metadata,
            session_id: &grant.session_id,
            session_public_key: &grant.session_public_key,
            credential_class: &grant.credential_class,
            not_before: grant.metadata.not_before,
            expires_at: grant.expires_at,
        })
        .map_err(|error| {
            DatabaseInconsistencyError::on("oauth_session_grants")
                .column("canonical_metadata")
                .row(id)
                .source(error)
        })?;
        Ok(grant)
    }
}

#[derive(Insertable)]
#[diesel(table_name = oauth_session_grants)]
struct NewSessionGrantRow<'a> {
    id: Uuid,
    grant_id: Uuid,
    issuance_operation_id: Uuid,
    user_session_id: Option<Uuid>,
    issuer_id: &'a DidCoreId,
    subject_id: &'a DidCoreId,
    local_account_id: &'a str,
    device_id: Option<&'a str>,
    audience_id: &'a DidCoreId,
    scope_list: Vec<String>,
    session_grant: &'a str,
    credential_digest: Vec<u8>,
    canonical_metadata: Vec<u8>,
    session_id: &'a str,
    session_public_key: &'a str,
    credential_class: &'a str,
    expires_at: DateTime<Utc>,
    lifecycle_state: &'static str,
    created_at: DateTime<Utc>,
}

fn validate_grant_projection(grant: &NewSessionGrant<'_>) -> Result<(), DatabaseError> {
    let metadata = grant.metadata;
    metadata
        .validate()
        .map_err(|_| DatabaseError::invalid_operation())?;
    let scopes = grant
        .scope
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect::<Vec<_>>();
    let class = match metadata.credential_class {
        SessionGrantCredentialClass::Standard => "standard",
        SessionGrantCredentialClass::RecoverySession => "recovery_session",
    };
    let constraints = [
        ("record_id", metadata.id == grant.grant_id),
        ("issuer", metadata.issuer_id == *grant.issuer_id),
        (
            "principal",
            metadata.account_id.principal_id == *grant.subject_id,
        ),
        (
            "station",
            metadata.account_id.station_id == *grant.audience_id,
        ),
        ("audience", metadata.audience_id == *grant.audience_id),
        (
            "device",
            metadata.device_id.as_ref().map(|id| id.as_str()) == grant.device_id,
        ),
        (
            "session_key",
            metadata.session_public_key.as_str() == grant.session_public_key,
        ),
        ("scopes", metadata.scopes == scopes),
        ("not_before", metadata.not_before == grant.not_before),
        ("expires_at", metadata.expires_at == grant.expires_at),
        ("session_id", metadata.session_id == grant.session_id),
        ("class", class == grant.credential_class),
    ];
    if let Some((constraint, _)) = constraints.iter().find(|(_, valid)| !valid) {
        tracing::error!(
            constraint,
            "session grant metadata projection constraint failed"
        );
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

fn validate_grant_material(
    operation: &SessionGrantOperation,
    grant: &NewSessionGrant<'_>,
) -> Result<(), DatabaseError> {
    validate_grant_projection(grant)?;
    if operation.reserved_grant_id.as_ref() != Some(&grant.grant_id)
        || operation.reserved_credential_digest
            != Some(arkret_canonical::sha256_bytes(
                grant.session_grant.as_str().as_bytes(),
            ))
        || operation.reserved_session_grant.as_ref() != Some(grant.session_grant)
        || operation.issuer_id != *grant.issuer_id
        || operation.session_id.as_deref() != Some(grant.session_id)
        || operation.grant_not_before != Some(grant.not_before)
        || operation.grant_expires_at != Some(grant.expires_at)
        || (operation.operation.kind() == SessionGrantOperationKind::Issue
            && operation.proof_kind != grant.metadata.proof_kind)
        || (operation.operation.kind() != SessionGrantOperationKind::Issue
            && operation.proof_kind.is_some())
    {
        return Err(DatabaseError::invalid_operation());
    }
    Ok(())
}

fn validate_refresh_chain(
    predecessor: &SessionGrant,
    successor: &NewSessionGrant<'_>,
) -> Result<(), DatabaseError> {
    let old = &predecessor.metadata;
    let new = successor.metadata;
    if old.issuer_id != new.issuer_id
        || old.account_id != new.account_id
        || old.audience_id != new.audience_id
        || old.session_id != new.session_id
        || old.session_public_key != new.session_public_key
        || old.cnf_jkt != new.cnf_jkt
        || old.credential_class != SessionGrantCredentialClass::Standard
        || new.credential_class != SessionGrantCredentialClass::Standard
        || old.holder_binding != new.holder_binding
        || old.device_binding != new.device_binding
        || old.id == new.id
        || predecessor.session_grant == *successor.session_grant
        || new.scopes != old.scopes
    {
        return Err(DatabaseError::invalid_operation());
    }
    match (&old.scope_details, &new.scope_details) {
        (None, None) => {}
        (Some(old), Some(new)) => {
            if old.controller_principal_id != new.controller_principal_id
                || old.agent_key_authorization_ref != new.agent_key_authorization_ref
                || new.realm_ids != old.realm_ids
                || new.strand_ids != old.strand_ids
                || new.resources != old.resources
                || new.constraints != old.constraints
                || new.capability_grant_refs != old.capability_grant_refs
                || new.policy_refs != old.policy_refs
            {
                return Err(DatabaseError::invalid_operation());
            }
            // Participation is a current observational overlay, not part of
            // the frozen action/resource/constraint ceiling. Its refresh may
            // change while the actual use-time selection gate remains in force.
        }
        _ => return Err(DatabaseError::invalid_operation()),
    }
    Ok(())
}

fn new_grant_row<'a>(
    id: Ulid,
    operation_id: Ulid,
    created_at: DateTime<Utc>,
    grant: &'a NewSessionGrant<'a>,
) -> Result<NewSessionGrantRow<'a>, DatabaseError> {
    Ok(NewSessionGrantRow {
        id: Uuid::from(id),
        grant_id: grant.grant_id.uuid(),
        issuance_operation_id: Uuid::from(operation_id),
        user_session_id: grant.browser_session_id.map(Uuid::from),
        issuer_id: grant.issuer_id,
        subject_id: grant.subject_id,
        local_account_id: grant.local_account_id.as_str(),
        device_id: grant.device_id,
        audience_id: grant.audience_id,
        scope_list: grant
            .scope
            .iter()
            .map(|token| token.as_str().to_owned())
            .collect(),
        session_grant: grant.session_grant.as_str(),
        credential_digest: arkret_canonical::sha256_bytes(grant.session_grant.as_str().as_bytes())
            .to_vec(),
        canonical_metadata: arkret_canonical::canonical_json_bytes(grant.metadata)?,
        session_id: grant.session_id,
        session_public_key: grant.session_public_key,
        credential_class: grant.credential_class,
        expires_at: grant.expires_at,
        lifecycle_state: "active",
        created_at,
    })
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
        issuer_id: grant.issuer_id.clone(),
        subject_id: grant.subject_id.clone(),
        local_account_id: grant.local_account_id.clone(),
        device_id: grant.device_id.map(ToOwned::to_owned),
        audience_id: grant.audience_id.clone(),
        scope: grant.scope,
        session_grant: grant.session_grant.clone(),
        metadata: grant.metadata.clone(),
        session_id: grant.session_id.to_owned(),
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
    conn: &mut impl horme::GetConnection<Connection = diesel_async::AsyncPgConnection>,
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
    conn: &mut impl horme::GetConnection<Connection = diesel_async::AsyncPgConnection>,
    issuer_id: &DidCoreId,
    grant_id: &SessionGrantId,
) -> Result<Option<SessionGrant>, DatabaseError> {
    oauth_session_grants::table
        .filter(oauth_session_grants::issuer_id.eq(issuer_id))
        .filter(oauth_session_grants::grant_id.eq(grant_id.uuid()))
        .select(SessionGrantLookup::as_select())
        .first::<SessionGrantLookup>(conn)
        .await
        .optional()?
        .map(SessionGrant::try_from)
        .transpose()
        .map_err(Into::into)
}

async fn load_grant_by_protocol_id_for_update(
    conn: &mut impl horme::GetConnection<Connection = diesel_async::AsyncPgConnection>,
    issuer_id: &DidCoreId,
    grant_id: &SessionGrantId,
) -> Result<Option<SessionGrant>, DatabaseError> {
    oauth_session_grants::table
        .filter(oauth_session_grants::issuer_id.eq(issuer_id))
        .filter(oauth_session_grants::grant_id.eq(grant_id.uuid()))
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
            issuer_id: DidCoreId::new("ak:did_core:web:issuer_id.example".to_owned()).unwrap(),
            operation: SessionGrantOperationDescriptor::Issue,
            proof_kind: None,
            request_identity: "oidc-code-hash".to_owned(),
            canonical_intent_digest: [7; 32],
            canonical_intent: Some(br#"{"kind":"oidc"}"#.to_vec()),
            reserved_grant_id: Some(SessionGrantId::new_v7_at(1_794_657_600_000)),
            reserved_credential_digest: Some(arkret_canonical::sha256_bytes(
                SessionGrantSecret::from_bytes([42; 32]).as_str().as_bytes(),
            )),
            reserved_session_grant: Some(SessionGrantSecret::from_bytes([42; 32])),
            session_id: Some("session-1".to_owned()),
            grant_not_before: Some(now - chrono::Duration::try_minutes(10).unwrap()),
            grant_expires_at: Some(now + chrono::Duration::try_minutes(50).unwrap()),
            proof_authorization_ref: Some(authorization.authorization_ref.to_owned()),
            proof_authorization_checkpoint: Some(authorization.checkpoint.clone()),
            proof_expires_at: Some(authorization.proof_expires_at),
            outcome_digest: None,
            canonical_outcome: None,
            state,
            target_session_grant_id: None,
            result_grant_id: None,
            affected_grant_ids: Vec::new(),
            retained_until: now + chrono::Duration::try_days(7).unwrap(),
            created_at: now - chrono::Duration::try_minutes(10).unwrap(),
            committed_at: None,
        }
    }

    #[test]
    fn authorized_exact_checkpoint_can_finish_after_proof_expiry() {
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixture timestamp")
            .with_timezone(&Utc);
        let checkpoint = serde_json::json!({"kind":"oidc","subject_id":"did:web:alice.example"});
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
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixture timestamp")
            .with_timezone(&Utc);
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
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixture timestamp")
            .with_timezone(&Utc);
        let stored = serde_json::json!({"kind":"oidc","subject_id":"did:web:alice.example"});
        let changed = serde_json::json!({"kind":"oidc","subject_id":"did:web:bob.example"});
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
    conn: &mut impl horme::GetConnection<Connection = diesel_async::AsyncPgConnection>,
    operation_id: Ulid,
) -> Result<SessionGrantOperation, DatabaseError> {
    diesel::update(oauth_session_grant_operations::table.find(Uuid::from(operation_id)))
        .set((
            oauth_session_grant_operations::state.eq("evicted"),
            oauth_session_grant_operations::canonical_intent.eq(None::<Vec<u8>>),
            oauth_session_grant_operations::reserved_session_grant.eq(None::<String>),
            oauth_session_grant_operations::session_id.eq(None::<String>),
            oauth_session_grant_operations::grant_not_before.eq(None::<DateTime<Utc>>),
            oauth_session_grant_operations::grant_expires_at.eq(None::<DateTime<Utc>>),
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
    conn: &mut impl horme::GetConnection<Connection = diesel_async::AsyncPgConnection>,
    issuer_id: &DidCoreId,
    subject_id: &DidCoreId,
) -> Result<(), DatabaseError> {
    let key = crate::advisory_lock::advisory_lock_key(&format!(
        "coauth:session-grant-ledger:{issuer_id}:{subject_id}"
    ));
    diesel::sql_query("SELECT pg_advisory_xact_lock($1), true AS acquired")
        .bind::<diesel::sql_types::BigInt, _>(key)
        .get_result::<crate::advisory_lock::AdvisoryLockResult>(conn)
        .await?;
    Ok(())
}

struct CommitOperationOutcome<'a> {
    operation_id: Ulid,
    authorization: SessionGrantProofAuthorization<'a>,
    outcome: SessionGrantExactOutcome<'a>,
    target_session_grant_id: Option<&'a SessionGrantId>,
    result_grant_id: Option<&'a SessionGrantId>,
    affected_grant_ids: &'a [SessionGrantId],
    retained_until: DateTime<Utc>,
    committed_at: DateTime<Utc>,
}

async fn commit_operation_outcome(
    conn: &mut impl horme::GetConnection<Connection = diesel_async::AsyncPgConnection>,
    commit: CommitOperationOutcome<'_>,
) -> Result<(), DatabaseError> {
    let CommitOperationOutcome {
        operation_id,
        authorization,
        outcome,
        target_session_grant_id,
        result_grant_id,
        affected_grant_ids,
        retained_until,
        committed_at,
    } = commit;
    let affected_grant_ids = affected_grant_ids
        .iter()
        .map(|id| Some(id.uuid()))
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
        oauth_session_grant_operations::target_session_grant_id
            .eq(target_session_grant_id.map(|id| id.uuid())),
        oauth_session_grant_operations::result_grant_id.eq(result_grant_id.map(|id| id.uuid())),
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

        if let Some(subject_id) = $filter.subject_id() {
            q = q.filter(oauth_session_grants::subject_id.eq(subject_id));
        }

        if let Some(device_id) = $filter.device_id() {
            q = q.filter(oauth_session_grants::device_id.eq(device_id));
        }

        if let Some(audience_id) = $filter.audience_id() {
            q = q.filter(oauth_session_grants::audience_id.eq(audience_id));
        }

        if let Some(active_at) = $filter.active_at_value() {
            q = q
                .filter(oauth_session_grants::lifecycle_state.eq("active"))
                .filter(oauth_session_grants::expires_at.gt(active_at));
        }

        q
    }};
}

const MAX_SESSION_GRANT_ALLOCATION_ATTEMPTS: usize = 32;

async fn existing_reservation_outcome(
    conn: &mut impl horme::GetConnection<Connection = diesel_async::AsyncPgConnection>,
    requested: &NewSessionGrantOperation<'_>,
    now: DateTime<Utc>,
    stored: SessionGrantOperation,
) -> Result<SessionGrantReserveOutcome, DatabaseError> {
    if stored.canonical_intent_digest != requested.canonical_intent_digest
        || stored.operation != requested.operation
        || stored.target_session_grant_id.as_ref() != requested.target_session_grant_id
        || (stored.state != SessionGrantOperationState::Evicted
            && stored.canonical_intent.as_deref() != Some(requested.canonical_intent))
    {
        return Ok(SessionGrantReserveOutcome::Conflict(stored));
    }
    if stored.state == SessionGrantOperationState::Evicted {
        return Ok(SessionGrantReserveOutcome::Indeterminate(stored));
    }
    if now >= stored.retained_until {
        return Ok(SessionGrantReserveOutcome::Indeterminate(
            evict_operation(conn, stored.id).await?,
        ));
    }
    Ok(if stored.state == SessionGrantOperationState::Committed {
        SessionGrantReserveOutcome::Replay(stored)
    } else {
        SessionGrantReserveOutcome::Pending(stored)
    })
}

#[cfg(test)]
mod collision_tests;

#[async_trait]
impl<P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    SessionGrantRepository for PgOAuthSessionGrantRepository<'_, P>
{
    type Error = DatabaseError;

    async fn lookup_operation_by_identity(
        &mut self,
        issuer_id: &DidCoreId,
        kind: SessionGrantOperationKind,
        proof_kind: Option<SessionGrantProofKind>,
        request_identity: &str,
    ) -> Result<Option<SessionGrantOperation>, Self::Error> {
        let query = oauth_session_grant_operations::table
            .filter(oauth_session_grant_operations::issuer_id.eq(issuer_id))
            .filter(oauth_session_grant_operations::operation_kind.eq(kind.as_str()))
            .filter(oauth_session_grant_operations::request_identity.eq(request_identity))
            .into_boxed();
        let row = if let Some(proof_kind) = proof_kind {
            query
                .filter(oauth_session_grant_operations::proof_kind.eq(proof_kind_wire(proof_kind)?))
                .select(SessionGrantOperationRow::as_select())
                .first::<SessionGrantOperationRow>(self.conn)
                .await
                .optional()?
        } else {
            query
                .filter(oauth_session_grant_operations::proof_kind.is_null())
                .select(SessionGrantOperationRow::as_select())
                .first::<SessionGrantOperationRow>(self.conn)
                .await
                .optional()?
        };
        row.map(SessionGrantOperation::try_from)
            .transpose()
            .map_err(Into::into)
    }

    async fn lock_operation(
        &mut self,
        operation_id: Ulid,
    ) -> Result<SessionGrantOperation, Self::Error> {
        load_operation_for_update(self.conn, operation_id).await
    }

    #[tracing::instrument(name = "db.oauth_session_grant.reserve_operation", skip_all, err)]
    async fn reserve_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        operation: NewSessionGrantOperation<'_>,
    ) -> Result<SessionGrantReserveOutcome, Self::Error> {
        let now = clock.now();
        if operation.request_identity.trim().is_empty()
            || operation.canonical_intent.is_empty()
            || arkret_canonical::sha256_bytes(operation.canonical_intent)
                != operation.canonical_intent_digest
        {
            return Err(DatabaseError::invalid_operation());
        }
        let operation_kind = operation.operation.kind();
        let proof_kind = operation.proof_kind.map(proof_kind_wire).transpose()?;
        if (operation_kind == SessionGrantOperationKind::Issue) != proof_kind.is_some() {
            return Err(DatabaseError::invalid_operation());
        }
        // An already reserved identity always wins before any new entropy or
        // predecessor lookup. A retry can never repair or replace its seed.
        if let Some(stored) = self
            .lookup_operation_by_identity(
                &operation.issuer_id,
                operation_kind,
                operation.proof_kind,
                operation.request_identity,
            )
            .await?
        {
            return existing_reservation_outcome(self.conn, &operation, now, stored).await;
        }
        let grant_producing = operation_kind != SessionGrantOperationKind::Revoke;
        if grant_producing
            && (operation.grant_not_before.is_none()
                || operation.grant_expires_at <= operation.grant_not_before)
        {
            return Err(DatabaseError::invalid_operation());
        }
        let (operation_selector, inherited_session_id) = match &operation.operation {
            SessionGrantOperationDescriptor::Issue => {
                if operation.target_session_grant_id.is_some() {
                    return Err(DatabaseError::invalid_operation());
                }
                (None, None)
            }
            SessionGrantOperationDescriptor::Refresh {
                predecessor_grant_id,
            } => {
                if operation.target_session_grant_id != Some(predecessor_grant_id) {
                    return Err(DatabaseError::invalid_operation());
                }
                let predecessor = load_grant_by_protocol_id(
                    self.conn,
                    &operation.issuer_id,
                    predecessor_grant_id,
                )
                .await?
                .ok_or_else(DatabaseError::invalid_operation)?;
                if predecessor.metadata.credential_class != SessionGrantCredentialClass::Standard {
                    return Err(DatabaseError::invalid_operation());
                }
                (
                    Some(serde_json::json!({"predecessor_grant_id":predecessor_grant_id})),
                    Some(predecessor.session_id),
                )
            }
            SessionGrantOperationDescriptor::Revoke { selector } => {
                if operation.grant_not_before.is_some() || operation.grant_expires_at.is_some() {
                    return Err(DatabaseError::invalid_operation());
                }
                (Some(serde_json::to_value(selector)?), None)
            }
        };
        let unix_ms = u64::try_from(now.timestamp_millis())
            .map_err(|_| DatabaseError::invalid_operation())?;
        if unix_ms >= 1_u64 << 48 {
            return Err(DatabaseError::invalid_operation());
        }
        let retained_until = operation
            .retained_until
            .max(now + chrono::Duration::seconds(MIN_SESSION_GRANT_OPERATION_RETENTION_SECONDS));
        for _ in 0..MAX_SESSION_GRANT_ALLOCATION_ATTEMPTS {
            let (reserved_grant_id, reserved_credential_digest, reserved_session_grant, session_id) =
                if grant_producing {
                    // ID and U use independent issuer entropy. Their sole
                    // uniqueness authority is this row's atomic insertion.
                    let grant_id = SessionGrantId::try_from_uuid(Uuid::from(new_id(now, rng)))
                        .map_err(DatabaseError::to_invalid_operation)?
                        .uuid();
                    let mut secret = [0_u8; 32];
                    rng.fill_bytes(&mut secret);
                    let secret = SessionGrantSecret::from_bytes(secret).into_string();
                    let digest = arkret_canonical::sha256_bytes(secret.as_bytes()).to_vec();
                    (
                        Some(grant_id),
                        Some(digest),
                        Some(secret),
                        Some(
                            inherited_session_id
                                .clone()
                                .unwrap_or_else(|| format!("session-chain:{}", new_id(now, rng))),
                        ),
                    )
                } else {
                    (None, None, None, None)
                };
            let id = new_id(now, rng);
            let row = NewSessionGrantOperationRow {
                id: Uuid::from(id),
                issuer_id: &operation.issuer_id,
                operation_kind: operation_kind.as_str(),
                proof_kind: proof_kind.as_deref(),
                request_identity: operation.request_identity,
                canonical_intent_digest: operation.canonical_intent_digest.to_vec(),
                canonical_intent: Some(operation.canonical_intent),
                operation_selector: operation_selector.clone(),
                reserved_grant_id,
                reserved_credential_digest,
                reserved_session_grant,
                session_id,
                grant_not_before: operation.grant_not_before,
                grant_expires_at: operation.grant_expires_at,
                state: "reserved",
                target_session_grant_id: operation
                    .target_session_grant_id
                    .map(SessionGrantId::uuid),
                retained_until,
                created_at: now,
            };
            let inserted = diesel::insert_into(oauth_session_grant_operations::table)
                .values(&row)
                .on_conflict_do_nothing()
                .execute(self.conn)
                .await?
                == 1;
            if inserted {
                return Ok(SessionGrantReserveOutcome::Reserved(
                    load_operation_for_update(self.conn, id).await?,
                ));
            }
            // ON CONFLICT waits for a competing owner. If it won this request
            // identity, return that immutable result; only an unreserved
            // candidate allocation collision may draw again.
            if let Some(stored) = self
                .lookup_operation_by_identity(
                    &operation.issuer_id,
                    operation_kind,
                    operation.proof_kind,
                    operation.request_identity,
                )
                .await?
            {
                return existing_reservation_outcome(self.conn, &operation, now, stored).await;
            }
        }
        Err(DatabaseError::to_invalid_operation(std::io::Error::other(
            "issuer allocation collision retry limit exhausted",
        )))
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
        horme::transaction(self.conn, async |conn| {
            let operation = load_operation_for_update(conn, operation_id).await?;
            if now >= operation.retained_until {
                return evict_operation(conn, operation_id).await;
            }
            match operation.state {
                SessionGrantOperationState::Evicted => Err(DatabaseError::invalid_operation()),
                SessionGrantOperationState::Authorized | SessionGrantOperationState::Committed => {
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
        let allocated_at = clock.now();
        let id = new_id(allocated_at, rng);
        horme::transaction(self.conn, async move |conn| {
            let operation = load_operation_for_update(conn, operation_id).await?;
            if operation.state == SessionGrantOperationState::Evicted
                || clock.now() >= operation.retained_until
            {
                return Ok(SessionGrantCommitOutcome::Indeterminate(operation));
            }
            if operation.operation.kind() != SessionGrantOperationKind::Issue {
                return Err(DatabaseError::invalid_operation());
            }
            if operation.state == SessionGrantOperationState::Committed {
                return Ok(SessionGrantCommitOutcome::Replay(operation));
            }
            // Keep the global operation -> subject order. Neither lock wait
            // can extend a first authorization or a retained gate witness.
            lock_session_grant_subject(conn, grant.issuer_id, grant.subject_id).await?;
            let now = clock.now();
            if operation
                .grant_expires_at
                .is_some_and(|expires_at| now >= expires_at)
            {
                let operation = evict_operation(conn, operation_id).await?;
                return Ok(SessionGrantCommitOutcome::Indeterminate(operation));
            }
            if operation.state == SessionGrantOperationState::Reserved
                && authorization.proof_expires_at <= now
            {
                return Ok(SessionGrantCommitOutcome::AuthorizationExpired(operation));
            }
            validate_authorization(&operation, authorization, now)?;
            validate_grant_material(&operation, &grant)?;
            let retained_until = operation.retained_until.max(authorization.proof_expires_at);
            let grant_id = grant.grant_id.clone();
            let row = new_grant_row(id, operation_id, now, &grant)?;
            diesel::insert_into(oauth_session_grants::table)
                .values(&row)
                .execute(conn)
                .await?;
            commit_operation_outcome(
                conn,
                CommitOperationOutcome {
                    operation_id,
                    authorization,
                    outcome,
                    target_session_grant_id: None,
                    result_grant_id: Some(&grant_id),
                    affected_grant_ids: &[],
                    retained_until,
                    committed_at: now,
                },
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
        commit: SessionGrantRefreshCommit<'_>,
    ) -> Result<SessionGrantRefreshOutcome, Self::Error> {
        let SessionGrantRefreshCommit {
            operation_id,
            authorization,
            outcome,
            predecessor_grant_id,
            successor,
        } = commit;
        validate_exact_outcome(outcome)?;
        let allocated_at = clock.now();
        let successor_row_id = new_id(allocated_at, rng);
        horme::transaction(self.conn, async move |conn| {
            let operation = load_operation_for_update(conn, operation_id).await?;
            if operation.state == SessionGrantOperationState::Evicted
                || clock.now() >= operation.retained_until
            {
                return Ok(SessionGrantRefreshOutcome::Indeterminate(operation));
            }
            if operation.operation.kind() != SessionGrantOperationKind::Refresh
                || operation.target_session_grant_id.as_ref() != Some(predecessor_grant_id)
            {
                return Err(DatabaseError::invalid_operation());
            }
            if operation.state == SessionGrantOperationState::Committed {
                return Ok(SessionGrantRefreshOutcome::Replay(operation));
            }
            validate_grant_material(&operation, &successor)?;
            lock_session_grant_subject(conn, successor.issuer_id, successor.subject_id).await?;
            let predecessor =
                load_grant_by_protocol_id(conn, &operation.issuer_id, predecessor_grant_id)
                    .await?
                    .ok_or_else(DatabaseError::invalid_operation)?;
            if predecessor.issuer_id != *successor.issuer_id
                || predecessor.subject_id != *successor.subject_id
                || predecessor.session_id != successor.session_id
            {
                return Err(DatabaseError::invalid_operation());
            }
            validate_refresh_chain(&predecessor, &successor)?;
            let predecessor = load_grant_by_protocol_id_for_update(
                conn,
                &operation.issuer_id,
                predecessor_grant_id,
            )
            .await?
            .ok_or_else(DatabaseError::invalid_operation)?;
            // All potentially blocking current-row locks precede the one
            // accepting time. A fresh witness cannot survive either wait.
            let now = clock.now();
            if operation
                .grant_expires_at
                .is_some_and(|expiry| now >= expiry)
            {
                let operation = evict_operation(conn, operation_id).await?;
                return Ok(SessionGrantRefreshOutcome::Indeterminate(operation));
            }
            if operation.state == SessionGrantOperationState::Reserved
                && now >= authorization.proof_expires_at
            {
                return Ok(SessionGrantRefreshOutcome::AuthorizationExpired(operation));
            }
            validate_authorization(&operation, authorization, now)?;
            if predecessor.lifecycle_state != SessionGrantLifecycleState::Active
                || predecessor.expires_at <= now
            {
                return Ok(SessionGrantRefreshOutcome::PredecessorTerminal(Box::new(
                    predecessor,
                )));
            }
            let successor_grant_id = successor.grant_id.clone();
            diesel::insert_into(oauth_session_grants::table)
                .values(new_grant_row(
                    successor_row_id,
                    operation_id,
                    now,
                    &successor,
                )?)
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
                oauth_session_grants::successor_grant_id.eq(Some(successor_grant_id.uuid())),
            ))
            .execute(conn)
            .await?;
            DatabaseError::ensure_affected_rows_usize(changed, 1)?;

            let retained_until = operation.retained_until.max(authorization.proof_expires_at);
            commit_operation_outcome(
                conn,
                CommitOperationOutcome {
                    operation_id,
                    authorization,
                    outcome,
                    target_session_grant_id: Some(predecessor_grant_id),
                    result_grant_id: Some(&successor_grant_id),
                    affected_grant_ids: &[],
                    retained_until,
                    committed_at: now,
                },
            )
            .await?;
            let predecessor =
                load_grant_by_protocol_id(conn, &operation.issuer_id, predecessor_grant_id)
                    .await?
                    .ok_or_else(DatabaseError::invalid_operation)?;
            Ok(SessionGrantRefreshOutcome::Committed {
                predecessor: Box::new(predecessor),
                successor: Box::new(owned_grant(successor_row_id, operation_id, now, successor)),
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
        horme::transaction(self.conn, async move |conn| {
            let operation = load_operation_for_update(conn, operation_id).await?;
            if operation.state == SessionGrantOperationState::Evicted
                || now >= operation.retained_until
            {
                return Ok(SessionGrantRevokeOutcome::Indeterminate(operation));
            }
            if operation.operation.kind() != SessionGrantOperationKind::Revoke {
                return Err(DatabaseError::invalid_operation());
            }
            if operation.state == SessionGrantOperationState::Committed {
                return Ok(SessionGrantRevokeOutcome::Replay(operation));
            }
            validate_authorization(&operation, authorization, now)?;

            let (subject_id, expected_selector) = match selector {
                SessionGrantRevokeSelector::Grant(grant_id) => {
                    let grant = load_grant_by_protocol_id(conn, &operation.issuer_id, grant_id)
                        .await?
                        .ok_or_else(DatabaseError::invalid_operation)?;
                    if grant.issuer_id != operation.issuer_id {
                        return Err(DatabaseError::invalid_operation());
                    }
                    (
                        grant.subject_id,
                        SessionGrantRevokeTarget::Grant {
                            grant_id: grant_id.clone(),
                        },
                    )
                }
                SessionGrantRevokeSelector::Device {
                    subject_id,
                    device_id,
                } => (
                    subject_id.to_owned(),
                    SessionGrantRevokeTarget::Device {
                        subject_id: subject_id.to_owned(),
                        device_id: device_id.to_owned(),
                    },
                ),
                SessionGrantRevokeSelector::AllForSubject { subject_id } => (
                    subject_id.to_owned(),
                    SessionGrantRevokeTarget::AllForSubject {
                        subject_id: subject_id.to_owned(),
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
            lock_session_grant_subject(conn, &operation.issuer_id, &subject_id).await?;

            let mut query = oauth_session_grants::table
                .filter(oauth_session_grants::issuer_id.eq(&operation.issuer_id))
                .filter(oauth_session_grants::subject_id.eq(&subject_id))
                .into_boxed();
            match selector {
                SessionGrantRevokeSelector::Grant(grant_id) => {
                    query = query.filter(oauth_session_grants::grant_id.eq(grant_id.uuid()));
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
                    load_grant_by_protocol_id_for_update(
                        conn,
                        &operation.issuer_id,
                        &candidate.grant_id,
                    )
                    .await?
                    .ok_or_else(DatabaseError::invalid_operation)?,
                );
            }
            let mut active_ids = matched
                .iter()
                .filter(|grant| {
                    grant.lifecycle_state == SessionGrantLifecycleState::Active
                        && grant.expires_at > now
                })
                .map(|grant| grant.grant_id.clone())
                .collect::<Vec<_>>();
            active_ids.sort();
            if !active_ids.is_empty() {
                let active_bytes = active_ids.iter().map(|id| id.uuid()).collect::<Vec<_>>();
                let changed = diesel::update(
                    oauth_session_grants::table
                        .filter(oauth_session_grants::issuer_id.eq(&operation.issuer_id))
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
                revoked_count: u64::try_from(active_ids.len())?,
                revoked_session_grant_ids: active_ids.clone(),
            };
            let canonical_response = arkret_canonical::canonical_json_bytes(&wire_outcome)?;
            let response_digest = arkret_canonical::sha256_bytes(&canonical_response);
            let target = match selector {
                SessionGrantRevokeSelector::Grant(grant_id) => Some(grant_id),
                _ => None,
            };
            commit_operation_outcome(
                conn,
                CommitOperationOutcome {
                    operation_id,
                    authorization,
                    outcome: SessionGrantExactOutcome {
                        canonical_response: &canonical_response,
                        response_digest,
                    },
                    target_session_grant_id: target,
                    result_grant_id: None,
                    affected_grant_ids: &active_ids,
                    retained_until,
                    committed_at: now,
                },
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
                    load_grant_by_protocol_id(conn, &operation.issuer_id, grant_id)
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
        issuer_id: &DidCoreId,
        grant_id: &SessionGrantId,
    ) -> Result<Option<SessionGrant>, Self::Error> {
        load_grant_by_protocol_id(self.conn, issuer_id, grant_id).await
    }

    #[tracing::instrument(name = "db.oauth_session_grant.lookup_by_secret", skip_all, err)]
    async fn lookup_by_secret(
        &mut self,
        issuer_id: &DidCoreId,
        secret: &SessionGrantSecret,
    ) -> Result<Option<SessionGrant>, Self::Error> {
        let digest = arkret_canonical::sha256_bytes(secret.as_str().as_bytes());
        let row = oauth_session_grants::table
            .filter(oauth_session_grants::issuer_id.eq(issuer_id))
            .filter(oauth_session_grants::credential_digest.eq(digest.to_vec()))
            .filter(oauth_session_grants::session_grant.eq(secret.as_str()))
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

        query = crate::paginate_by_id!(query, pagination, oauth_session_grants::id);

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
        horme::transaction(self.conn, async move |conn| {
            let rows_affected = diesel::update(
                oauth_session_grants::table
                    .find(Uuid::from(grant.id))
                    .filter(oauth_session_grants::lifecycle_state.eq("active")),
            )
            .set((
                oauth_session_grants::lifecycle_state.eq("revoked"),
                oauth_session_grants::revoked_at.eq(Some(revoked_at)),
            ))
            .execute(conn)
            .await?;
            DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;
            grant
                .revoke(revoked_at)
                .map_err(DatabaseError::to_invalid_operation)
        })
        .await
    }

    #[tracing::instrument(name = "db.oauth_session_grant.revoke_if_active", skip_all, err)]
    async fn revoke_if_active(&mut self, clock: &dyn Clock, id: Ulid) -> Result<bool, Self::Error> {
        let revoked_at = clock.now();
        // Conditional UPDATE remains the one-shot rotation CAS.
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
        name = "db.oauth_session_grant.revoke_active_for_audience",
        skip_all,
        err
    )]
    async fn revoke_active_for_audience(
        &mut self,
        clock: &dyn Clock,
        audience_id: &DidCoreId,
    ) -> Result<usize, Self::Error> {
        let revoked_at = clock.now();
        let rows_affected = diesel::update(
            oauth_session_grants::table
                .filter(oauth_session_grants::audience_id.eq(audience_id))
                .filter(oauth_session_grants::lifecycle_state.eq("active")),
        )
        .set((
            oauth_session_grants::lifecycle_state.eq("revoked"),
            oauth_session_grants::revoked_at.eq(Some(revoked_at)),
        ))
        .execute(self.conn)
        .await?;
        Ok(rows_affected)
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
                                replay.target_session_grant_id = oauth_session_grants.grant_id
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

#[cfg(test)]
mod opaque_record_tests {
    use arkret_models_identity::{
        CanonicalSessionPublicJwk, SessionGrantDeviceBinding, SessionGrantHolderBinding,
    };

    use super::*;

    fn metadata() -> SessionGrantMetadata {
        let public_key = CanonicalSessionPublicJwk::new(
            r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap();
        let account = arkret_wire::AccountId::new(
            "ak:did_core:web:alice.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        );
        let device_id: arkret_identifiers::DeviceId =
            "ak:device:0190c6aa-1234-7000-8000-000000000001"
                .parse()
                .unwrap();
        SessionGrantMetadata {
            id: SessionGrantId::new_v7_at(1_794_657_600_000),
            issuer_id: "ak:did_core:web:issuer.example".parse().unwrap(),
            account_id: account.clone(),
            device_id: Some(device_id.clone()),
            audience_id: account.station_id,
            scopes: vec!["ak.message.create".into(), "ak.message.read".into()],
            not_before: "2026-11-14T12:00:00.000Z".parse().unwrap(),
            expires_at: "2026-11-14T12:15:00.000Z".parse().unwrap(),
            session_id: "opaque-record-test-chain".into(),
            cnf_jkt: public_key.thumbprint_sha256().unwrap(),
            session_public_key: public_key,
            credential_class: SessionGrantCredentialClass::Standard,
            holder_binding: SessionGrantHolderBinding::HumanDevice {
                device_binding: device_id.to_string(),
            },
            device_binding: Some(SessionGrantDeviceBinding {
                device_id,
                authorization_event_id: "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .parse()
                    .unwrap(),
                model_generation_ref: 1,
            }),
            proof_kind: Some(SessionGrantProofKind::AccountHandoff),
            scope_details: None,
        }
    }
    fn grant<'a>(
        metadata: &'a SessionGrantMetadata,
        secret: &'a SessionGrantSecret,
        local: &'a LocalAccountId,
    ) -> NewSessionGrant<'a> {
        NewSessionGrant {
            grant_id: metadata.id.clone(),
            browser_session_id: None,
            issuer_id: &metadata.issuer_id,
            subject_id: &metadata.account_id.principal_id,
            local_account_id: local,
            device_id: metadata.device_id.as_ref().map(|id| id.as_str()),
            audience_id: &metadata.audience_id,
            scope: metadata
                .scopes
                .iter()
                .map(|scope| scope.parse::<ScopeToken>().unwrap())
                .collect(),
            session_grant: secret,
            metadata,
            session_id: &metadata.session_id,
            session_public_key: metadata.session_public_key.as_str(),
            credential_class: "standard",
            not_before: metadata.not_before,
            expires_at: metadata.expires_at,
        }
    }
    fn operation(
        metadata: &SessionGrantMetadata,
        secret: &SessionGrantSecret,
    ) -> SessionGrantOperation {
        let intent = br#"{"request_id":"first"}"#.to_vec();
        SessionGrantOperation {
            id: Ulid::from(1_u128),
            issuer_id: metadata.issuer_id.clone(),
            operation: SessionGrantOperationDescriptor::Issue,
            proof_kind: metadata.proof_kind,
            request_identity: "logical-issue".into(),
            canonical_intent_digest: arkret_canonical::sha256_bytes(&intent),
            canonical_intent: Some(intent),
            reserved_grant_id: Some(metadata.id.clone()),
            reserved_credential_digest: Some(arkret_canonical::sha256_bytes(
                secret.as_str().as_bytes(),
            )),
            reserved_session_grant: Some(secret.clone()),
            session_id: Some(metadata.session_id.clone()),
            grant_not_before: Some(metadata.not_before),
            grant_expires_at: Some(metadata.expires_at),
            proof_authorization_ref: None,
            proof_authorization_checkpoint: None,
            proof_expires_at: None,
            outcome_digest: None,
            canonical_outcome: None,
            state: SessionGrantOperationState::Reserved,
            target_session_grant_id: None,
            result_grant_id: None,
            affected_grant_ids: vec![],
            retained_until: metadata.expires_at + chrono::Duration::days(7),
            created_at: metadata.not_before,
            committed_at: None,
        }
    }
    #[test]
    fn valid_material_requires_exact_reserved_secret_record_and_metadata() {
        let metadata = metadata();
        let secret = SessionGrantSecret::from_bytes([1; 32]);
        let local = LocalAccountId::new("local-account").unwrap();
        let operation = operation(&metadata, &secret);
        validate_grant_material(&operation, &grant(&metadata, &secret, &local)).unwrap();
        let other = SessionGrantSecret::from_bytes([2; 32]);
        assert!(validate_grant_material(&operation, &grant(&metadata, &other, &local)).is_err());
        let mut changed = operation.clone();
        changed.reserved_grant_id = Some(SessionGrantId::new_v7_at(1_794_657_600_001));
        assert!(validate_grant_material(&changed, &grant(&metadata, &secret, &local)).is_err());
        let mut changed = operation.clone();
        changed.issuer_id = "ak:did_core:web:another.example".parse().unwrap();
        assert!(validate_grant_material(&changed, &grant(&metadata, &secret, &local)).is_err());
        let mut changed = operation.clone();
        changed.reserved_session_grant = None;
        assert!(validate_grant_material(&changed, &grant(&metadata, &secret, &local)).is_err());
        let mut changed = operation;
        changed.grant_expires_at = Some(metadata.expires_at + chrono::Duration::milliseconds(1));
        assert!(validate_grant_material(&changed, &grant(&metadata, &secret, &local)).is_err());
    }
    #[test]
    fn query_projections_cannot_replace_immutable_authorization_metadata() {
        let metadata = metadata();
        let secret = SessionGrantSecret::from_bytes([1; 32]);
        let local = LocalAccountId::new("local-account").unwrap();
        let other: DidCoreId = "ak:did_core:web:another.example".parse().unwrap();
        let mut changed = grant(&metadata, &secret, &local);
        changed.subject_id = &other;
        assert!(validate_grant_projection(&changed).is_err());
        let mut changed = grant(&metadata, &secret, &local);
        changed.audience_id = &other;
        assert!(validate_grant_projection(&changed).is_err());
        let mut changed = grant(&metadata, &secret, &local);
        changed.session_id = "other-chain";
        assert!(validate_grant_projection(&changed).is_err());
        let mut changed = grant(&metadata, &secret, &local);
        changed.scope = "ak.message.read".parse().unwrap();
        assert!(validate_grant_projection(&changed).is_err());
    }
    #[test]
    fn refresh_preserves_one_holder_chain_and_the_exact_scope() {
        let old = metadata();
        let old_secret = SessionGrantSecret::from_bytes([1; 32]);
        let new_secret = SessionGrantSecret::from_bytes([2; 32]);
        let local = LocalAccountId::new("local-account").unwrap();
        let predecessor = owned_grant(
            Ulid::from(1_u128),
            Ulid::from(2_u128),
            old.not_before,
            grant(&old, &old_secret, &local),
        );
        let mut next = old.clone();
        next.id = SessionGrantId::new_v7_at(1_794_657_600_001);
        validate_refresh_chain(&predecessor, &grant(&next, &new_secret, &local)).unwrap();
        assert!(validate_refresh_chain(&predecessor, &grant(&next, &old_secret, &local)).is_err());
        for change in 0..7 {
            let mut changed = next.clone();
            match change {
                0 => changed.id = old.id.clone(),
                1 => changed.issuer_id = "ak:did_core:web:another.example".parse().unwrap(),
                2 => changed.session_id = "other-chain".into(),
                3 => changed.scopes.push("ak.message.write".into()),
                4 => {
                    changed
                        .device_binding
                        .as_mut()
                        .unwrap()
                        .model_generation_ref += 1
                }
                5 => changed.credential_class = SessionGrantCredentialClass::RecoverySession,
                _ => {
                    changed.scopes.pop();
                }
            }
            assert!(
                validate_refresh_chain(&predecessor, &grant(&changed, &new_secret, &local))
                    .is_err(),
                "case {change}"
            );
        }
    }
}
