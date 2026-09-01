//! Durable Passkey / WebAuthn registration and authentication.
//!
//! Ceremony state is server-side, single-use, and stored in PostgreSQL.  The
//! opaque ceremony id and a separate browser binding are both required at
//! finish time, so account hints never select the subject of a completed
//! ceremony.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use diesel::sql_types::{
    Array, BigInt, Bool, Bytea, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid,
};
use diesel::{OptionalExtension as _, QueryableByName};
use diesel_async::pooled_connection::deadpool::Pool as DieselPool;
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};
use thiserror::Error;
use ulid::Ulid;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

pub type WebauthnServiceHandle = Arc<dyn WebauthnService>;

const CHALLENGE_TTL: Duration = Duration::minutes(10);
const MAX_LABEL_CHARS: usize = 80;
const REGISTRATION_KIND: &str = "registration";
const AUTHENTICATION_KIND: &str = "authentication";

#[derive(Clone, Debug)]
pub struct WebauthnCredentialRecord {
    pub id: Ulid,
    pub account_id: Ulid,
    pub credential_id: Vec<u8>,
    pub public_key: Passkey,
    pub sign_count: u32,
    pub transports: Vec<String>,
    pub label: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct WebauthnAuthentication {
    pub account_id: Ulid,
    pub credential_record_id: Ulid,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

#[derive(Debug)]
pub struct CeremonyStart<T> {
    pub id: Ulid,
    pub challenge: T,
}

#[derive(Debug, Error)]
pub enum WebauthnError {
    #[error("webauthn-rs core error: {0}")]
    Core(#[from] webauthn_rs::prelude::WebauthnError),

    #[error("storage error: {0}")]
    Storage(#[from] anyhow::Error),

    #[error("ceremony {0} is missing, expired, already consumed, or bound to another browser")]
    NoChallenge(Ulid),

    #[error("no passkeys registered for account {0}")]
    NoCredentials(Ulid),

    #[error("credential {0} not found")]
    CredentialNotFound(Ulid),

    #[error("passkey label must be at most {MAX_LABEL_CHARS} characters")]
    InvalidLabel,

    #[error("the last active passkey cannot be revoked")]
    LastCredential,

    #[error("the authenticator did not perform user verification")]
    UserVerificationRequired,

    #[error("the authenticator signature counter changed concurrently")]
    CounterConflict,

    #[error("invalid relying-party origin: {0}")]
    InvalidOrigin(String),

    #[error("credential serialisation failed: {0}")]
    Serde(#[from] serde_json::Error),
}

impl From<diesel::result::Error> for WebauthnError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Storage(anyhow::anyhow!(error))
    }
}

#[async_trait::async_trait]
pub trait WebauthnService: Send + Sync {
    async fn register_start(
        &self,
        account_id: Ulid,
        username: &str,
        display_name: &str,
        binding_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CeremonyStart<CreationChallengeResponse>, WebauthnError>;

    async fn register_finish(
        &self,
        ceremony_id: Ulid,
        account_id: Ulid,
        binding_id: &str,
        attestation: &RegisterPublicKeyCredential,
        label: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<WebauthnCredentialRecord, WebauthnError>;

    async fn auth_start(
        &self,
        account_id: Ulid,
        binding_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CeremonyStart<RequestChallengeResponse>, WebauthnError>;

    async fn auth_finish(
        &self,
        ceremony_id: Ulid,
        binding_id: &str,
        assertion: &PublicKeyCredential,
        now: DateTime<Utc>,
    ) -> Result<WebauthnAuthentication, WebauthnError>;

    async fn list(&self, account_id: Ulid) -> Result<Vec<WebauthnCredentialRecord>, WebauthnError>;

    async fn rename(
        &self,
        account_id: Ulid,
        credential_id: Ulid,
        label: Option<String>,
    ) -> Result<(), WebauthnError>;

    async fn revoke(
        &self,
        account_id: Ulid,
        credential_id: Ulid,
        now: DateTime<Utc>,
    ) -> Result<(), WebauthnError>;
}

pub struct PgWebauthnService {
    webauthn: Arc<Webauthn>,
    pool: DieselPool<AsyncPgConnection>,
}

impl PgWebauthnService {
    pub fn new(
        rp_id: &str,
        rp_origin: &url::Url,
        rp_name: &str,
        pool: DieselPool<AsyncPgConnection>,
    ) -> Result<Self, WebauthnError> {
        if !is_secure_webauthn_origin(rp_origin) {
            return Err(WebauthnError::InvalidOrigin(
                "WebAuthn requires HTTPS outside localhost development".to_owned(),
            ));
        }
        let builder = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|e| WebauthnError::InvalidOrigin(e.to_string()))?
            .rp_name(rp_name);
        let webauthn = builder
            .build()
            .map_err(|e| WebauthnError::InvalidOrigin(e.to_string()))?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
            pool,
        })
    }

    async fn connection(
        &self,
    ) -> Result<diesel_async::pooled_connection::deadpool::Object<AsyncPgConnection>, WebauthnError>
    {
        self.pool
            .get()
            .await
            .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))
    }

    async fn load_credential_rows(
        &self,
        account_id: Ulid,
    ) -> Result<Vec<CredentialRow>, WebauthnError> {
        let mut conn = self.connection().await?;
        diesel::sql_query(
            r"
            SELECT id, account_id, credential_id, public_key, sign_count,
                   transports, label, backup_eligible, backup_state, user_verified,
                   created_at, last_used_at, revoked_at
            FROM webauthn_credentials
            WHERE account_id = $1 AND revoked_at IS NULL
            ORDER BY created_at DESC
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .get_results::<CredentialRow>(&mut *conn)
        .await
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))
    }

    async fn load_passkeys(&self, account_id: Ulid) -> Result<Vec<Passkey>, WebauthnError> {
        self.load_credential_rows(account_id)
            .await?
            .into_iter()
            .map(|row| serde_json::from_value(row.public_key).map_err(WebauthnError::from))
            .collect()
    }

    async fn insert_ceremony<S: serde::Serialize>(
        &self,
        account_id: Ulid,
        kind: &str,
        binding_id: &str,
        state: &S,
        now: DateTime<Utc>,
    ) -> Result<Ulid, WebauthnError> {
        let id = Uuid::now_v7();
        let expires_at = now + CHALLENGE_TTL;
        let state = serde_json::to_value(state)?;
        let mut conn = self.connection().await?;

        diesel::sql_query("DELETE FROM webauthn_ceremonies WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;

        diesel::sql_query(
            r"
            INSERT INTO webauthn_ceremonies
                (id, account_id, kind, binding_id, state, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ",
        )
        .bind::<DieselUuid, _>(id)
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .bind::<Text, _>(kind)
        .bind::<Text, _>(binding_id)
        .bind::<Jsonb, _>(state)
        .bind::<Timestamptz, _>(now)
        .bind::<Timestamptz, _>(expires_at)
        .execute(&mut *conn)
        .await
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;

        Ok(Ulid::from(id))
    }

    async fn consume_ceremony<S: serde::de::DeserializeOwned>(
        &self,
        ceremony_id: Ulid,
        kind: &str,
        binding_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(Ulid, S), WebauthnError> {
        let mut conn = self.connection().await?;
        let row = diesel::sql_query(
            r"
            DELETE FROM webauthn_ceremonies
            WHERE id = $1
              AND kind = $2
              AND binding_id = $3
              AND expires_at > $4
            RETURNING account_id, state
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(ceremony_id))
        .bind::<Text, _>(kind)
        .bind::<Text, _>(binding_id)
        .bind::<Timestamptz, _>(now)
        .get_result::<CeremonyRow>(&mut *conn)
        .await
        .optional()
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?
        .ok_or(WebauthnError::NoChallenge(ceremony_id))?;

        Ok((
            Ulid::from(row.account_id),
            serde_json::from_value(row.state)?,
        ))
    }
}

#[derive(Debug, QueryableByName)]
struct CeremonyRow {
    #[diesel(sql_type = DieselUuid)]
    account_id: Uuid,
    #[diesel(sql_type = Jsonb)]
    state: serde_json::Value,
}

#[derive(Debug, QueryableByName)]
struct CredentialRow {
    #[diesel(sql_type = DieselUuid)]
    id: Uuid,
    #[diesel(sql_type = DieselUuid)]
    account_id: Uuid,
    #[diesel(sql_type = Bytea)]
    credential_id: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    public_key: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    sign_count: i64,
    #[diesel(sql_type = Array<Text>)]
    transports: Vec<String>,
    #[diesel(sql_type = Nullable<Text>)]
    label: Option<String>,
    #[diesel(sql_type = Bool)]
    backup_eligible: bool,
    #[diesel(sql_type = Bool)]
    backup_state: bool,
    #[diesel(sql_type = Bool)]
    user_verified: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_used_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct CredentialCounts {
    #[diesel(sql_type = BigInt)]
    active_count: i64,
    #[diesel(sql_type = BigInt)]
    target_count: i64,
}

#[derive(QueryableByName)]
struct AdvisoryLockRow {
    #[diesel(sql_type = Text)]
    _locked: String,
}

impl CredentialRow {
    fn into_record(self) -> Result<WebauthnCredentialRecord, WebauthnError> {
        let public_key = serde_json::from_value(self.public_key)?;
        let sign_count = u32::try_from(self.sign_count).map_err(|_| {
            WebauthnError::Storage(anyhow::anyhow!(
                "stored WebAuthn signature counter is outside the u32 range"
            ))
        })?;
        Ok(WebauthnCredentialRecord {
            id: Ulid::from(self.id),
            account_id: Ulid::from(self.account_id),
            credential_id: self.credential_id,
            public_key,
            sign_count,
            transports: self.transports,
            label: self.label,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            user_verified: self.user_verified,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
        })
    }
}

fn passkey_metadata(
    public_key: &serde_json::Value,
) -> (i64, Vec<String>, Option<Uuid>, bool, bool, bool) {
    let credential = public_key.get("cred").unwrap_or(public_key);
    let counter = credential
        .get("counter")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or_default();
    let transports = credential
        .get("transports")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let backup_eligible = credential
        .get("backup_eligible")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let backup_state = credential
        .get("backup_state")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let user_verified = credential
        .get("user_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let aaguid = credential
        .get("attestation")
        .and_then(|value| value.get("metadata"))
        .and_then(|value| value.get("Packed").or_else(|| value.get("Tpm")))
        .and_then(|value| value.get("aaguid"))
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse().ok());
    (
        counter,
        transports,
        aaguid,
        backup_eligible,
        backup_state,
        user_verified,
    )
}

fn normalize_label(label: Option<String>) -> Result<Option<String>, WebauthnError> {
    let label = label
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if label
        .as_ref()
        .is_some_and(|value| value.chars().count() > MAX_LABEL_CHARS)
    {
        return Err(WebauthnError::InvalidLabel);
    }
    Ok(label)
}

fn is_secure_webauthn_origin(origin: &url::Url) -> bool {
    origin.scheme() == "https"
        || (origin.scheme() == "http" && origin.host_str() == Some("localhost"))
}

fn counter_transition_is_valid(stored: u32, asserted: u32) -> bool {
    (stored == 0 && asserted == 0) || asserted > stored
}

#[async_trait::async_trait]
impl WebauthnService for PgWebauthnService {
    async fn register_start(
        &self,
        account_id: Ulid,
        username: &str,
        display_name: &str,
        binding_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CeremonyStart<CreationChallengeResponse>, WebauthnError> {
        let existing = self.load_passkeys(account_id).await?;
        let exclude: Vec<CredentialID> = existing.iter().map(|pk| pk.cred_id().clone()).collect();
        let (challenge, state) = self.webauthn.start_passkey_registration(
            Uuid::from(account_id),
            username,
            display_name,
            (!exclude.is_empty()).then_some(exclude),
        )?;
        let id = self
            .insert_ceremony(account_id, REGISTRATION_KIND, binding_id, &state, now)
            .await?;
        Ok(CeremonyStart { id, challenge })
    }

    async fn register_finish(
        &self,
        ceremony_id: Ulid,
        account_id: Ulid,
        binding_id: &str,
        attestation: &RegisterPublicKeyCredential,
        label: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<WebauthnCredentialRecord, WebauthnError> {
        let label = normalize_label(label)?;
        let (ceremony_account_id, state): (Ulid, PasskeyRegistration) = self
            .consume_ceremony(ceremony_id, REGISTRATION_KIND, binding_id, now)
            .await?;
        if ceremony_account_id != account_id {
            return Err(WebauthnError::NoChallenge(ceremony_id));
        }

        let passkey = self
            .webauthn
            .finish_passkey_registration(attestation, &state)?;
        let id = Uuid::now_v7();
        let credential_id = passkey.cred_id().as_ref().to_vec();
        let public_key = serde_json::to_value(&passkey)?;
        let (sign_count, transports, aaguid, backup_eligible, backup_state, user_verified) =
            passkey_metadata(&public_key);
        let transports = attestation
            .response
            .transports
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.as_ref().to_owned())
                    .collect()
            })
            .filter(|values: &Vec<String>| !values.is_empty())
            .unwrap_or(transports);

        let mut conn = self.connection().await?;
        let row = diesel::sql_query(
            r"
            INSERT INTO webauthn_credentials (
                id, account_id, credential_id, public_key, sign_count,
                transports, aaguid, backup_eligible, backup_state,
                user_verified, label, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id, account_id, credential_id, public_key, sign_count,
                      transports, label, backup_eligible, backup_state, user_verified,
                      created_at, last_used_at, revoked_at
            ",
        )
        .bind::<DieselUuid, _>(id)
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .bind::<Bytea, _>(credential_id)
        .bind::<Jsonb, _>(public_key)
        .bind::<BigInt, _>(sign_count)
        .bind::<Array<Text>, _>(transports)
        .bind::<Nullable<DieselUuid>, _>(aaguid)
        .bind::<Bool, _>(backup_eligible)
        .bind::<Bool, _>(backup_state)
        .bind::<Bool, _>(user_verified)
        .bind::<Nullable<Text>, _>(label)
        .bind::<Timestamptz, _>(now)
        .get_result::<CredentialRow>(&mut *conn)
        .await
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;

        row.into_record()
    }

    async fn auth_start(
        &self,
        account_id: Ulid,
        binding_id: &str,
        now: DateTime<Utc>,
    ) -> Result<CeremonyStart<RequestChallengeResponse>, WebauthnError> {
        let passkeys = self.load_passkeys(account_id).await?;
        if passkeys.is_empty() {
            return Err(WebauthnError::NoCredentials(account_id));
        }
        let (challenge, state) = self.webauthn.start_passkey_authentication(&passkeys)?;
        let id = self
            .insert_ceremony(account_id, AUTHENTICATION_KIND, binding_id, &state, now)
            .await?;
        Ok(CeremonyStart { id, challenge })
    }

    async fn auth_finish(
        &self,
        ceremony_id: Ulid,
        binding_id: &str,
        assertion: &PublicKeyCredential,
        now: DateTime<Utc>,
    ) -> Result<WebauthnAuthentication, WebauthnError> {
        let (account_id, state): (Ulid, PasskeyAuthentication) = self
            .consume_ceremony(ceremony_id, AUTHENTICATION_KIND, binding_id, now)
            .await?;
        let result = self
            .webauthn
            .finish_passkey_authentication(assertion, &state)?;
        if !result.user_verified() {
            return Err(WebauthnError::UserVerificationRequired);
        }
        let credential_id = result.cred_id().as_ref().to_vec();

        let mut conn = self.connection().await?;
        (*conn)
            .transaction::<_, WebauthnError, _>(async move |conn| {
                // Lock the current credential projection before comparing the
                // authenticator counter. Ceremony state may be older than a
                // concurrently completed assertion, so verification against
                // ceremony state alone is insufficient to prevent rollback.
                let existing = diesel::sql_query(
                    r"
                    SELECT id, account_id, credential_id, public_key, sign_count,
                           transports, label, backup_eligible, backup_state, user_verified,
                           created_at, last_used_at, revoked_at
                    FROM webauthn_credentials
                    WHERE account_id = $1
                      AND credential_id = $2
                      AND revoked_at IS NULL
                    FOR UPDATE
                    ",
                )
                .bind::<DieselUuid, _>(Uuid::from(account_id))
                .bind::<Bytea, _>(credential_id.clone())
                .get_result::<CredentialRow>(conn)
                .await
                .optional()
                .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?
                .ok_or(WebauthnError::NoChallenge(ceremony_id))?;
                let credential_record_id = Ulid::from(existing.id);
                let current_counter = u32::try_from(existing.sign_count).map_err(|_| {
                    WebauthnError::Storage(anyhow::anyhow!(
                        "stored WebAuthn signature counter is outside the u32 range"
                    ))
                })?;
                if !counter_transition_is_valid(current_counter, result.counter()) {
                    return Err(WebauthnError::CounterConflict);
                }
                let mut passkey: Passkey = serde_json::from_value(existing.public_key)?;
                passkey.update_credential(&result);
                let public_key = serde_json::to_value(&passkey)?;
                let backup_eligible = existing.backup_eligible || result.backup_eligible();

                let row = diesel::sql_query(
                    r"
                    UPDATE webauthn_credentials
                    SET public_key = $3,
                        sign_count = $4,
                        backup_eligible = $5,
                        backup_state = $6,
                        user_verified = $7,
                        last_used_at = GREATEST(COALESCE(last_used_at, $8), $8)
                    WHERE account_id = $1
                      AND credential_id = $2
                      AND revoked_at IS NULL
                      AND sign_count = $9
                    RETURNING id, account_id, credential_id, public_key, sign_count,
                              transports, label, backup_eligible, backup_state, user_verified,
                              created_at, last_used_at, revoked_at
                    ",
                )
                .bind::<DieselUuid, _>(Uuid::from(account_id))
                .bind::<Bytea, _>(credential_id)
                .bind::<Jsonb, _>(public_key)
                .bind::<BigInt, _>(i64::from(result.counter()))
                .bind::<Bool, _>(backup_eligible)
                .bind::<Bool, _>(result.backup_state())
                .bind::<Bool, _>(result.user_verified())
                .bind::<Timestamptz, _>(now)
                .bind::<BigInt, _>(existing.sign_count)
                .get_result::<CredentialRow>(conn)
                .await
                .optional()
                .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?
                .ok_or(WebauthnError::CounterConflict)?;

                Ok(WebauthnAuthentication {
                    account_id,
                    credential_record_id,
                    user_verified: row.user_verified,
                    backup_eligible: row.backup_eligible,
                    backup_state: row.backup_state,
                })
            })
            .await
    }

    async fn list(&self, account_id: Ulid) -> Result<Vec<WebauthnCredentialRecord>, WebauthnError> {
        self.load_credential_rows(account_id)
            .await?
            .into_iter()
            .map(CredentialRow::into_record)
            .collect()
    }

    async fn rename(
        &self,
        account_id: Ulid,
        credential_id: Ulid,
        label: Option<String>,
    ) -> Result<(), WebauthnError> {
        let label = normalize_label(label)?;
        let mut conn = self.connection().await?;
        let affected = diesel::sql_query(
            r"
            UPDATE webauthn_credentials
            SET label = $3
            WHERE account_id = $1 AND id = $2 AND revoked_at IS NULL
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .bind::<DieselUuid, _>(Uuid::from(credential_id))
        .bind::<Nullable<Text>, _>(label)
        .execute(&mut *conn)
        .await
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;
        if affected == 0 {
            return Err(WebauthnError::CredentialNotFound(credential_id));
        }
        Ok(())
    }

    async fn revoke(
        &self,
        account_id: Ulid,
        credential_id: Ulid,
        now: DateTime<Utc>,
    ) -> Result<(), WebauthnError> {
        let mut conn = self.connection().await?;
        (*conn)
            .transaction::<_, WebauthnError, _>(async move |conn| {
                diesel::sql_query(
                    "SELECT pg_advisory_xact_lock(
                            hashtextextended(CAST($1 AS text), 0)
                         )::text AS _locked",
                )
                .bind::<DieselUuid, _>(Uuid::from(account_id))
                .get_result::<AdvisoryLockRow>(conn)
                .await
                .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;

                let counts = diesel::sql_query(
                    r"
                    SELECT COUNT(*) AS active_count,
                           COUNT(*) FILTER (WHERE id = $2) AS target_count
                    FROM webauthn_credentials
                    WHERE account_id = $1 AND revoked_at IS NULL
                    ",
                )
                .bind::<DieselUuid, _>(Uuid::from(account_id))
                .bind::<DieselUuid, _>(Uuid::from(credential_id))
                .get_result::<CredentialCounts>(conn)
                .await
                .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;
                if counts.target_count == 0 {
                    return Err(WebauthnError::CredentialNotFound(credential_id));
                }
                if counts.active_count <= 1 {
                    return Err(WebauthnError::LastCredential);
                }

                diesel::sql_query(
                    r"
                    UPDATE webauthn_credentials
                    SET revoked_at = $3
                    WHERE account_id = $1 AND id = $2 AND revoked_at IS NULL
                    ",
                )
                .bind::<DieselUuid, _>(Uuid::from(account_id))
                .bind::<DieselUuid, _>(Uuid::from(credential_id))
                .bind::<Timestamptz, _>(now)
                .execute(conn)
                .await
                .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;
                Ok(())
            })
            .await
    }
}

pub fn webauthn_service(
    rp_id: &str,
    rp_origin: &url::Url,
    rp_name: &str,
    pool: DieselPool<AsyncPgConnection>,
) -> Result<WebauthnServiceHandle, WebauthnError> {
    Ok(Arc::new(PgWebauthnService::new(
        rp_id, rp_origin, rp_name, pool,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_origin_is_rejected() {
        assert!(url::Url::parse("not-a-real-url").is_err());
    }

    #[test]
    fn rp_builder_accepts_https_origin() {
        let origin = url::Url::parse("https://auth.example.com").unwrap();
        assert!(WebauthnBuilder::new("auth.example.com", &origin).is_ok());
    }

    #[test]
    fn rp_builder_accepts_localhost_http_origin() {
        let origin = url::Url::parse("http://localhost:7080").unwrap();
        assert!(WebauthnBuilder::new("localhost", &origin).is_ok());
    }

    #[test]
    fn secure_origin_policy_rejects_insecure_non_localhost_origin() {
        let origin = url::Url::parse("http://auth.example.com").unwrap();
        assert!(WebauthnBuilder::new("auth.example.com", &origin).is_ok());
        assert!(!is_secure_webauthn_origin(&origin));
        assert!(is_secure_webauthn_origin(
            &url::Url::parse("https://auth.example.com").unwrap()
        ));
        assert!(is_secure_webauthn_origin(
            &url::Url::parse("http://localhost:7080").unwrap()
        ));
    }

    #[test]
    fn rp_builder_rejects_ip_literal_origin() {
        let origin = url::Url::parse("http://127.0.0.1:7080").unwrap();
        assert!(WebauthnBuilder::new("127.0.0.1", &origin).is_err());
    }

    #[test]
    fn rp_builder_rejects_mismatched_id() {
        let origin = url::Url::parse("https://auth.example.com").unwrap();
        assert!(WebauthnBuilder::new("other-host.com", &origin).is_err());
    }

    #[test]
    fn passkey_metadata_defaults_closed() {
        let (counter, transports, aaguid, backup_eligible, backup_state, user_verified) =
            passkey_metadata(&serde_json::json!({}));
        assert_eq!(counter, 0);
        assert!(transports.is_empty());
        assert_eq!(aaguid, None);
        assert!(!backup_eligible);
        assert!(!backup_state);
        assert!(!user_verified);
    }

    #[test]
    fn passkey_metadata_reads_credential_projection() {
        let value = serde_json::json!({
            "cred": {
                "counter": 4,
                "transports": ["usb", "internal"],
                "backup_eligible": true,
                "backup_state": false,
                "user_verified": true
            }
        });
        assert_eq!(
            passkey_metadata(&value),
            (
                4,
                vec!["usb".to_owned(), "internal".to_owned()],
                None,
                true,
                false,
                true
            )
        );
    }

    #[test]
    fn passkey_label_is_trimmed_and_bounded() {
        assert_eq!(
            normalize_label(Some("  Windows Hello  ".to_owned())).unwrap(),
            Some("Windows Hello".to_owned())
        );
        assert_eq!(normalize_label(Some("  ".to_owned())).unwrap(), None);
        assert!(matches!(
            normalize_label(Some("密".repeat(MAX_LABEL_CHARS + 1))),
            Err(WebauthnError::InvalidLabel)
        ));
    }

    #[test]
    fn signature_counter_never_rolls_back_or_repeats() {
        assert!(counter_transition_is_valid(0, 0));
        assert!(counter_transition_is_valid(0, 1));
        assert!(counter_transition_is_valid(5, 6));
        assert!(!counter_transition_is_valid(5, 5));
        assert!(!counter_transition_is_valid(7, 6));
        assert!(!counter_transition_is_valid(1, 0));
    }

    #[tokio::test]
    async fn durable_ceremony_is_cross_instance_bound_and_single_use() {
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let now = Utc::now();
        let account_id = Uuid::now_v7();
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO users (id, localpart, created_at) VALUES ($1, $2, $3)")
            .bind::<DieselUuid, _>(account_id)
            .bind::<Text, _>(format!("passkey-test-{}", Ulid::from(account_id)))
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);

        let origin = url::Url::parse("https://auth.example.com").unwrap();
        let first =
            PgWebauthnService::new("auth.example.com", &origin, "Arkret", pool.clone()).unwrap();
        let second =
            PgWebauthnService::new("auth.example.com", &origin, "Arkret", pool.clone()).unwrap();

        let id = first
            .insert_ceremony(
                Ulid::from(account_id),
                REGISTRATION_KIND,
                "browser-a",
                &serde_json::json!({ "nonce": "one" }),
                now,
            )
            .await
            .unwrap();
        let wrong_browser = second
            .consume_ceremony::<serde_json::Value>(id, REGISTRATION_KIND, "browser-b", now)
            .await;
        assert!(matches!(wrong_browser, Err(WebauthnError::NoChallenge(_))));

        let state = second
            .consume_ceremony::<serde_json::Value>(id, REGISTRATION_KIND, "browser-a", now)
            .await
            .unwrap();
        assert_eq!(state.1, serde_json::json!({ "nonce": "one" }));
        let replay = first
            .consume_ceremony::<serde_json::Value>(id, REGISTRATION_KIND, "browser-a", now)
            .await;
        assert!(matches!(replay, Err(WebauthnError::NoChallenge(_))));

        let purpose_bound = first
            .insert_ceremony(
                Ulid::from(account_id),
                REGISTRATION_KIND,
                "browser-a",
                &serde_json::json!({ "nonce": "purpose" }),
                now,
            )
            .await
            .unwrap();
        let wrong_purpose = second
            .consume_ceremony::<serde_json::Value>(
                purpose_bound,
                AUTHENTICATION_KIND,
                "browser-a",
                now,
            )
            .await;
        assert!(matches!(wrong_purpose, Err(WebauthnError::NoChallenge(_))));
        second
            .consume_ceremony::<serde_json::Value>(
                purpose_bound,
                REGISTRATION_KIND,
                "browser-a",
                now,
            )
            .await
            .unwrap();

        let parallel_a = first
            .insert_ceremony(
                Ulid::from(account_id),
                AUTHENTICATION_KIND,
                "browser-a",
                &serde_json::json!({ "nonce": "two" }),
                now,
            )
            .await
            .unwrap();
        let parallel_b = first
            .insert_ceremony(
                Ulid::from(account_id),
                AUTHENTICATION_KIND,
                "browser-a",
                &serde_json::json!({ "nonce": "three" }),
                now,
            )
            .await
            .unwrap();
        assert_ne!(parallel_a, parallel_b);
        for ceremony_id in [parallel_a, parallel_b] {
            second
                .consume_ceremony::<serde_json::Value>(
                    ceremony_id,
                    AUTHENTICATION_KIND,
                    "browser-a",
                    now,
                )
                .await
                .unwrap();
        }

        let expired = first
            .insert_ceremony(
                Ulid::from(account_id),
                AUTHENTICATION_KIND,
                "browser-a",
                &serde_json::json!({ "nonce": "expired" }),
                now,
            )
            .await
            .unwrap();
        let expired_result = second
            .consume_ceremony::<serde_json::Value>(
                expired,
                AUTHENTICATION_KIND,
                "browser-a",
                now + CHALLENGE_TTL + Duration::seconds(1),
            )
            .await;
        assert!(matches!(expired_result, Err(WebauthnError::NoChallenge(_))));

        let credential_a = Ulid::generate();
        let credential_b = Ulid::generate();
        let mut conn = pool.get().await.unwrap();
        for (id, credential_id) in [
            (credential_a, b"credential-a".as_slice()),
            (credential_b, b"credential-b".as_slice()),
        ] {
            diesel::sql_query(
                r"
                INSERT INTO webauthn_credentials (
                    id, account_id, credential_id, public_key, created_at
                ) VALUES ($1, $2, $3, $4, $5)
                ",
            )
            .bind::<DieselUuid, _>(Uuid::from(id))
            .bind::<DieselUuid, _>(account_id)
            .bind::<Bytea, _>(credential_id)
            .bind::<Jsonb, _>(serde_json::json!({}))
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        drop(conn);

        let (revoke_a, revoke_b) = tokio::join!(
            first.revoke(Ulid::from(account_id), credential_a, now),
            second.revoke(Ulid::from(account_id), credential_b, now)
        );
        assert!(
            matches!(
                (&revoke_a, &revoke_b),
                (Ok(()), Err(WebauthnError::LastCredential))
                    | (Err(WebauthnError::LastCredential), Ok(()))
            ),
            "concurrent last-passkey protection must allow exactly one revoke: {revoke_a:?}, {revoke_b:?}"
        );
        let remaining = if revoke_a.is_ok() {
            credential_b
        } else {
            credential_a
        };
        assert!(matches!(
            first.revoke(Ulid::from(account_id), remaining, now).await,
            Err(WebauthnError::LastCredential)
        ));

        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("DELETE FROM users WHERE id = $1")
            .bind::<DieselUuid, _>(account_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }
}
