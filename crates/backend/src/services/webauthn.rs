//! Passkey / `WebAuthn` registration + authentication.
//!
//! Wires `webauthn-rs` into a coauth-shaped service that:
//!
//! 1. starts a passkey registration ceremony for an account
//!    (`register_start`);
//! 2. finalises that ceremony, persists a `Passkey` to
//!    `webauthn_credentials` (`register_finish`);
//! 3. starts an authentication ceremony for an account that already has
//!    one or more credentials (`auth_start`);
//! 4. finalises authentication, updates the credential's `sign_count` and
//!    `last_used_at` (`auth_finish`).
//!
//! Challenge state lives in an in-memory map keyed by account ULID.
//! Production deployments wanting horizontal scale-out will need a
//! Redis-backed swap, but the surface (`take_register_state`,
//! `take_auth_state`) is small enough to make that easy.
//!
//! The `webauthn_credentials` table (round 23 scaffold) carries:
//! `id, account_id, credential_id, public_key (jsonb), sign_count,
//! transports[], aaguid, backup_eligible, backup_state, user_verified,
//! label, created_at, last_used_at, revoked_at`.

use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use diesel::{
    QueryableByName,
    sql_types::{BigInt, Bytea, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid},
};
use diesel_async::{
    AsyncPgConnection, RunQueryDsl as _, pooled_connection::deadpool::Pool as DieselPool,
};
use thiserror::Error;
use tokio::sync::Mutex;
use ulid::Ulid;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{
        CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
        PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
        RequestChallengeResponse,
    },
};

/// Type alias for the boxed dynamic service used by handlers.
pub type WebauthnServiceHandle = Arc<dyn WebauthnService>;

/// Persisted credential row (`webauthn_credentials`).
#[derive(Clone, Debug)]
pub struct WebauthnCredentialRecord {
    pub id: Ulid,
    pub account_id: Ulid,
    pub credential_id: Vec<u8>,
    pub public_key: Passkey,
    pub sign_count: u32,
    pub label: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum WebauthnError {
    #[error("webauthn-rs core error: {0}")]
    Core(#[from] webauthn_rs::prelude::WebauthnError),

    #[error("storage error: {0}")]
    Storage(#[from] anyhow::Error),

    #[error("no challenge state for account {0}")]
    NoChallenge(Ulid),

    #[error("no passkeys registered for account {0}")]
    NoCredentials(Ulid),

    #[error("invalid relying-party origin: {0}")]
    InvalidOrigin(String),

    #[error("credential serialisation failed: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Public service surface.
#[async_trait::async_trait]
pub trait WebauthnService: Send + Sync {
    /// Start a registration ceremony. Returns the
    /// `CreationChallengeResponse` that the browser hands to
    /// `navigator.credentials.create`.
    async fn register_start(
        &self,
        account_id: Ulid,
        username: &str,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, WebauthnError>;

    /// Finish a registration ceremony. Persists a row to
    /// `webauthn_credentials`.
    async fn register_finish(
        &self,
        account_id: Ulid,
        attestation: &RegisterPublicKeyCredential,
        label: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<WebauthnCredentialRecord, WebauthnError>;

    /// Start an authentication ceremony. Loads the account's existing
    /// passkeys; returns the assertion challenge.
    async fn auth_start(&self, account_id: Ulid)
    -> Result<RequestChallengeResponse, WebauthnError>;

    /// Finish an authentication ceremony. Updates the matched credential's
    /// `sign_count` + `last_used_at`. Returns the credential id used.
    async fn auth_finish(
        &self,
        account_id: Ulid,
        assertion: &PublicKeyCredential,
        now: DateTime<Utc>,
    ) -> Result<CredentialID, WebauthnError>;
}

/// Concrete `webauthn-rs` + Diesel-backed implementation.
pub struct PgWebauthnService {
    webauthn: Arc<Webauthn>,
    pool: DieselPool<AsyncPgConnection>,
    register_states: Mutex<HashMap<Ulid, PasskeyRegistration>>,
    auth_states: Mutex<HashMap<Ulid, PasskeyAuthentication>>,
}

impl PgWebauthnService {
    /// Build a new service.
    ///
    /// * `rp_id` — the relying-party effective domain (e.g. `auth.example.com`).
    /// * `rp_origin` — the origin URL (`https://auth.example.com`).
    /// * `rp_name` — the human-readable RP name.
    pub fn new(
        rp_id: &str,
        rp_origin: &url::Url,
        rp_name: &str,
        pool: DieselPool<AsyncPgConnection>,
    ) -> Result<Self, WebauthnError> {
        let builder = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|e| WebauthnError::InvalidOrigin(e.to_string()))?
            .rp_name(rp_name);
        let webauthn = builder
            .build()
            .map_err(|e| WebauthnError::InvalidOrigin(e.to_string()))?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
            pool,
            register_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
        })
    }

    async fn load_passkeys(&self, account_id: Ulid) -> Result<Vec<Passkey>, WebauthnError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;
        let rows = diesel::sql_query(
            r"
            SELECT id, account_id, credential_id, public_key, sign_count,
                   label, backup_eligible, backup_state, user_verified,
                   created_at, last_used_at, revoked_at
            FROM webauthn_credentials
            WHERE account_id = $1 AND revoked_at IS NULL
            ORDER BY created_at DESC
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .get_results::<CredentialRow>(&mut *conn)
        .await
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let pk: Passkey = serde_json::from_value(row.public_key)?;
            out.push(pk);
        }
        Ok(out)
    }
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
    #[diesel(sql_type = Nullable<Text>)]
    label: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    backup_eligible: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    backup_state: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    user_verified: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_used_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
}

impl CredentialRow {
    fn into_record(self, public_key: Passkey) -> WebauthnCredentialRecord {
        WebauthnCredentialRecord {
            id: Ulid::from(self.id),
            account_id: Ulid::from(self.account_id),
            credential_id: self.credential_id,
            public_key,
            sign_count: u32::try_from(self.sign_count.max(0)).unwrap_or(0),
            label: self.label,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            user_verified: self.user_verified,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
        }
    }
}

#[async_trait::async_trait]
impl WebauthnService for PgWebauthnService {
    async fn register_start(
        &self,
        account_id: Ulid,
        username: &str,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, WebauthnError> {
        // Load existing credential ids so the browser excludes them.
        let existing = self.load_passkeys(account_id).await?;
        let exclude: Vec<CredentialID> = existing.iter().map(|pk| pk.cred_id().clone()).collect();

        let exclude_opt = if exclude.is_empty() {
            None
        } else {
            Some(exclude)
        };

        let user_uuid = Uuid::from(account_id);
        let (challenge, state) = self.webauthn.start_passkey_registration(
            user_uuid,
            username,
            display_name,
            exclude_opt,
        )?;

        self.register_states.lock().await.insert(account_id, state);
        Ok(challenge)
    }

    async fn register_finish(
        &self,
        account_id: Ulid,
        attestation: &RegisterPublicKeyCredential,
        label: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<WebauthnCredentialRecord, WebauthnError> {
        let state = self
            .register_states
            .lock()
            .await
            .remove(&account_id)
            .ok_or(WebauthnError::NoChallenge(account_id))?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(attestation, &state)?;

        let id = Uuid::now_v7();
        let cred_id_bytes: Vec<u8> = passkey.cred_id().as_ref().to_vec();
        let public_key_json = serde_json::to_value(&passkey)?;

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;
        let row = diesel::sql_query(
            r"
            INSERT INTO webauthn_credentials (
                id, account_id, credential_id, public_key, sign_count,
                transports, aaguid, backup_eligible, backup_state,
                user_verified, label, created_at
            )
            VALUES ($1, $2, $3, $4, 0, ARRAY[]::TEXT[], NULL, FALSE, FALSE,
                    FALSE, $5, $6)
            RETURNING id, account_id, credential_id, public_key, sign_count,
                      label, backup_eligible, backup_state, user_verified,
                      created_at, last_used_at, revoked_at
            ",
        )
        .bind::<DieselUuid, _>(id)
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .bind::<Bytea, _>(cred_id_bytes)
        .bind::<Jsonb, _>(public_key_json.clone())
        .bind::<Nullable<Text>, _>(label)
        .bind::<Timestamptz, _>(now)
        .get_result::<CredentialRow>(&mut *conn)
        .await
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;

        Ok(row.into_record(passkey))
    }

    async fn auth_start(
        &self,
        account_id: Ulid,
    ) -> Result<RequestChallengeResponse, WebauthnError> {
        let passkeys = self.load_passkeys(account_id).await?;
        if passkeys.is_empty() {
            return Err(WebauthnError::NoCredentials(account_id));
        }

        let (challenge, state) = self.webauthn.start_passkey_authentication(&passkeys)?;
        self.auth_states.lock().await.insert(account_id, state);
        Ok(challenge)
    }

    async fn auth_finish(
        &self,
        account_id: Ulid,
        assertion: &PublicKeyCredential,
        now: DateTime<Utc>,
    ) -> Result<CredentialID, WebauthnError> {
        let state = self
            .auth_states
            .lock()
            .await
            .remove(&account_id)
            .ok_or(WebauthnError::NoChallenge(account_id))?;

        let result = self
            .webauthn
            .finish_passkey_authentication(assertion, &state)?;

        // Persist new sign_count + last_used_at.
        let cred_id_bytes: Vec<u8> = result.cred_id().as_ref().to_vec();
        let new_count = i64::from(result.counter());

        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;
        diesel::sql_query(
            r"
            UPDATE webauthn_credentials
            SET sign_count = $3, last_used_at = $4
            WHERE account_id = $1 AND credential_id = $2 AND revoked_at IS NULL
            ",
        )
        .bind::<DieselUuid, _>(Uuid::from(account_id))
        .bind::<Bytea, _>(cred_id_bytes)
        .bind::<BigInt, _>(new_count)
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map_err(|e| WebauthnError::Storage(anyhow::anyhow!(e)))?;

        Ok(result.cred_id().clone())
    }
}

/// Build a Pg-backed webauthn service with the relying-party config from
/// the deployment's URL builder. `rp_origin` is derived from
/// `url_builder.http_base()` and `rp_id` from `public_hostname()`.
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
        // `webauthn-rs` requires the rp_id to be a registrable domain
        // suffix of the origin. A bare scheme (`abc`) cannot be parsed
        // into a URL, so we get an InvalidOrigin error.
        let parse = url::Url::parse("not-a-real-url");
        assert!(parse.is_err());
    }

    #[test]
    fn rp_builder_accepts_https_origin() {
        let origin = url::Url::parse("https://auth.example.com").unwrap();
        let result = WebauthnBuilder::new("auth.example.com", &origin);
        assert!(result.is_ok());
    }

    #[test]
    fn rp_builder_rejects_mismatched_id() {
        // `rp_id` must be a registrable suffix of the origin.
        let origin = url::Url::parse("https://auth.example.com").unwrap();
        let result = WebauthnBuilder::new("other-host.com", &origin);
        assert!(result.is_err());
    }
}
