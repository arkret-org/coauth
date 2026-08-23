// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Test utilities: temporary test databases and the shared principal-DID
//! binding fixtures used by both this crate's repository tests and the
//! `coauth-backend` handler tests.

use std::ops::Deref;

use coauth_data::user::VerifiedPrincipalDidBindingInput;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};

/// Session-scoped Postgres advisory-lock key that serializes every test
/// holding a [`TestDatabase`]. Postgres releases a session-level advisory lock
/// when the owning session closes, so the guard needs no async drop.
const TEST_DATABASE_ADVISORY_LOCK_KEY: i64 = 0x0063_6f61_7574_68db;

/// Exclusive handle on the shared test database.
///
/// Holding one guarantees two things for the duration of a test:
///
/// * no other test in any process may hold one at the same time, and
/// * every application table starts empty.
///
/// Both are required because the repository tests assert on global state
/// (`count(all) == 0`) and seed deterministic identifiers from fixed RNG
/// seeds, so two tests sharing a populated database collide on `users_pkey`
/// and on handle uniqueness instead of exercising their assertions.
pub struct TestDatabase {
    pool: Pool<AsyncPgConnection>,
    /// Owns the advisory lock. Dropping it closes the session and releases
    /// the lock for the next test.
    _lock: AsyncPgConnection,
}

impl Deref for TestDatabase {
    type Target = Pool<AsyncPgConnection>;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

/// Take exclusive ownership of the test database and return a connection pool
/// for it.
///
/// Returns `Some(database)` when the `DATABASE_URL` env var is set (typical CI
/// or a developer with a local Postgres available), or `None` when it is
/// not set. Tests requiring a live Postgres should early-return on `None`,
/// e.g.:
///
/// ```ignore
/// let Some(pool) = setup_test_pool().await else { return; };
/// ```
///
/// This makes the test suite's "happy path" — `cargo test --workspace`
/// without any environment — actually pass, while still fully exercising
/// the Postgres path under CI. Migrations are expected to already have
/// been applied to the test database.
///
/// # Panics
///
/// Panics when `DATABASE_URL` is set but the database cannot be reached or
/// reset; a test database that cannot be isolated must fail loudly rather
/// than run against leftover rows.
#[must_use = "tests should early-return when this returns None"]
pub async fn setup_test_pool() -> Option<TestDatabase> {
    let database_url = std::env::var("DATABASE_URL").ok()?;

    let mut lock = AsyncPgConnection::establish(&database_url)
        .await
        .expect("could not connect to the test database");
    diesel::sql_query(format!(
        "SELECT pg_advisory_lock({TEST_DATABASE_ADVISORY_LOCK_KEY})"
    ))
    .execute(&mut lock)
    .await
    .expect("could not acquire the test database advisory lock");
    reset_database(&mut lock).await;

    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
    let pool = Pool::builder(manager)
        .max_size(5)
        .build()
        .expect("could not build test pool");
    Some(TestDatabase { pool, _lock: lock })
}

#[derive(diesel::QueryableByName)]
struct QualifiedTableName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    qualified_name: String,
}

/// Empty every application table. The diesel migration ledger is preserved so
/// the already-applied schema stays valid.
async fn reset_database(connection: &mut AsyncPgConnection) {
    let tables = diesel::sql_query(
        "SELECT format('%I.%I', schemaname, tablename) AS qualified_name \
         FROM pg_tables \
         WHERE schemaname = 'public' AND tablename <> '__diesel_schema_migrations'",
    )
    .get_results::<QualifiedTableName>(connection)
    .await
    .expect("could not enumerate the test database tables");
    if tables.is_empty() {
        return;
    }
    let names = tables
        .iter()
        .map(|table| table.qualified_name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    diesel::sql_query(format!("TRUNCATE TABLE {names} RESTART IDENTITY CASCADE"))
        .execute(connection)
        .await
        .expect("could not reset the test database");
}

/// Deterministic principal core DID plus key-log head for a binding fixture.
///
/// # Panics
///
/// Panics when the fixture digest is not a valid hash.
#[must_use]
pub fn principal_binding_test_material(label: &str) -> (String, arkret_identifiers::Hash) {
    let principal_id = format!("ak:did_core:webvh:z{label}");
    let key_log_head = arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    (principal_id, key_log_head)
}

/// Stable identity core of an Account Authority's complete DID.
///
/// # Panics
///
/// Panics when `full_id` is not a complete DID this profile can project.
#[must_use]
pub fn account_authority_core_id(full_id: &str) -> arkret_identifiers::DidCoreId {
    arkret_identifiers::project_full_id_to_core_id(
        &arkret_identifiers::DidFullId::new(full_id.to_owned()).unwrap(),
    )
    .unwrap()
}

/// Public account-authority coordinate for a binding fixture.
#[must_use]
pub fn principal_authority(
    principal_id: &str,
    principal_server_id: &str,
) -> arkret_wire::PrincipalAuthorityKey {
    arkret_wire::PrincipalAuthorityKey::new(
        arkret_identifiers::DidCoreId::new(principal_id).unwrap(),
        arkret_identifiers::DidCoreId::new(principal_server_id).unwrap(),
    )
}

/// Fixed principal control realm accepted by the binding fixtures.
#[must_use]
pub fn principal_control_realm_id() -> arkret_identifiers::RealmId {
    arkret_identifiers::RealmId::from_event_id(&arkret_identifiers::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x42; 32],
    ))
}

/// Shape-valid authority-signed account binding receipt for fixtures.
///
/// # Panics
///
/// Panics when the fixture inputs do not produce a shape-valid receipt.
#[must_use]
pub fn account_binding_receipt(
    account_authority_full_id: &str,
    principal_id: arkret_identifiers::DidCoreId,
    full_id: arkret_identifiers::DidFullId,
    version_id: &str,
    head_event_digest: arkret_identifiers::Hash,
) -> arkret_models_identity::AccountBindingReceipt {
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture timestamp")
        .with_timezone(&chrono::Utc);
    let mut receipt = arkret_models_identity::AccountBindingReceipt {
        binding_state: arkret_models_identity::AccountBindingState::Bound,
        binding_kind: arkret_models_identity::AccountBindingKind::IdentityCreation,
        account_authority_id: account_authority_core_id(account_authority_full_id),
        account_subject: arkret_identifiers::Hash::new(format!("sha256:{}", "1".repeat(64)))
            .unwrap(),
        principal_id,
        full_id,
        did_version_id: version_id.to_owned(),
        control_key_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "2".repeat(64)))
            .unwrap(),
        identity_creation_lease_id: Some("test-identity-creation-lease".to_owned()),
        lease_fence: Some(1),
        operation_status: arkret_models_identity::IdentityCreationOperationStatus::Accepted,
        operation_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "3".repeat(64)))
            .unwrap(),
        head_event_digest,
        issued_at,
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            // The receipt proof controller MUST be the account authority.
            verification_method: arkret_wire::DidUrl::new(format!(
                "{account_authority_full_id}#service-key"
            ))
            .unwrap(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "test-detached-jws".to_owned(),
        },
    };
    receipt.proof.payload_digest = receipt.canonical_payload_digest().unwrap();
    receipt.validate_shape().unwrap();
    receipt
}

/// Accepted principal-DID binding input for one account and audience.
///
/// # Panics
///
/// Panics when `principal_id` is not a `ak:did_core:webvh:` core DID.
#[must_use]
pub fn verified_principal_binding_input(
    account_authority_full_id: &str,
    audience: impl Into<String>,
    principal_id: String,
    key_log_head: arkret_identifiers::Hash,
) -> VerifiedPrincipalDidBindingInput {
    let audience = audience.into();
    let method_specific_id = principal_id
        .strip_prefix("ak:did_core:webvh:")
        .expect("webvh test principal core");
    let full_id = format!("did:webvh:{method_specific_id}:fixture.example");
    let principal_authority = principal_authority(&principal_id, &audience);
    let audience_id = arkret_identifiers::DidCoreId::new(audience).unwrap();
    let principal_id = arkret_identifiers::DidCoreId::new(principal_id).unwrap();
    let full_id = arkret_identifiers::DidFullId::new(full_id).unwrap();
    VerifiedPrincipalDidBindingInput {
        audience: audience_id.clone(),
        principal_id: principal_id.clone(),
        key_log_head: key_log_head.clone(),
        verified_full_id: full_id.clone(),
        verified_version_id: "1-fixture".to_owned(),
        binding_receipt: account_binding_receipt(
            account_authority_full_id,
            principal_id,
            full_id,
            "1-fixture",
            key_log_head,
        ),
        // The accepted service identity is the Principal Server the binding is
        // scoped to; the Account Authority that accepted it is carried by the
        // receipt.
        accepted_service_id: audience_id,
        binding_version: 1,
        binding_frontier_digest: arkret_identifiers::Hash::new(format!(
            "sha256:{}",
            "b".repeat(64)
        ))
        .unwrap(),
        principal_authority,
        principal_control_realm_id: principal_control_realm_id(),
    }
}
