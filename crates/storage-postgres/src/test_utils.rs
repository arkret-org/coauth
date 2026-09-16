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

/// Build a cryptographically valid WebVH principal registration anchor for
/// storage and handler tests. Human account registration supports WebVH only.
pub fn principal_registration_anchor_fixture(
    local_id: &str,
    root_seed: [u8; 32],
) -> arkret_models_identity::PrincipalRegistrationAnchor {
    let endpoint = url::Url::parse("https://registration.example/").expect("fixture endpoint");
    let next_root_public_key_multibase = "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";
    let inception = arkret_signatures::webvh::prepare_principal_inception(
        &arkret_signatures::webvh::PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id,
            also_known_as: &[],
            version_time: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            root_seed: &root_seed,
            next_root_public_key_multibase,
            witness_policy: None,
        },
    )
    .expect("valid WebVH inception fixture");
    arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation: Box::new(inception.submit_body),
        log_entries: vec![
            serde_json::from_value(inception.log_entry.clone()).expect("typed log entry"),
        ],
        witness_records: Vec::new(),
        normalized_did_document: serde_json::from_value(inception.log_entry["state"].clone())
            .expect("typed DID document"),
    }
}

/// Session-scoped Postgres advisory-lock key that serializes every test
/// holding a [`TestDatabase`]. Postgres releases a session-level advisory lock
/// when the owning session closes, so the guard needs no async drop.
const TEST_DATABASE_ADVISORY_LOCK_KEY: i64 = 0x0063_6f61_7574_68db;

/// The migration this repository rewrites in place, embedded so its bytes
/// can be fingerprinted.
const INITIAL_MIGRATION_SQL: &str = include_str!("../migrations/00000000000000_initial/up.sql");

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
/// Returns `Some(database)` when `DATABASE_URL` names a scratch Postgres.
///
/// Without `DATABASE_URL` this **panics** by default. Returning `None`
/// silently made `cargo test --workspace` green on a machine with no
/// database while every Postgres-backed case had run zero assertions, which
/// is the opposite of soland's `TestDatabase::lease_blocking()` in the same
/// workspace and hid the real state of this crate for as long as it existed.
///
/// Set `COAUTH_SKIP_POSTGRES_TESTS=1` to accept the skip deliberately; each
/// skipped case then prints one `SKIP(no DATABASE_URL)` line naming itself,
/// so the count of what did not run is visible in the output instead of
/// being indistinguishable from a pass.
///
/// Migrations are expected to already have been applied to the test database.
///
/// # Panics
///
/// Panics when `DATABASE_URL` is unset and the skip has not been opted into,
/// and when it is set but the database cannot be reached or reset; a test
/// database that cannot be isolated must fail loudly rather than run against
/// leftover rows.
#[must_use = "tests should early-return when this returns None"]
pub async fn setup_test_pool() -> Option<TestDatabase> {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(database_url) => database_url,
        Err(_) => {
            assert!(
                std::env::var_os("COAUTH_SKIP_POSTGRES_TESTS").is_some(),
                "DATABASE_URL is unset, so this case cannot exercise anything. Point it at a \
                 scratch database (`just db-migrate` against it first), or set \
                 COAUTH_SKIP_POSTGRES_TESTS=1 to accept that every Postgres-backed case is \
                 skipped."
            );
            eprintln!(
                "SKIP(no DATABASE_URL): {}",
                std::thread::current().name().unwrap_or("<unnamed test>")
            );
            return None;
        }
    };

    let mut lock = AsyncPgConnection::establish(&database_url)
        .await
        .expect("could not connect to the test database");
    diesel::sql_query(format!(
        "SELECT pg_advisory_lock({TEST_DATABASE_ADVISORY_LOCK_KEY})"
    ))
    .execute(&mut lock)
    .await
    .expect("could not acquire the test database advisory lock");
    verify_schema_fingerprint(&mut lock, &database_url).await;
    reset_database(&mut lock).await;

    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
    let pool = Pool::builder(manager)
        .max_size(5)
        .build()
        .expect("could not build test pool");
    Some(TestDatabase { pool, _lock: lock })
}

#[derive(diesel::QueryableByName)]
struct FingerprintRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    fingerprint: String,
}

/// Refuse a test database whose schema predates the current migration.
///
/// coauth does **not** apply migrations from the test harness ([`setup_test_pool`]
/// documents that they "are expected to already have been applied"), and this
/// repository rewrites its single migration in place rather than adding a new
/// one -- so a database prepared before an edit keeps its old schema silently.
/// Measured on 2026-09-05, that produced 73 failures reading `字段 X 不存在` /
/// `关系 Y 不存在` spread across unrelated modules: a shape that reads like a
/// broad functional regression and costs a full debugging cycle before anyone
/// suspects the database.
///
/// The first connection to a database records the fingerprint; every later one
/// compares. That misses only the first transition on a database created before
/// this fence existed -- from then on an edit is caught on the next run.
///
/// soland solves the same problem differently because its harness *does* create
/// databases: there the fingerprint is part of the leased slot name, so a stale
/// slot is never a candidate. Here nothing can create the database for you, so
/// the honest move is to fail with the commands that fix it.
async fn verify_schema_fingerprint(connection: &mut AsyncPgConnection, database_url: &str) {
    let current: String = arkret_canonical::sha256_hex(INITIAL_MIGRATION_SQL.as_bytes())
        .chars()
        .take(8)
        .collect();
    diesel::sql_query(
        "CREATE TABLE IF NOT EXISTS coauth_test_schema_fingerprint (
             singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
             fingerprint text NOT NULL)",
    )
    .execute(connection)
    .await
    .expect("could not create the test schema fingerprint table");
    let recorded = diesel::sql_query(
        "SELECT fingerprint FROM coauth_test_schema_fingerprint WHERE singleton = TRUE",
    )
    .get_results::<FingerprintRow>(connection)
    .await
    .expect("could not read the test schema fingerprint");
    // `.first()` here would resolve to diesel's `LimitDsl::first`, not the
    // slice method: `RunQueryDsl` is in scope for this module.
    match recorded.into_iter().next() {
        None => {
            diesel::sql_query(
                "INSERT INTO coauth_test_schema_fingerprint (singleton, fingerprint)
                 VALUES (true, $1)",
            )
            .bind::<diesel::sql_types::Text, _>(current)
            .execute(connection)
            .await
            .expect("could not record the test schema fingerprint");
        }
        Some(row) if row.fingerprint == current => {}
        Some(row) => panic!(
            "the test database at {database_url} was migrated under schema {}, but \
             migrations/00000000000000_initial/up.sql now fingerprints as {current}. coauth \
             rewrites that migration in place and never re-applies it, so this database keeps \
             its old columns; the failures you would otherwise see read `... 不存在` and are \
             not regressions. Recreate the database from the current up.sql, apply the diesel \
             ledger row for 00000000000000, and point DATABASE_URL at it -- \
             arkret-work/memory/coauth-postgres-face-only-runs-with-database-url.md has the \
             exact commands.",
            row.fingerprint
        ),
    }
}

#[derive(diesel::QueryableByName)]
struct QualifiedTableName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    qualified_name: String,
}

/// Empty every application table. The diesel migration ledger and this
/// harness's own fingerprint row are preserved: truncating either would
/// invalidate the already-applied schema or disarm the staleness fence.
async fn reset_database(connection: &mut AsyncPgConnection) {
    let tables = diesel::sql_query(
        "SELECT format('%I.%I', schemaname, tablename) AS qualified_name \
         FROM pg_tables \
         WHERE schemaname = 'public' AND tablename NOT IN ('__diesel_schema_migrations', 'coauth_test_schema_fingerprint')",
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
/// Panics when `did` is not a complete DID this profile can project.
#[must_use]
pub fn account_authority_core_id(did: &str) -> arkret_identifiers::DidCoreId {
    arkret_identifiers::project_did_to_core_id(
        &arkret_identifiers::Did::new(did.to_owned()).unwrap(),
    )
    .unwrap()
}

/// Public account-authority coordinate for a binding fixture.
#[must_use]
pub fn account_id(principal_id: &str, station_id: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(principal_id).unwrap(),
        arkret_identifiers::DidCoreId::new(station_id).unwrap(),
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

/// Seed of the deterministic Account Authority key that signs fixture receipts.
///
/// Public by construction: nothing may trust a receipt carrying this
/// signature outside a test, which is why `test_utils` is feature-gated.
const FIXTURE_ACCOUNT_AUTHORITY_SEED: [u8; 32] = [0x9a; 32];

/// The public half of [`FIXTURE_ACCOUNT_AUTHORITY_SEED`], for tests that
/// verify a fixture receipt rather than merely persist one.
#[must_use]
pub fn fixture_account_authority_verifying_key() -> [u8; 32] {
    fixture_account_authority_signer("did:web:fixture.example#service-key")
        .verifying_key()
        .to_bytes()
}

fn fixture_account_authority_signer(
    verification_method: &str,
) -> arkret_signatures::Ed25519DetachedJwsSigner {
    arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        FIXTURE_ACCOUNT_AUTHORITY_SEED,
        verification_method.to_owned(),
    )
}

/// Account binding receipt carrying a real Account Authority signature.
///
/// The proof is a genuine detached JWS over `canonical_proof_binding_bytes`,
/// the same transcript `sign_account_binding_receipt` produces in the
/// register handler. It used to be the literal `"test-detached-jws"`, which is
/// not even a compact JWS: `event-envelope.schema.json#/$defs/proof` pins
/// `jws` to `^[A-Za-z0-9_-]+\.(?:[A-Za-z0-9_-]+)?\.[A-Za-z0-9_-]+$`, and
/// `PayloadProof::validate` -- unlike `ProducerEventProof::validate` -- does
/// not enforce that grammar, so the wire-invalid value survived every check
/// this fixture passes through.
///
/// # Panics
///
/// Panics when the fixture inputs do not produce a shape-valid receipt.
#[must_use]
pub fn account_binding_receipt(
    account_authority_did: &str,
    did: arkret_identifiers::Did,
    version_id: &str,
    _log_head_digest: arkret_identifiers::Hash,
) -> arkret_models_identity::AccountBindingReceipt {
    // The receipt's `principal_id` is the projection of its own `did`:
    // `AccountBindingReceipt::validate_shape` requires exactly that, so a
    // receipt cannot express a mismatch between the two. Fixtures that need a
    // mismatched *binding* express it in `VerifiedPrincipalDidBindingInput`
    // instead, which is where `add_verified` compares the two and where the
    // case under test expects the rejection.
    let principal_id = arkret_identifiers::project_did_to_core_id(&did)
        .expect("a fixture receipt DID projects to a core id");
    let issued_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixture timestamp")
        .with_timezone(&chrono::Utc);
    let mut receipt = arkret_models_identity::AccountBindingReceipt {
        binding_state: arkret_models_identity::AccountBindingState::Bound,
        binding_kind: arkret_models_identity::AccountBindingKind::IdentityCreation,
        account_authority_id: account_authority_core_id(account_authority_did),
        account_subject: arkret_identifiers::Hash::new(format!("sha256:{}", "1".repeat(64)))
            .unwrap(),
        principal_id,
        did,
        did_version_id: version_id.to_owned(),
        control_key_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "2".repeat(64)))
            .unwrap(),
        identity_creation_lease_id: Some("test-identity-creation-lease".to_owned()),
        lease_fence: Some(1),
        operation_status: arkret_models_identity::IdentityCreationOperationStatus::Accepted,
        registration_anchor_digest: arkret_identifiers::Hash::new(format!(
            "sha256:{}",
            "3".repeat(64)
        ))
        .unwrap(),
        issued_at,
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            // The receipt proof controller MUST be the account authority.
            verification_method: arkret_wire::DidUrl::new(format!(
                "{account_authority_did}#service-key"
            ))
            .unwrap(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        },
    };
    receipt.proof.payload_digest = receipt.canonical_payload_digest().unwrap();
    let signer = fixture_account_authority_signer(receipt.proof.verification_method.as_str());
    receipt.proof.jws = signer.sign_detached_jws(
        &receipt
            .canonical_proof_binding_bytes()
            .expect("a self-consistent fixture receipt has a proof binding"),
    );
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
    account_authority_did: &str,
    audience: impl Into<String>,
    principal_id: String,
    key_log_head: arkret_identifiers::Hash,
) -> VerifiedPrincipalDidBindingInput {
    let audience = audience.into();
    let method_specific_id = principal_id
        .strip_prefix("ak:did_core:webvh:")
        .expect("webvh test principal core");
    let did = format!("did:webvh:{method_specific_id}:fixture.example");
    let account_id = account_id(&principal_id, &audience);
    let audience_id = arkret_identifiers::DidCoreId::new(audience).unwrap();
    let principal_id = arkret_identifiers::DidCoreId::new(principal_id).unwrap();
    let did = arkret_identifiers::Did::new(did).unwrap();
    VerifiedPrincipalDidBindingInput {
        audience_id: audience_id.clone(),
        principal_id: principal_id.clone(),
        key_log_head: key_log_head.clone(),
        verified_did: did.clone(),
        verified_version_id: "1-fixture".to_owned(),
        binding_receipt: account_binding_receipt(
            account_authority_did,
            did,
            "1-fixture",
            key_log_head,
        ),
        // The accepted service identity is the Station the binding is
        // scoped to; the Account Authority that accepted it is carried by the
        // receipt.
        accepted_id: audience_id,
        binding_version: 1,
        binding_receipt_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "b".repeat(64)))
            .unwrap(),
        account_id,
        principal_control_realm_id: principal_control_realm_id(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The receipt fixture carries a real Account Authority signature, not a
    /// placeholder: it verifies, and it stops verifying when one byte of the
    /// transcript it covers changes.
    #[test]
    fn the_fixture_receipt_proof_verifies_and_one_changed_byte_breaks_it() {
        let receipt = account_binding_receipt(
            "did:webvh:zaccountauthority:account.example",
            arkret_identifiers::Did::new("did:webvh:zfixturereceipt:principal.example").unwrap(),
            "1-fixture",
            arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        );
        let material = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: fixture_account_authority_verifying_key().to_vec(),
        };
        let transcript = receipt
            .canonical_proof_binding_bytes()
            .expect("the fixture receipt has a proof binding");

        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(receipt.proof.jws.as_str(), &transcript, &material)
            .expect("the fixture receipt proof must really verify");

        let mut tampered = transcript.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(receipt.proof.jws.as_str(), &tampered, &material)
            .expect_err("one changed transcript byte must invalidate the receipt proof");
    }
}
