//! Unified helper for writing and verifying admin audit log entries.
//!
//! Signed writers insert
//! the audit row first, then sign the canonical transcript that includes the
//! repository-generated row id and created_at timestamp, and finally update the
//! same row's `audit_signature` column.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::SecondsFormat;
use coauth_data::audit::{AdminOperation, AdminOperationLog, NewAdminOperationLog};
use coauth_data::{BoxRepository, RepositoryAccess, RepositoryError};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::constraints::Constrainable as _;
use coauth_jose::jwa::{AsymmetricVerifyingKey, Signature as JoseSignature};
use coauth_keystore::Keystore;
use arkret_core::canonical::canonical_json_bytes;
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng as _};
use salvo::oapi::ToSchema;
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use signature::{RandomizedSigner as _, Verifier as _};
use ulid::Ulid;
use uuid::Uuid;

const AUDIT_TRANSCRIPT_KIND: &str = "org.arkret.coauth.audit.admin_operation.v1";
const AUDIT_TRANSCRIPT_SCHEMA_VERSION: u32 = 1;

/// Verification state returned on admin audit read/export surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditSignatureStatus {
    /// The row has a signature and the current service public key verifies it.
    Verified,
    /// The row was explicitly written unsigned.
    Unsigned,
    /// The row has a signature, but the signature no longer matches the row.
    Invalid,
    /// The row references a signing key that is not available in this process.
    KeyUnavailable,
}

/// Runtime signing inputs for admin audit helpers.
#[derive(Clone, Copy)]
pub struct AdminAuditSigning<'a> {
    pub keystore: &'a Keystore,
    pub service_did: &'a str,
    pub fail_closed: bool,
}

/// Record an admin operation in the audit log, if the caller is an
/// authenticated admin user.
///
/// When `admin_user` is `None` (e.g. the request was made with a
/// service-level token that has no associated user), the function is a
/// no-op.
pub async fn record_admin_operation(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn coauth_data::Clock,
    admin_user: Option<&coauth_data::User>,
    operation: AdminOperation,
    resource_type: &str,
    resource_id: Option<Ulid>,
    details: serde_json::Value,
) -> Result<(), RepositoryError> {
    if let Some(admin) = admin_user {
        let mut params = NewAdminOperationLog::new(admin.id, operation, resource_type, details);
        if let Some(id) = resource_id {
            params = params.with_resource_id(id);
        }
        repo.audit().add_admin_operation(rng, clock, params).await?;
    }
    Ok(())
}

/// Like [`record_admin_operation`] but signs the persisted row's full
/// canonical transcript with the coauth service signing key.
///
/// When `fail_closed` is false, missing signing keys or signature-update
/// failures leave the row unsigned and the caller continues. Production
/// deployments can set `fail_closed` true to reject the surrounding write when
/// a signed audit row cannot be produced.
pub async fn record_admin_operation_signed(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn coauth_data::Clock,
    keystore: &Keystore,
    service_did: &str,
    fail_closed: bool,
    admin_user: Option<&coauth_data::User>,
    operation: AdminOperation,
    resource_type: &str,
    resource_id: Option<Ulid>,
    details: serde_json::Value,
) -> Result<(), RepositoryError> {
    let Some(admin) = admin_user else {
        return Ok(());
    };

    let mut params = NewAdminOperationLog::new(admin.id, operation, resource_type, details);
    if let Some(id) = resource_id {
        params = params.with_resource_id(id);
    }

    let log = repo.audit().add_admin_operation(rng, clock, params).await?;
    sign_persisted_admin_operation(repo, keystore, service_did, fail_closed, &log).await
}

/// Record a signed service-originated admin audit row.
///
/// Internal service endpoints such as the Personal Agent accountability-grant
/// issuer are authenticated with static service bearers, so there is no
/// `User` row to pass into [`record_admin_operation_signed`]. The audit table
/// does not currently foreign-key `admin_user_id`, so we derive a stable
/// synthetic id from the service DID and keep the actual actor identity in the
/// signed details payload.
pub(crate) async fn record_service_admin_operation_signed(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn coauth_data::Clock,
    keystore: &Keystore,
    service_did: &str,
    fail_closed: bool,
    operation: AdminOperation,
    resource_type: &str,
    resource_id: Option<Ulid>,
    details: serde_json::Value,
) -> Result<(), RepositoryError> {
    let admin_user_id = service_admin_user_id(service_did);
    let mut params = NewAdminOperationLog::new(admin_user_id, operation, resource_type, details);
    if let Some(id) = resource_id {
        params = params.with_resource_id(id);
    }

    let log = repo.audit().add_admin_operation(rng, clock, params).await?;
    sign_persisted_admin_operation(repo, keystore, service_did, fail_closed, &log).await
}

async fn sign_persisted_admin_operation(
    repo: &mut BoxRepository,
    keystore: &Keystore,
    service_did: &str,
    fail_closed: bool,
    log: &AdminOperationLog,
) -> Result<(), RepositoryError> {
    let signature = match sign_admin_operation_log(keystore, service_did, log) {
        Ok(signature) => signature,
        Err(err) if fail_closed => return Err(RepositoryError::from_error(err)),
        Err(err) => {
            tracing::warn!(
                error = %err,
                audit_log_id = %log.id,
                resource_type = %log.resource_type,
                "audit row written unsigned: keystore could not produce a signature"
            );
            return Ok(());
        }
    };

    match repo
        .audit()
        .set_admin_operation_signature(log.id, &signature)
        .await
    {
        Ok(_) => Ok(()),
        Err(err) if fail_closed => Err(err),
        Err(err) => {
            tracing::warn!(
                error = %err,
                audit_log_id = %log.id,
                resource_type = %log.resource_type,
                "audit row written unsigned: signature update failed"
            );
            Ok(())
        }
    }
}

pub(crate) fn service_admin_user_id(service_did: &str) -> Ulid {
    let name = format!("coauth:service-admin:{service_did}");
    let digest = Sha256::digest(name.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ulid::from(Uuid::from_bytes(bytes))
}

/// Verify an admin audit row signature against the current service public keys.
#[must_use]
pub fn verify_admin_operation_signature(
    log: &AdminOperationLog,
    keystore: &Keystore,
    service_did: &str,
) -> AuditSignatureStatus {
    let Some(signature_value) = log
        .audit_signature
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return AuditSignatureStatus::Unsigned;
    };

    let parsed = match parse_audit_signature(signature_value) {
        Ok(parsed) => parsed,
        Err(()) => return AuditSignatureStatus::Invalid,
    };
    if parsed.service_did != service_did {
        return AuditSignatureStatus::KeyUnavailable;
    }

    let public_jwks = keystore.public_jwks();
    let Some(public_key) = public_jwks
        .iter()
        .find(|candidate| candidate.kid() == Some(parsed.kid))
    else {
        return AuditSignatureStatus::KeyUnavailable;
    };

    let transcript = transcript_for_log(log);
    let canonical = match canonical_json_bytes(&transcript) {
        Ok(canonical) => canonical,
        Err(_) => return AuditSignatureStatus::Invalid,
    };

    let mut usable_key = false;
    for alg in audit_signature_algorithms() {
        let Ok(verifying_key) = AsymmetricVerifyingKey::from_jwk_and_alg(public_key.params(), &alg)
        else {
            continue;
        };
        usable_key = true;
        let signature = JoseSignature::new(parsed.signature.clone());
        if verifying_key.verify(&canonical, &signature).is_ok() {
            return AuditSignatureStatus::Verified;
        }
    }

    if !usable_key {
        return AuditSignatureStatus::KeyUnavailable;
    }

    AuditSignatureStatus::Invalid
}

/// Canonical-JSON transcript bound to one admin-audit row. Field order is fixed
/// for readability; `arkret_core::canonical` re-sorts before emitting bytes.
#[derive(Debug, Serialize)]
struct AuditTranscript<'a> {
    kind: &'a str,
    schema_version: u32,
    row_id: String,
    created_at: String,
    admin_user_id: String,
    operation: &'a AdminOperation,
    resource_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<String>,
    details: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<&'a str>,
}

fn transcript_for_log(log: &AdminOperationLog) -> AuditTranscript<'_> {
    AuditTranscript {
        kind: AUDIT_TRANSCRIPT_KIND,
        schema_version: AUDIT_TRANSCRIPT_SCHEMA_VERSION,
        row_id: log.id.to_string(),
        created_at: log.created_at.to_rfc3339_opts(SecondsFormat::Micros, true),
        admin_user_id: log.admin_user_id.to_string(),
        operation: &log.operation,
        resource_type: &log.resource_type,
        resource_id: log.resource_id.map(|id| id.to_string()),
        details: &log.details,
        ip_address: log.ip_address.map(|ip| ip.to_string()),
        user_agent: log.user_agent.as_deref(),
    }
}

#[derive(Debug, thiserror::Error)]
enum SignError {
    #[error("no usable service signing key in keystore")]
    NoSigningKey,
    #[error("keystore signing key rejected the audit algorithm")]
    KeyAlgMismatch,
    #[error("canonical-JSON encoding failed: {0}")]
    Canonical(String),
    #[error("audit transcript signing failed")]
    Sign,
}

fn sign_admin_operation_log(
    keystore: &Keystore,
    service_did: &str,
    log: &AdminOperationLog,
) -> Result<String, SignError> {
    let transcript = transcript_for_log(log);
    let canonical =
        canonical_json_bytes(&transcript).map_err(|e| SignError::Canonical(e.to_string()))?;

    let (alg, key) = audit_signature_algorithms()
        .into_iter()
        .find_map(|alg| keystore.signing_key_for_algorithm(&alg).map(|k| (alg, k)))
        .ok_or(SignError::NoSigningKey)?;

    let kid = key.kid().ok_or(SignError::NoSigningKey)?;
    let signer = keystore
        .signer_for_algorithm(&alg)
        .map_err(|_| SignError::KeyAlgMismatch)?;

    let mut rng = ChaChaRng::from_rng(rand_core::OsRng).map_err(|_| SignError::Sign)?;
    let raw = signer
        .try_sign_with_rng(&mut rng, &canonical)
        .map_err(|_| SignError::Sign)?;

    let sig_bytes: Box<[u8]> = raw.into();
    let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
    Ok(format!("{service_did}#{kid}:{sig_b64}"))
}

fn audit_signature_algorithms() -> [JsonWebSignatureAlg; 7] {
    [
        JsonWebSignatureAlg::EdDsa,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
    ]
}

struct ParsedAuditSignature<'a> {
    service_did: &'a str,
    kid: &'a str,
    signature: Vec<u8>,
}

fn parse_audit_signature(value: &str) -> Result<ParsedAuditSignature<'_>, ()> {
    let (did_url, signature_b64) = value.rsplit_once(':').ok_or(())?;
    let (service_did, kid) = did_url.rsplit_once('#').ok_or(())?;
    if service_did.is_empty() || kid.is_empty() || signature_b64.is_empty() {
        return Err(());
    }
    let signature = Base64UrlUnpadded::decode_vec(signature_b64).map_err(|_| ())?;
    if signature.is_empty() {
        return Err(());
    }
    Ok(ParsedAuditSignature {
        service_did,
        kid,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use coauth_data::audit::{AdminOperation, AdminOperationFilter, AdminOperationLog};
    use coauth_data::clock::MockClock;
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _};
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;

    use super::*;

    fn test_keystore() -> Keystore {
        let mut rng = ChaChaRng::seed_from_u64(7);
        let key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng)).with_kid("audit-test");
        Keystore::new(JsonWebKeySet::new(vec![key]))
    }

    fn other_keystore() -> Keystore {
        let mut rng = ChaChaRng::seed_from_u64(99);
        let key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng)).with_kid("other-key");
        Keystore::new(JsonWebKeySet::new(vec![key]))
    }

    fn test_log(audit_signature: Option<String>) -> AdminOperationLog {
        AdminOperationLog {
            id: Ulid::from(Uuid::from_bytes([1; 16])),
            admin_user_id: Ulid::from(Uuid::from_bytes([2; 16])),
            operation: AdminOperation::UserPasswordSet,
            resource_type: "user".to_owned(),
            resource_id: Some(Ulid::from(Uuid::from_bytes([3; 16]))),
            details: serde_json::json!({
                "reason": "break glass",
                "ticket": "SEC-123",
            }),
            ip_address: Some("203.0.113.10".parse().unwrap()),
            user_agent: Some("coauth-test/1.0".to_owned()),
            created_at: chrono::Utc
                .with_ymd_and_hms(2026, 5, 30, 12, 34, 56)
                .single()
                .unwrap(),
            audit_signature,
        }
    }

    fn signed_test_log(service_did: &str) -> (Keystore, AdminOperationLog) {
        let keystore = test_keystore();
        let mut log = test_log(None);
        log.audit_signature = Some(sign_admin_operation_log(&keystore, service_did, &log).unwrap());
        (keystore, log)
    }

    #[test]
    fn signed_row_verifies() {
        let service_did = "did:web:coauth.example";
        let (keystore, log) = signed_test_log(service_did);
        assert_eq!(
            verify_admin_operation_signature(&log, &keystore, service_did),
            AuditSignatureStatus::Verified
        );
    }

    #[test]
    fn details_tamper_invalidates_signature() {
        let service_did = "did:web:coauth.example";
        let (keystore, mut log) = signed_test_log(service_did);
        log.details["ticket"] = serde_json::json!("SEC-999");
        assert_eq!(
            verify_admin_operation_signature(&log, &keystore, service_did),
            AuditSignatureStatus::Invalid
        );
    }

    #[test]
    fn resource_id_tamper_invalidates_signature() {
        let service_did = "did:web:coauth.example";
        let (keystore, mut log) = signed_test_log(service_did);
        log.resource_id = Some(Ulid::from(Uuid::from_bytes([4; 16])));
        assert_eq!(
            verify_admin_operation_signature(&log, &keystore, service_did),
            AuditSignatureStatus::Invalid
        );
    }

    #[test]
    fn row_id_or_created_at_replay_invalidates_signature() {
        let service_did = "did:web:coauth.example";
        let (keystore, log) = signed_test_log(service_did);

        let mut replayed_id = log.clone();
        replayed_id.id = Ulid::from(Uuid::from_bytes([5; 16]));
        assert_eq!(
            verify_admin_operation_signature(&replayed_id, &keystore, service_did),
            AuditSignatureStatus::Invalid
        );

        let mut replayed_time = log;
        replayed_time.created_at += chrono::Duration::seconds(1);
        assert_eq!(
            verify_admin_operation_signature(&replayed_time, &keystore, service_did),
            AuditSignatureStatus::Invalid
        );
    }

    #[test]
    fn unsigned_status_is_reported() {
        assert_eq!(
            verify_admin_operation_signature(
                &test_log(None),
                &test_keystore(),
                "did:web:coauth.example"
            ),
            AuditSignatureStatus::Unsigned
        );
    }

    #[test]
    fn key_unavailable_status_is_reported() {
        let service_did = "did:web:coauth.example";
        let (_keystore, log) = signed_test_log(service_did);
        assert_eq!(
            verify_admin_operation_signature(&log, &other_keystore(), service_did),
            AuditSignatureStatus::KeyUnavailable
        );
    }

    #[tokio::test]
    async fn service_admin_audit_row_is_persisted_signed_and_verifiable() {
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut repo = coauth_data::PgRepositoryFactory::new(pool)
            .create()
            .await
            .unwrap();
        let clock = MockClock::default();
        let mut rng = ChaChaRng::seed_from_u64(8);
        let service_did = "did:web:coauth.example";
        let keystore = test_keystore();

        record_service_admin_operation_signed(
            &mut repo,
            &mut rng,
            &clock,
            &keystore,
            service_did,
            false,
            AdminOperation::Other("accountability_grant_issued".to_owned()),
            "agent",
            None,
            serde_json::json!({
                "accountability_grant_id": "ak:grant:test",
                "agent_principal_id": "did:web:agent.example",
            }),
        )
        .await
        .unwrap();

        let rows = repo
            .audit()
            .list_admin_operations(
                AdminOperationFilter::new()
                    .for_admin_user(service_admin_user_id(service_did))
                    .for_resource_type("agent")
                    .with_limit(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].operation,
            AdminOperation::Other("accountability_grant_issued".to_owned())
        );
        assert!(
            rows[0]
                .audit_signature
                .as_ref()
                .is_some_and(|sig| sig.starts_with("did:web:coauth.example#audit-test:"))
        );
        assert_eq!(
            verify_admin_operation_signature(&rows[0], &keystore, service_did),
            AuditSignatureStatus::Verified
        );

        repo.cancel().await.unwrap();
    }
}
