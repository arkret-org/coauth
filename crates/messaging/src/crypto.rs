//! Shared HMAC / SHA-256 signing helpers for the messaging gateways.
//!
//! The email and SMS send paths (Paloud internal auth, AWS SigV4, Tencent
//! TC3) all need the same primitives. These previously lived as byte-identical
//! copies in `email/transport.rs`, `sms/transport.rs`, and `sms/tencent.rs`,
//! which meant a fix to the signing-string layout or nonce algorithm had to be
//! applied in three places. They are centralised here so every gateway shares
//! one implementation.

use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// HMAC-SHA256 instance used by every messaging signer.
pub(crate) type HmacSha256 = Hmac<Sha256>;

/// Lowercase-hex SHA-256 of `data`.
pub(crate) fn hex_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// HMAC-SHA256 of `data` under `key`, returned as raw bytes.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Process-unique nonce for a Paloud internal request, derived from the
/// request timestamp, the process id, and a monotonic counter.
pub(crate) fn paloud_internal_nonce(timestamp: i64) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!(
        "{timestamp:x}-{:x}-{:x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Sign a Paloud internal request. The canonical string is
/// `METHOD\npath\ntimestamp\nnonce\nhex_sha256(body)`, HMAC-SHA256'd under
/// `secret` and hex-encoded.
pub(crate) fn sign_paloud_internal_request(
    secret: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let payload = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.trim().to_ascii_uppercase(),
        path.trim(),
        timestamp,
        nonce.trim(),
        hex_sha256(body)
    );
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts arbitrary key lengths");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
