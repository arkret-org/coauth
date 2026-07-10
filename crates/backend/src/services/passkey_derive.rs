//! Derive a deterministic starid `update_key` from a webauthn-rs `Passkey`.
//!
//! Produces a per-credential, device-bound key that starid stores on the
//! DID's `updateKeys` slot. The strand is:
//!
//! 1. Browser finishes a `WebAuthn` registration ceremony (`PgWebauthnService::register_finish`)
//!    producing a [`Passkey`].
//! 2. coauth runs [`derive_update_key_from_credential`] over the passkey's COSE public key,
//!    yielding a multibase `z…` string of the same shape (`z6Mk…`) starid expects.
//! 3. coauth hands that key to starid as either:
//!    * `StaridRegistry::create_principal_did` (first passkey on the account → mints the DID), or
//!    * `StaridRegistry::rotate_update_key` (subsequent enrolment → `POST
//!      /_starid/root/webvh/dids/{did}/update` swaps the key on the existing DID).
//!
//! Determinism note: the returned string is a function of the
//! credential's COSE public key bytes only. Two enrolments of the same
//! authenticator credential produce the same `update_key`; two distinct
//! credentials produce two distinct keys. The `z` prefix is the
//! multibase tag (`base58btc`) and the next bytes are the multicodec
//! envelope `0xed01` (Ed25519 public key) followed by 32 bytes of
//! SHA-256(serialized COSE key). This is **not** a real Ed25519 public
//! key — it's a stable, opaque 32-byte identifier in the same multibase
//! alphabet starid validates. starid treats `update_keys` as opaque
//! identifiers for control-proof verification, so any 32-byte string
//! that round-trips through the same multibase decoder is acceptable
//! for the v1 wire-up; a real Ed25519 update-key rotation lands once
//! the device-side key-export contract stabilises (tracked separately).
//!
//! SDK-10 migration (2026-05-18): the multibase / multicodec envelope
//! is now produced by
//! `arkret_core::ed25519_pubkey_to_did_key_multibase` so coauth,
//! inkson, and any other consumer reach the same bytes for the same 32-byte
//! input. The COSE→32-byte digest step stays here because it's coupled to
//! webauthn-rs's `Passkey` / `COSEKey` types (which are coauth-specific deps).

use arkret_core::ed25519_pubkey_to_did_key_multibase;
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::Passkey;

/// Derive a deterministic, multibase-encoded `update_key` from
/// `passkey`. Returns a string of the form `z6Mk…` that starid accepts
/// in the `update_keys` slot of `POST /_starid/root/webvh/dids` and
/// `POST /_starid/root/webvh/dids/{did}/update`.
///
/// The hash input is the JSON serialisation of the passkey's COSE
/// public key (via `Passkey::get_public_key`). This is stable across
/// process restarts and across the wire because `webauthn-rs`'s
/// `COSEKey` Serde representation is part of its public API and round-
/// trips identically.
#[must_use]
pub fn derive_update_key_from_credential(passkey: &Passkey) -> String {
    let cose = passkey.get_public_key();
    let cose_bytes = serde_json::to_vec(cose)
        // Serialising a COSEKey to JSON cannot fail in practice — the
        // type's Serialize impl is total over its inhabitants.
        .expect("COSEKey serialisation is infallible");
    derive_update_key_from_cose_bytes(&cose_bytes)
}

/// Pure helper exposed for tests: derive an `update_key` from raw COSE
/// key bytes (or any byte slice — it's the same SHA-256 + multibase
/// envelope).
#[must_use]
pub fn derive_update_key_from_cose_bytes(cose_bytes: &[u8]) -> String {
    let digest = Sha256::digest(cose_bytes);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    ed25519_pubkey_to_did_key_multibase(&bytes)
}

#[cfg(test)]
mod tests {
    //! Determinism + shape tests for the passkey-derived `update_key`.
    //!
    //! We don't unit-test against a live `Passkey` here — exercising
    //! `webauthn-rs`'s registration ceremony from inside a unit test
    //! requires a full `Webauthn` builder + a fake authenticator that's
    //! out of scope for this module. The integration is covered by the
    //! `services::onboarding_starid::tests` wire-up below + the admin
    //! `passkeys::register_finish` handler tests. Here we lock down the
    //! pure derivation contract on raw COSE-key bytes.
    use arkret_core::decode_ed25519_multibase;

    use super::*;

    /// Same input bytes → same multibase string; different inputs →
    /// different strings. This is the load-bearing property the starid
    /// rotation wire-up relies on (a credential rotates to itself; a
    /// new credential rotates the DID to a new key).
    #[test]
    fn derive_is_deterministic_and_distinguishes_inputs() {
        let a = derive_update_key_from_cose_bytes(b"cose-key-a");
        let a2 = derive_update_key_from_cose_bytes(b"cose-key-a");
        let b = derive_update_key_from_cose_bytes(b"cose-key-b");
        assert_eq!(a, a2, "same input → same update_key");
        assert_ne!(a, b, "different inputs → different update_keys");
    }

    /// Output is multibase z-base58btc with the Ed25519 multicodec
    /// envelope. The `z6Mk` prefix is what starid + did:key consumers
    /// match against. Locking this in here means a regression in the
    /// envelope (e.g. wrong multicodec tag) breaks this test rather
    /// than silently producing a key starid rejects with
    /// `error.code=invalid_update_key`.
    #[test]
    fn derive_output_uses_multibase_z6mk_prefix() {
        let key = derive_update_key_from_cose_bytes(b"any-input");
        assert!(
            key.starts_with("z6Mk"),
            "derived key {key:?} must start with z6Mk (multibase z-base58btc + ed25519 multicodec)",
        );
    }

    /// Output decodes back via the SDK helper to the 32-byte digest
    /// payload (the SDK strips the 2-byte multicodec tag). Catches
    /// accidental truncation / padding bugs in the encoder path.
    #[test]
    fn derive_output_round_trips_to_32_bytes() {
        let key = derive_update_key_from_cose_bytes(b"hello world");
        let decoded = decode_multicodec_ed25519(&key).expect("output is valid multicodec-ed25519");
        assert_eq!(
            decoded.len(),
            32,
            "payload after tag strip must be 32 bytes"
        );
        // The 32 bytes are the SHA-256 of the input; recompute and
        // compare to lock in that the digest survives the round trip
        // intact.
        let expected: [u8; 32] = Sha256::digest(b"hello world").into();
        assert_eq!(decoded, expected);
    }
}
