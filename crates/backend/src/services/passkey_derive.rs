//! Derive a deterministic starid `update_key` from a webauthn-rs `Passkey`.
//!
//! Replaces the round-37.4 placeholder
//! (`onboarding_starid::PLACEHOLDER_UPDATE_KEY` — removed) with a
//! per-credential, device-bound key that starid stores on the DID's
//! `updateKeys` slot. The flow is:
//!
//! 1. Browser finishes a WebAuthn registration ceremony
//!    (`PgWebauthnService::register_finish`) producing a [`Passkey`].
//! 2. coauth runs [`derive_update_key_from_credential`] over the
//!    passkey's COSE public key, yielding a multibase `z…` string of
//!    the same shape (`z6Mk…`) starid expects.
//! 3. coauth hands that key to starid as either:
//!    * `StaridRegistry::create_principal_did` (first passkey on the
//!      account → mints the DID), or
//!    * `StaridRegistry::rotate_update_key` (subsequent enrolment →
//!      `POST /api/v1/webvh/dids/{did}/update` swaps the key on the
//!      existing DID).
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

use sha2::{Digest, Sha256};
use webauthn_rs::prelude::Passkey;

/// Multicodec tag for an Ed25519 public key — two bytes prepended to
/// the 32-byte raw key before multibase-encoding.
const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// Base58btc alphabet (Bitcoin) used by `did:key` / multibase `z…`
/// prefix. Inlined to avoid pulling the `multibase` crate just for one
/// 58-character table.
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Derive a deterministic, multibase-encoded `update_key` from
/// `passkey`. Returns a string of the form `z6Mk…` that starid accepts
/// in the `update_keys` slot of `POST /api/v1/webvh/dids` and
/// `POST /api/v1/webvh/dids/{did}/update`.
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

    let mut envelope = Vec::with_capacity(2 + digest.len());
    envelope.extend_from_slice(&MULTICODEC_ED25519_PUB);
    envelope.extend_from_slice(&digest);

    let mut out = String::with_capacity(1 + envelope.len() * 2);
    out.push('z');
    out.push_str(&base58btc_encode(&envelope));
    out
}

/// Minimal base58btc encoder. Accepts an arbitrary byte slice and
/// returns the base58btc-encoded string (no leading multibase tag —
/// that's the caller's job).
fn base58btc_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    // Count leading zero bytes — these become leading '1's in the
    // output, since base58 has no zero digit at index 0 (the alphabet
    // starts at '1').
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();

    // Convert big-endian bytes to base58 by repeated long division.
    // Allocation: log_58(256) ≈ 1.366, so ceil(len * 1.4) is safe.
    let mut input: Vec<u8> = bytes.to_vec();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);

    let mut start = leading_zeros;
    while start < input.len() {
        let mut remainder: u32 = 0;
        for byte in input.iter_mut().skip(start) {
            let acc = (remainder << 8) | u32::from(*byte);
            *byte = u8::try_from(acc / 58).expect("acc/58 fits in u8 because acc < 58 * 256");
            remainder = acc % 58;
        }
        output.push(BASE58_ALPHABET[remainder as usize]);
        // Skip any new leading zeros that the division introduced.
        while start < input.len() && input[start] == 0 {
            start += 1;
        }
    }

    let mut s = String::with_capacity(leading_zeros + output.len());
    for _ in 0..leading_zeros {
        s.push('1');
    }
    // We accumulated least-significant-digit first; reverse for the
    // canonical big-endian base58 string.
    for &b in output.iter().rev() {
        s.push(b as char);
    }
    s
}

#[cfg(test)]
mod tests {
    //! Determinism + shape tests for the passkey-derived update_key.
    //!
    //! We don't unit-test against a live `Passkey` here — exercising
    //! `webauthn-rs`'s registration ceremony from inside a unit test
    //! requires a full `Webauthn` builder + a fake authenticator that's
    //! out of scope for this module. The integration is covered by the
    //! `services::onboarding_starid::tests` wire-up below + the admin
    //! `passkeys::register_finish` handler tests. Here we lock down the
    //! pure derivation contract on raw COSE-key bytes.
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
    /// `errcode=invalid_update_key`.
    #[test]
    fn derive_output_uses_multibase_z6mk_prefix() {
        let key = derive_update_key_from_cose_bytes(b"any-input");
        assert!(
            key.starts_with("z6Mk"),
            "derived key {key:?} must start with z6Mk (multibase z-base58btc + ed25519 multicodec)",
        );
    }

    /// Output decodes back to a 34-byte payload (2-byte multicodec +
    /// 32-byte sha256). Catches accidental truncation / padding bugs
    /// in the base58 encoder.
    #[test]
    fn derive_output_round_trips_to_34_bytes() {
        let key = derive_update_key_from_cose_bytes(b"hello world");
        assert!(key.starts_with('z'));
        let body = &key[1..];
        let decoded = base58btc_decode(body).expect("output is valid base58btc");
        assert_eq!(decoded.len(), 34, "envelope must be 2-byte tag + 32-byte digest");
        assert_eq!(&decoded[..2], &MULTICODEC_ED25519_PUB);
    }

    /// Sanity check on the encoder against a known vector: the all-
    /// zero 32-byte digest with the Ed25519 envelope must round-trip.
    #[test]
    fn base58_encoder_round_trips_known_vector() {
        let mut envelope = Vec::with_capacity(34);
        envelope.extend_from_slice(&MULTICODEC_ED25519_PUB);
        envelope.extend_from_slice(&[0u8; 32]);
        let encoded = base58btc_encode(&envelope);
        let decoded = base58btc_decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
    }

    /// Inverse of `base58btc_encode`. Test-only — production code only
    /// ever encodes (starid handles the decode side).
    fn base58btc_decode(s: &str) -> Option<Vec<u8>> {
        if s.is_empty() {
            return Some(Vec::new());
        }
        let mut lookup = [255u8; 128];
        for (i, &c) in BASE58_ALPHABET.iter().enumerate() {
            lookup[c as usize] = u8::try_from(i).ok()?;
        }

        let leading_ones = s.bytes().take_while(|&b| b == b'1').count();
        let mut acc: Vec<u8> = Vec::with_capacity(s.len());
        for c in s.bytes() {
            let v = lookup.get(c as usize).copied()?;
            if v == 255 {
                return None;
            }
            let mut carry = u32::from(v);
            for byte in acc.iter_mut() {
                let total = u32::from(*byte) * 58 + carry;
                *byte = u8::try_from(total & 0xff).ok()?;
                carry = total >> 8;
            }
            while carry > 0 {
                acc.push(u8::try_from(carry & 0xff).ok()?);
                carry >>= 8;
            }
        }
        let mut out: Vec<u8> = vec![0; leading_ones];
        out.extend(acc.iter().rev());
        Some(out)
    }
}
