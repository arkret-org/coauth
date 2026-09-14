//! The only crossing between the two Ed25519 generations this crate links.
//!
//! `coauth-jose` and `coauth-keyring` are built on `ed25519-dalek` 2.x: that
//! generation carries the `pkcs8` feature `PrivateKey::to_pkcs8_der` needs in
//! order to keep every OIDC signing algorithm behind one return type, and
//! `coauth_jose::jwa::Ed25519SigningKey` / `Ed25519VerifyingKey` are aliases
//! for its types. The Arkret SDK (`arkret-signatures`, `arkret-identity`) is
//! built on `ed25519-dalek` 3.x, declared in the workspace manifest under the
//! `ed25519-dalek-3` rename. `coauth-backend` sits on top of both, so every
//! key that travels from the keyring/JOSE side into an SDK signing or
//! verification call has to change generation somewhere.
//!
//! It changes generation here, and nowhere else under `src/`. The crossing is
//! sound today only because an Ed25519 seed and an Ed25519 compressed public
//! key are the same 32 bytes in both generations — a property of the wire
//! format, not something either crate promises across a major version. Putting
//! every crossing behind a named function means a future change to `to_bytes`
//! semantics has exactly one place to break instead of eight, and
//! `ed25519_generation_crossings_stay_in_this_module` below asserts that
//! property mechanically rather than by convention.
//!
//! Nothing here changes signing or verification behaviour: each function is
//! the byte-for-byte constructor the call sites used to spell inline.

/// Ed25519 signing key in the generation the Arkret SDK signs with
/// (`ed25519-dalek` 3.x).
pub type SdkSigningKey = ed25519_dalek_3::SigningKey;

/// Ed25519 verifying key in the generation the Arkret SDK verifies with
/// (`ed25519-dalek` 3.x).
pub type SdkVerifyingKey = ed25519_dalek_3::VerifyingKey;

/// Returned when 32 bytes are not a canonical compressed Ed25519 point.
///
/// The generation crossing is deliberately opaque about which side rejected
/// the key: call sites map this onto their own protocol-level error and must
/// not branch on the underlying `SignatureError`.
#[derive(Debug, thiserror::Error)]
#[error("value is not a canonical Ed25519 public key")]
pub struct MalformedEd25519PublicKey;

/// Builds an SDK-generation signing key from a raw 32-byte Ed25519 seed.
///
/// The seed comes from `coauth_keyring::Keyring::account_authority_seed`, or
/// from a fixed test seed. An Ed25519 seed is opaque bytes in every
/// generation, so this direction cannot fail.
#[must_use]
pub fn sdk_signing_key_from_seed_bytes(seed: &[u8; 32]) -> SdkSigningKey {
    SdkSigningKey::from_bytes(seed)
}

/// Builds an SDK-generation verifying key from a raw 32-byte compressed
/// Ed25519 public key.
///
/// The bytes come off the wire — a DID document verification method, a JWK, or
/// a peer-supplied key — so decompression can fail.
///
/// # Errors
///
/// Returns [`MalformedEd25519PublicKey`] when the bytes do not decompress to a
/// valid Edwards point.
pub fn sdk_verifying_key_from_public_key_bytes(
    public_key: &[u8; 32],
) -> Result<SdkVerifyingKey, MalformedEd25519PublicKey> {
    SdkVerifyingKey::from_bytes(public_key).map_err(|_| MalformedEd25519PublicKey)
}

/// Re-parses a JOSE-generation (`ed25519-dalek` 2.x) verifying key into the
/// SDK generation.
///
/// Both generations serialise a verifying key as the same 32-byte compressed
/// point, so the round-trip is lossless. The SDK-side parse is kept rather
/// than elided: it is the second of the two validations the call path performs
/// today, and dropping it would change which inputs are accepted.
///
/// # Errors
///
/// Returns [`MalformedEd25519PublicKey`] when the SDK generation rejects a
/// point the JOSE generation accepted.
pub fn sdk_verifying_key_from_jose_verifying_key(
    jose_key: &ed25519_dalek::VerifyingKey,
) -> Result<SdkVerifyingKey, MalformedEd25519PublicKey> {
    sdk_verifying_key_from_public_key_bytes(&jose_key.to_bytes())
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use camino::{Utf8Path, Utf8PathBuf};

    use super::*;

    /// Floor for the source-tree scan below. `crates/backend/src` held 251
    /// `.rs` files when this guard was written; the floor exists so that a
    /// directory move, a renamed crate root, or a broken relative path makes
    /// the guard fail loudly instead of passing over an empty scan.
    const MINIMUM_SCANNED_SOURCES: usize = 200;

    fn rust_sources(root: &Utf8Path, out: &mut Vec<Utf8PathBuf>) -> io::Result<()> {
        for entry in root.read_dir_utf8()? {
            let path = entry?.into_path();
            if path.is_dir() {
                rust_sources(&path, out)?;
            } else if path.extension() == Some("rs") {
                out.push(path);
            }
        }
        Ok(())
    }

    #[test]
    fn ed25519_generation_crossings_stay_in_this_module() {
        // Assembled at runtime so this file is not itself a literal match, the
        // same self-exclusion the workspace's other source-scan guards take.
        let needle = ["ed25519_dalek", "_3"].concat();
        let src_root = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let bridge = Utf8Path::new(file!())
            .file_name()
            .expect("guard file has a name")
            .to_owned();

        let mut sources = Vec::new();
        rust_sources(&src_root, &mut sources).expect("walk crate sources");

        // Scan-surface self-check: an empty or truncated scan must fail, not
        // pass. Both halves matter - the count catches a wrong root, and the
        // anchor catches a scan that reached a tree without this module in it.
        assert!(
            sources.len() >= MINIMUM_SCANNED_SOURCES,
            "guard scanned only {} Rust sources under {}; expected at least \
             {MINIMUM_SCANNED_SOURCES}. The scan surface moved - fix the root \
             before trusting this test",
            sources.len(),
            src_root,
        );
        assert!(
            sources
                .iter()
                .any(|path| path.file_name() == Some(bridge.as_str())),
            "guard did not scan its own module ({bridge}) under {src_root}; the \
             scan surface is not the tree this guard is meant to cover",
        );

        let mut violations = Vec::new();
        for path in &sources {
            if path.file_name() == Some(bridge.as_str()) {
                continue;
            }
            let source = fs::read_to_string(path).expect("read Rust source");
            if source.contains(&needle) {
                violations.push(path.to_string());
            }
        }

        assert!(
            violations.is_empty(),
            "the two ed25519-dalek generations may only meet in \
             crate::arkret_key_bridge; name that module's helpers instead of \
             the renamed crate:\n{}",
            violations.join("\n"),
        );
    }

    #[test]
    fn jose_and_sdk_generations_agree_on_public_key_bytes() {
        let seed = [0x2a_u8; 32];
        let jose_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let sdk_key = sdk_signing_key_from_seed_bytes(&seed).verifying_key();

        assert_eq!(jose_key.to_bytes(), sdk_key.to_bytes());
        assert_eq!(
            sdk_verifying_key_from_jose_verifying_key(&jose_key)
                .expect("jose key crosses into the sdk generation")
                .to_bytes(),
            sdk_key.to_bytes(),
        );
    }

    #[test]
    fn both_generations_accept_and_reject_the_same_encodings() {
        // The bridge is only sound while the two generations agree on which
        // 32-byte strings decompress. Sweep a deterministic sample of
        // arbitrary bytes (most of which are not valid points) and require the
        // verdicts to match; a divergence here is the failure mode the module
        // doc warns about, and it would otherwise surface as a silent
        // verification difference in production.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..512 {
            let mut candidate = [0_u8; 32];
            for chunk in candidate.as_chunks_mut::<8>().0 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *chunk = state.to_le_bytes();
            }
            assert_eq!(
                ed25519_dalek::VerifyingKey::from_bytes(&candidate).is_ok(),
                sdk_verifying_key_from_public_key_bytes(&candidate).is_ok(),
                "generations disagree on {}",
                hex::encode(candidate),
            );
        }
    }
}
