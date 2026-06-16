//! Persistent device-enrollment-authority signing key (decision 0002, B model).
//!
//! Under the managed-DID (account-authority) profile, device enrollment is
//! attested by a **persistent** service key — distinct from the inception
//! `did_key_seed` which is consumed and discarded after minting
//! (`zh/identity/key-management.md` §5.0.6 rule 2). coauth holds exactly one
//! such key process-wide; it signs `service_attested` `ck.device.authorize`
//! events on behalf of any principal whose DID document designates this
//! authority via a `CokretDeviceEnrollmentAuthority` service entry
//! (`zh/crypto-media/device-lifecycle.md` §5.4).
//!
//! The key is loaded from `COAUTH_DEVICE_ENROLLMENT_KEY_SEED` (base64 of a
//! 32-byte ed25519 seed). When absent, a random seed is generated once at
//! process start and a warning is emitted: anything signed with an ephemeral
//! key is unverifiable across restarts (acceptable for single-process e2e, not
//! for production). The resolved authority is cached in a process-wide
//! `OnceLock` so every request shares the same key.
//!
//! The authority identity is a `did:key` so any spec-conformant `did:key`
//! resolver (soland's included) can verify the event proof without contacting
//! coauth. The DID is `did:key:z<multibase-ed25519-pub>` and the verification
//! method is `did:key:z<mb>#z<mb>` — the canonical `did:key` VM form the SDK
//! `DidKeyResolver` produces.

use std::sync::OnceLock;

use cokret_core::Did;
use cokret_core::multibase::ed25519_pubkey_to_did_key_multibase;
use cokret_signatures::Ed25519MoveSigner;
use ed25519_dalek::SigningKey;

/// Env var carrying the base64-encoded 32-byte ed25519 enrollment seed.
pub const ENROLLMENT_KEY_SEED_ENV: &str = "COAUTH_DEVICE_ENROLLMENT_KEY_SEED";

/// How the enrollment signing key was obtained at process start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentKeyOrigin {
    /// Loaded from [`ENROLLMENT_KEY_SEED_ENV`].
    Configured,
    /// No env var present — generated at process start. Anything signed with
    /// this key is unverifiable across restarts.
    Ephemeral,
}

/// Resolved, process-wide enrollment authority. Carries the raw seed so a
/// fresh [`Ed25519MoveSigner`] (not `Clone`) can be rebuilt per signing call.
#[derive(Clone)]
pub struct EnrollmentAuthority {
    seed: [u8; 32],
    /// `did:key:z<multibase-ed25519-pub>`.
    did: String,
    /// `did:key:z<mb>#z<mb>` — the proof `verification_method`.
    verification_method: String,
    origin: EnrollmentKeyOrigin,
}

impl std::fmt::Debug for EnrollmentAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentAuthority")
            .field("seed", &"<redacted>")
            .field("did", &self.did)
            .field("verification_method", &self.verification_method)
            .field("origin", &self.origin)
            .finish()
    }
}

impl EnrollmentAuthority {
    /// Build the authority from a raw 32-byte ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32], origin: EnrollmentKeyOrigin) -> Self {
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
        let multibase = ed25519_pubkey_to_did_key_multibase(&verifying_key.to_bytes());
        let did = format!("did:key:{multibase}");
        let verification_method = format!("{did}#{multibase}");
        Self {
            seed,
            did,
            verification_method,
            origin,
        }
    }

    /// The enrollment authority DID (`did:key:z…`). Written into principal DID
    /// documents as the `CokretDeviceEnrollmentAuthority` `serviceEndpoint`,
    /// recorded as the event `executed_by` and the payload `authorized_by` /
    /// `enrollment_authority_binding.authority_did`.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The proof `verification_method` (`did:key:z…#z…`). MUST map to
    /// `executed_by` per device-lifecycle §5.4.
    #[must_use]
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    /// Origin of the underlying key (configured vs ephemeral).
    #[must_use]
    pub fn origin(&self) -> EnrollmentKeyOrigin {
        self.origin
    }

    /// Build a fresh SDK signer bound to this authority's DID + VM. The signer
    /// is consumed by [`cokret_signatures::sign_event`].
    #[must_use]
    pub fn signer(&self) -> Ed25519MoveSigner {
        let did = Did::new(self.did.clone()).expect("did:key authority DID is valid");
        Ed25519MoveSigner::from_did_key_seed(self.seed, did, self.verification_method.clone())
    }
}

static AUTHORITY: OnceLock<EnrollmentAuthority> = OnceLock::new();

/// Decode the configured seed, or generate a random one with a warning.
fn load_authority() -> EnrollmentAuthority {
    use base64ct::{Base64, Encoding as _};

    if let Ok(raw) = std::env::var(ENROLLMENT_KEY_SEED_ENV) {
        let trimmed = raw.trim();
        let mut buf = [0u8; 48];
        match Base64::decode(trimmed, &mut buf) {
            Ok(decoded) if decoded.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(decoded);
                return EnrollmentAuthority::from_seed(seed, EnrollmentKeyOrigin::Configured);
            }
            Ok(decoded) => {
                tracing::warn!(
                    "{ENROLLMENT_KEY_SEED_ENV} decoded to {} bytes (expected 32); \
                     falling back to an ephemeral enrollment key",
                    decoded.len()
                );
            }
            Err(error) => {
                tracing::warn!(
                    "{ENROLLMENT_KEY_SEED_ENV} base64 decode failed ({error:?}); \
                     falling back to an ephemeral enrollment key"
                );
            }
        }
    }

    let mut seed = [0u8; 32];
    use rand::RngExt as _;
    rand::rng().fill(&mut seed[..]);
    tracing::warn!(
        "{ENROLLMENT_KEY_SEED_ENV} not set; using an ephemeral device-enrollment \
         authority key (signed device authorizations will be unverifiable across \
         restarts — configure a real key for production)"
    );
    EnrollmentAuthority::from_seed(seed, EnrollmentKeyOrigin::Ephemeral)
}

/// Return the process-wide enrollment authority, initialising it on first use.
#[must_use]
pub fn enrollment_authority() -> &'static EnrollmentAuthority {
    AUTHORITY.get_or_init(load_authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_and_vm_share_the_multibase_key() {
        let authority = EnrollmentAuthority::from_seed([7u8; 32], EnrollmentKeyOrigin::Configured);
        let did = authority.did();
        assert!(did.starts_with("did:key:z"));
        // VM form is `did:key:z…#z…` with the same multibase on both sides.
        let multibase = did.strip_prefix("did:key:").unwrap();
        assert_eq!(
            authority.verification_method(),
            format!("{did}#{multibase}")
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = EnrollmentAuthority::from_seed([3u8; 32], EnrollmentKeyOrigin::Configured);
        let b = EnrollmentAuthority::from_seed([3u8; 32], EnrollmentKeyOrigin::Configured);
        assert_eq!(a.did(), b.did());
        assert_eq!(a.verification_method(), b.verification_method());
    }

    #[test]
    fn signer_did_matches_authority_did() {
        let authority = EnrollmentAuthority::from_seed([9u8; 32], EnrollmentKeyOrigin::Configured);
        let signer = authority.signer();
        use cokret_core::MoveSigner as _;
        assert_eq!(signer.signer_did().as_str(), authority.did());
        assert_eq!(
            signer.verification_method_id(),
            authority.verification_method()
        );
    }
}
