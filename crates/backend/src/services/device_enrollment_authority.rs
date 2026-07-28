//! Persistent device-enrollment-authority signing key (decision 0002, B model).
//!
//! Under the B custody model, the identity root and recovery keys remain in
//! client-controlled cold custody and never enter coauth. Device enrollment is
//! instead attested by this **persistent**, narrowly delegated service key.
//! coauth holds exactly one such key in its configured key backend; it signs `service_attested`
//! `ak.device.authorize` events on behalf of principals whose inception DID
//! document designates this authority via an
//! `ArkretDeviceEnrollmentAuthority` service entry
//! (`zh/crypto-media/device-lifecycle.md` §5.4).
//!
//! The key is selected from the deployment keystore by the reserved
//! `coauth-device-enrollment-v1` key id. Missing, duplicated, or non-Ed25519
//! keys fail closed; there is no ephemeral runtime fallback because it would
//! invalidate every previously issued device authorization after restart.
//!
//! The authority identity is a `did:key` so any spec-conformant `did:key`
//! resolver (soland's included) can verify the event proof without contacting
//! coauth. The DID is `did:key:z<multibase-ed25519-pub>` and the verification
//! method is `did:key:z<mb>#z<mb>` — the canonical `did:key` VM form the SDK
//! `DidKeyResolver` produces.

use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_identifiers::Did;
use arkret_signatures::Ed25519PayloadSigner;
use ed25519_dalek::SigningKey;

/// Resolved enrollment authority. Carries the raw seed so a
/// fresh [`Ed25519PayloadSigner`] (not `Clone`) can be rebuilt per signing call.
#[derive(Clone)]
pub struct EnrollmentAuthority {
    seed: [u8; 32],
    /// `did:key:z<multibase-ed25519-pub>`.
    did: String,
    /// `did:key:z<mb>#z<mb>` — the proof `verification_method`.
    verification_method: String,
}

impl std::fmt::Debug for EnrollmentAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentAuthority")
            .field("seed", &"<redacted>")
            .field("did", &self.did)
            .field("verification_method", &self.verification_method)
            .finish()
    }
}

impl EnrollmentAuthority {
    /// Build the authority from a raw 32-byte ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
        let multibase = ed25519_pubkey_to_did_key_multibase(&verifying_key.to_bytes());
        let did = format!("did:key:{multibase}");
        let verification_method = format!("{did}#{multibase}");
        Self {
            seed,
            did,
            verification_method,
        }
    }

    /// The enrollment authority DID (`did:key:z…`). Written into principal DID
    /// documents as the `ArkretDeviceEnrollmentAuthority` `serviceEndpoint`,
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

    /// Stable secret dedicated to Realm-scoped HLC node-id derivation.
    #[must_use]
    pub fn hlc_node_secret(&self) -> [u8; 32] {
        arkret_canonical::sha256_bytes_from_slices(&[
            b"coauth-device-enrollment-hlc-v1",
            &self.seed,
        ])
    }

    /// Build a fresh SDK signer bound to this authority's DID + VM. The signer
    /// is consumed by [`arkret_signatures::sign_event`].
    #[must_use]
    pub fn signer(&self) -> Ed25519PayloadSigner {
        let did = Did::new(self.did.clone()).expect("did:key authority DID is valid");
        Ed25519PayloadSigner::from_did_key_seed(self.seed, did, self.verification_method.clone())
    }
}

/// Resolve the deployment-pinned authority from the configured key backend.
pub fn enrollment_authority(
    key_store: &coauth_keystore::Keystore,
) -> Result<EnrollmentAuthority, coauth_keystore::DeviceEnrollmentKeyError> {
    key_store
        .device_enrollment_seed()
        .map(EnrollmentAuthority::from_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_and_vm_share_the_multibase_key() {
        let authority = EnrollmentAuthority::from_seed([7u8; 32]);
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
        let a = EnrollmentAuthority::from_seed([3u8; 32]);
        let b = EnrollmentAuthority::from_seed([3u8; 32]);
        assert_eq!(a.did(), b.did());
        assert_eq!(a.verification_method(), b.verification_method());
    }

    #[test]
    fn signer_did_matches_authority_did() {
        let authority = EnrollmentAuthority::from_seed([9u8; 32]);
        let signer = authority.signer();
        use arkret_wire::PayloadSigner as _;
        assert_eq!(signer.signer_did().as_str(), authority.did());
        assert_eq!(
            signer.verification_method_id(),
            authority.verification_method()
        );
    }
}
