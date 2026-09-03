pub mod account_claims;
pub mod account_status_publication;
pub mod device_revoke;
pub mod did_binding;
pub mod did_binding_proof;
pub mod did_resolver;
pub mod dpop;
pub mod email_webhook;
pub mod erasure_receipt;
pub mod handle_subject_validator;
pub mod invite_quarantine;
pub mod organization_bootstrap;
pub mod organization_statement;
pub mod peer_protocol_client;
pub mod principal_facade;
pub mod refresh_token_rotation;
pub mod risk_action_proposals;
pub mod risk_action_state;
pub mod soland_webvh;
pub mod station_trust;
pub mod upstream_oidc;
pub mod upstream_oidc_mapping;
pub mod user_admin;
pub mod user_profile;
pub mod verified_profiles;
pub mod webauthn;

/// The service-wide JWS algorithm preference order for coauth-issued
/// artefacts (session grant JWTs, handle-claim proofs, policy decisions,
/// organization statements).
///
/// Every service signer resolves its key through this one function so a
/// keystore that offers several algorithms cannot make two coauth surfaces
/// sign with different keys.
pub(crate) fn preferred_service_signing_key(
    key_store: &coauth_keystore::Keystore,
) -> Option<(
    coauth_iana::jose::JsonWebSignatureAlg,
    &coauth_keystore::JsonWebKey<coauth_keystore::PrivateKey>,
)> {
    key_store.session_grant_signing_key()
}

#[cfg(test)]
mod tests {
    use coauth_jose::constraints::Constrainable as _;
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;

    use super::preferred_service_signing_key;

    fn ed25519(seed: u64, kid: &str) -> JsonWebKey<PrivateKey> {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng)).with_kid(kid)
    }

    /// A deployment legitimately holds several Ed25519 keys, each documented
    /// for one job. Selecting by algorithm returned the last one configured, so
    /// grant issuance moved onto a different key - and the `kid` clients read
    /// out of every grant moved with it - whenever a key was added or
    /// reordered. Both orders must now name the designated key.
    #[test]
    fn session_grant_signer_is_the_designated_key_regardless_of_key_order() {
        let designated = coauth_keystore::SESSION_GRANT_SIGNING_KEY_ID;

        for order in [
            [("other-a", 21_u64), (designated, 22), ("other-z", 23)],
            [("other-z", 23), (designated, 22), ("other-a", 21)],
        ] {
            let keys = order
                .iter()
                .map(|(kid, seed)| ed25519(*seed, kid))
                .collect();
            let key_store = Keystore::new(JsonWebKeySet::new(keys));
            let (alg, key) =
                preferred_service_signing_key(&key_store).expect("a signing key is available");
            assert_eq!(key.kid(), Some(designated));
            assert_eq!(alg, coauth_iana::jose::JsonWebSignatureAlg::Ed25519);
        }
    }

    /// A config written before the designated kid existed still has to issue
    /// grants: refusing would take an upgrading deployment's logins down.
    #[test]
    fn a_keystore_without_the_designated_key_still_signs() {
        let key_store = Keystore::new(JsonWebKeySet::new(vec![ed25519(24, "legacy-only")]));
        let (_, key) = preferred_service_signing_key(&key_store)
            .expect("legacy keystores keep their historical selection");
        assert_eq!(key.kid(), Some("legacy-only"));
    }
}
