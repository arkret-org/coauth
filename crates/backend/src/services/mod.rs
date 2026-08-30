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
    use coauth_iana::jose::JsonWebSignatureAlg;
    [
        JsonWebSignatureAlg::Ed25519,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps256,
    ]
    .into_iter()
    .find_map(|alg| {
        key_store
            .signing_key_for_algorithm(&alg)
            .map(|key| (alg, key))
    })
}
