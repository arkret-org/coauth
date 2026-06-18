#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod agent_auth_error_matrix_tests {
    use chrono::Utc;
    use cokret_core::canonical::canonical_json_bytes;

    use super::super::accountability::{
        accountability_capabilities_digest, normalize_capabilities,
    };
    use super::super::error_matrix::{
        AgentAuthRejection, PAUSED_REVOCATION_FRESHNESS_WINDOW, enforce_agent_lifecycle_gate,
        enforce_paused_revocation_freshness, enforce_verification_method_binding,
    };
    use super::super::proof::{ProofSignedFields, base64_decode_flexible, verify_proof_signature};
    use super::super::session_proof::AGENT_SESSION_MAX_TTL;

    #[test]
    fn verification_method_mismatch_fires_before_proof_validator() {
        let agent_did = "did:web:agent.example";
        let bad_vm = "did:web:other.example#key-1";
        let err = enforce_verification_method_binding(bad_vm, agent_did).expect_err("must reject");
        assert_eq!(
            err.code(),
            "verification_method_principal_mismatch",
            "must surface the canonical wire code"
        );
        assert_eq!(err.http_status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn verification_method_match_succeeds_with_fragment() {
        let agent_did = "did:web:agent.example";
        let good_vm = "did:web:agent.example#key-1";
        enforce_verification_method_binding(good_vm, agent_did).expect("must accept exact match");
    }

    #[test]
    fn deactivated_takes_priority_over_paused() {
        let err = enforce_agent_lifecycle_gate(true, true).expect_err("must reject");
        assert_eq!(err.code(), "agent_deactivated");
        assert_eq!(err.http_status(), http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn paused_alone_yields_agent_paused() {
        let err = enforce_agent_lifecycle_gate(true, false).expect_err("must reject");
        assert_eq!(err.code(), "agent_paused");
    }

    #[test]
    fn auth3_freshness_window_holds_for_30s() {
        let paused_at = Utc::now();
        let just_paused = paused_at + chrono::Duration::seconds(5);
        let err = enforce_paused_revocation_freshness(paused_at, just_paused)
            .expect_err("must reject inside window");
        assert_eq!(err.code(), "agent_paused");
    }

    #[test]
    fn auth3_freshness_window_releases_after_30s() {
        let paused_at = Utc::now();
        let after_window = paused_at + chrono::Duration::seconds(31);
        enforce_paused_revocation_freshness(paused_at, after_window)
            .expect("must release once window has elapsed");
    }

    #[test]
    fn auth3_natural_expiry_window_is_bounded_by_agent_session_ttl() {
        assert_eq!(AGENT_SESSION_MAX_TTL, chrono::Duration::minutes(15));
        assert!(
            PAUSED_REVOCATION_FRESHNESS_WINDOW <= AGENT_SESSION_MAX_TTL,
            "freshness recheck window must never outlive the stateless agent grant"
        );
    }

    #[test]
    fn accountability_grant_missing_renders_as_failed_precondition() {
        let err = AgentAuthRejection::AccountabilityGrantMissing;
        assert_eq!(err.code(), "accountability_grant_missing");
        assert_eq!(err.http_status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unknown_accountability_grant_action_is_rejected() {
        let err = normalize_capabilities(vec!["ck.agent.unregistered".to_owned()])
            .expect_err("unknown action must fail closed");
        assert_eq!(err.status(), http::StatusCode::BAD_REQUEST);
        assert!(
            err.message()
                .contains("is not a registered ck.agent.* action")
        );
    }

    #[test]
    fn capability_set_is_trimmed_sorted_and_deduplicated() {
        let normalized = normalize_capabilities(vec![
            " ck.self.agent.command.resume ".to_owned(),
            "ck.self.agent.command.provision".to_owned(),
            "ck.self.agent.command.resume".to_owned(),
        ])
        .expect("registered actions normalize");
        assert_eq!(
            normalized,
            vec![
                "ck.self.agent.command.provision".to_owned(),
                "ck.self.agent.command.resume".to_owned()
            ]
        );
    }

    #[test]
    fn capability_digest_is_stable_after_normalization() {
        let left = normalize_capabilities(vec![
            "ck.self.agent.command.resume".to_owned(),
            "ck.self.agent.command.provision".to_owned(),
        ])
        .unwrap();
        let right = normalize_capabilities(vec![
            " ck.self.agent.command.provision ".to_owned(),
            "ck.self.agent.command.resume".to_owned(),
            "ck.self.agent.command.resume".to_owned(),
        ])
        .unwrap();
        assert_eq!(left, right);
        assert_eq!(
            accountability_capabilities_digest(
                "did:web:agent.example",
                "did:web:controller.example",
                &left,
            )
            .unwrap(),
            accountability_capabilities_digest(
                "did:web:agent.example",
                "did:web:controller.example",
                &right,
            )
            .unwrap()
        );
    }

    #[test]
    fn pairing_request_expired_is_401() {
        let err = AgentAuthRejection::PairingRequestExpired;
        assert_eq!(err.code(), "pairing_request_expired");
        assert_eq!(err.http_status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn proof_signature_round_trips_over_canonical_signed_fields() {
        use base64ct::Encoding as _;
        use cokret::identity::binding::{derive_ed25519_from_seed, multicodec_ed25519_public_key};
        use ed25519_dalek::Signer as _;

        let signing_key = derive_ed25519_from_seed(&[7u8; 32]);
        let multibase = multicodec_ed25519_public_key(&signing_key.verifying_key());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let fields = ProofSignedFields {
            audience: "https://cokret.example/_cokret",
            challenge: "challenge-abc",
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let message = canonical_json_bytes(&fields).expect("canonical bytes");
        let signature = signing_key.sign(&message);
        let sig_b64 = base64ct::Base64UrlUnpadded::encode_string(&signature.to_bytes());

        verify_proof_signature(&multibase, &fields, &sig_b64).expect("valid signature accepts");
    }

    #[test]
    fn proof_signature_rejects_tampered_field() {
        use base64ct::Encoding as _;
        use cokret::identity::binding::{derive_ed25519_from_seed, multicodec_ed25519_public_key};
        use ed25519_dalek::Signer as _;

        let signing_key = derive_ed25519_from_seed(&[9u8; 32]);
        let multibase = multicodec_ed25519_public_key(&signing_key.verifying_key());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let signed = ProofSignedFields {
            audience: "https://cokret.example/_cokret",
            challenge: "challenge-abc",
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let message = canonical_json_bytes(&signed).expect("canonical bytes");
        let signature = signing_key.sign(&message);
        let sig_b64 = base64ct::Base64UrlUnpadded::encode_string(&signature.to_bytes());

        // A different audience (replay to a different service) must fail closed.
        let tampered = ProofSignedFields {
            audience: "https://evil.example/_cokret",
            challenge: "challenge-abc",
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let err = verify_proof_signature(&multibase, &tampered, &sig_b64)
            .expect_err("tampered audience must reject");
        assert_eq!(err.code(), "proof_invalid");
    }

    #[test]
    fn base64_decode_accepts_url_and_standard() {
        use base64ct::Encoding as _;
        // 64 zero bytes encoded url-unpadded and standard-padded both decode.
        let raw = [0u8; 64];
        let url = base64ct::Base64UrlUnpadded::encode_string(&raw);
        let std_padded = base64ct::Base64::encode_string(&raw);
        assert_eq!(base64_decode_flexible(&url).unwrap().len(), 64);
        assert_eq!(base64_decode_flexible(&std_padded).unwrap().len(), 64);
    }
}
