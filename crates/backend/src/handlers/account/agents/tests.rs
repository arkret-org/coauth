#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod agent_auth_error_matrix_tests {
    use arkret_core::canonical::canonical_json_bytes;
    use chrono::Utc;
    use salvo::prelude::Router;
    use salvo::test::{ResponseExt as _, TestClient};

    fn derive_ed25519_from_seed(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(seed)
    }

    fn multicodec_ed25519_public_key(key: &ed25519_dalek::VerifyingKey) -> String {
        arkret_core::ed25519_pubkey_to_did_key_multibase(&key.to_bytes())
    }

    use super::super::accountability::{
        accountability_capabilities_digest, normalize_capabilities,
    };
    use super::super::error_matrix::{
        AgentAuthRejection, PAUSED_REVOCATION_FRESHNESS_WINDOW, enforce_agent_lifecycle_gate,
        enforce_paused_revocation_freshness, enforce_verification_method_binding,
    };
    use super::super::proof::{ProofSignedFields, verify_proof_signature};
    use super::super::session_proof::AGENT_SESSION_MAX_TTL;

    #[salvo::handler]
    async fn agent_pcr_recovery_not_ready_fixture()
    -> Result<(), crate::handlers::arkret::ArkretRouteError> {
        Err(AgentAuthRejection::AgentPcrRecoveryNotReady
            .into_app_error()
            .into())
    }

    #[tokio::test]
    async fn agent_pcr_recovery_not_ready_renders_arkret_error_envelope() {
        let service = salvo::Service::new(
            Router::with_path("agent-pcr-recovery-not-ready")
                .post(agent_pcr_recovery_not_ready_fixture),
        );
        let mut response = TestClient::post("http://127.0.0.1:8698/agent-pcr-recovery-not-ready")
            .send(&service)
            .await;

        assert_eq!(
            response.status_code,
            Some(http::StatusCode::PRECONDITION_FAILED)
        );
        let body: serde_json::Value =
            serde_json::from_str(&response.take_string().await.unwrap()).unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(
            body["error"]["code"],
            arkret_core::error::REASON_AGENT_PCR_RECOVERY_NOT_READY
        );
        assert!(body.get("errors").is_none());
    }

    #[test]
    fn verification_method_mismatch_fires_before_proof_validator() {
        let agent_did = "did:web:agent.example";
        let bad_vm = "did:web:other.example#key-1";
        let err = enforce_verification_method_binding(bad_vm, agent_did).expect_err("must reject");
        assert_eq!(
            err.reason_code(),
            Some("verification_method_principal_mismatch"),
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
        assert_eq!(err.reason_code(), Some("agent_deactivated"));
        assert_eq!(err.http_status(), http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn paused_alone_yields_agent_paused() {
        let err = enforce_agent_lifecycle_gate(true, false).expect_err("must reject");
        assert_eq!(err.reason_code(), Some("agent_paused"));
    }

    #[test]
    fn auth3_freshness_window_holds_for_30s() {
        let paused_at = Utc::now();
        let just_paused = paused_at + chrono::Duration::seconds(5);
        let err = enforce_paused_revocation_freshness(paused_at, just_paused)
            .expect_err("must reject inside window");
        assert_eq!(err.reason_code(), Some("agent_paused"));
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
        assert_eq!(err.reason_code(), Some("accountability_grant_missing"));
        assert_eq!(err.http_status(), http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pair_agent_key_error_contract_excludes_accountability_grant_missing() {
        let pair_agent_key_rejections = [
            AgentAuthRejection::VerificationMethodPrincipalMismatch,
            AgentAuthRejection::PairingRequestExpired,
            AgentAuthRejection::ProofInvalid,
            AgentAuthRejection::AgentDeactivated,
        ];

        assert!(
            !pair_agent_key_rejections.contains(&AgentAuthRejection::AccountabilityGrantMissing)
        );
    }

    #[test]
    fn unknown_accountability_grant_action_is_rejected() {
        let err = normalize_capabilities(vec!["ak.agent.unregistered".to_owned()])
            .expect_err("unknown action must fail closed");
        assert_eq!(err.status(), http::StatusCode::BAD_REQUEST);
        assert!(
            err.message()
                .contains("is not a registered ak.agent.* action")
        );
    }

    #[test]
    fn removed_agent_actions_are_rejected() {
        for action in [
            "ak.agent.key.rotate",
            "ak.agent.protocol.discover",
            "ak.agent.session.start",
            "ak.agent.session.cancel",
            "ak.agent.session.stream_status",
            "ak.agent.session.attach_artifact",
            "ak.agent.session.read_transcript",
        ] {
            normalize_capabilities(vec![action.to_owned()])
                .expect_err("removed v1 action must fail closed");
        }
    }

    #[test]
    fn capability_set_is_trimmed_sorted_and_deduplicated() {
        let normalized = normalize_capabilities(vec![
            " ak.self.agent.command.resume ".to_owned(),
            "ak.self.agent.command.provision".to_owned(),
            "ak.self.agent.command.resume".to_owned(),
        ])
        .expect("registered actions normalize");
        assert_eq!(
            normalized,
            vec![
                "ak.self.agent.command.provision".to_owned(),
                "ak.self.agent.command.resume".to_owned()
            ]
        );
    }

    #[test]
    fn capability_digest_is_stable_after_normalization() {
        let left = normalize_capabilities(vec![
            "ak.self.agent.command.resume".to_owned(),
            "ak.self.agent.command.provision".to_owned(),
        ])
        .unwrap();
        let right = normalize_capabilities(vec![
            " ak.self.agent.command.provision ".to_owned(),
            "ak.self.agent.command.resume".to_owned(),
            "ak.self.agent.command.resume".to_owned(),
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
        assert_eq!(err.reason_code(), Some("pairing_request_expired"));
        assert_eq!(err.http_status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn agent_pcr_recovery_not_ready_is_a_distinct_precondition() {
        let err = AgentAuthRejection::AgentPcrRecoveryNotReady;
        assert_eq!(err.reason_code(), Some("agent_pcr_recovery_not_ready"));
        assert_eq!(err.http_status(), http::StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn agent_key_authorization_expired_is_distinct_from_proof_invalid() {
        let err = AgentAuthRejection::AgentKeyAuthorizationExpired;
        assert_eq!(
            err.reason_code(),
            Some(arkret_core::error::REASON_AGENT_KEY_AUTHORIZATION_EXPIRED)
        );
        assert_eq!(err.http_status(), http::StatusCode::UNAUTHORIZED);
        assert_ne!(
            err.reason_code(),
            AgentAuthRejection::ProofInvalid.reason_code(),
            "runtime must be able to tell controller re-authorization apart from proof bugs"
        );
    }

    #[test]
    fn proof_signature_round_trips_over_canonical_signed_fields() {
        use base64ct::Encoding as _;
        use ed25519_dalek::Signer as _;

        let signing_key = derive_ed25519_from_seed(&[7u8; 32]);
        let multibase = multicodec_ed25519_public_key(&signing_key.verifying_key());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let fields = ProofSignedFields {
            audience: "https://arkret.example/_arkret",
            challenge: "challenge-abc",
            nonce: Some("nonce-abc"),
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
        use ed25519_dalek::Signer as _;

        let signing_key = derive_ed25519_from_seed(&[9u8; 32]);
        let multibase = multicodec_ed25519_public_key(&signing_key.verifying_key());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let signed = ProofSignedFields {
            audience: "https://arkret.example/_arkret",
            challenge: "challenge-abc",
            nonce: Some("nonce-abc"),
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let message = canonical_json_bytes(&signed).expect("canonical bytes");
        let signature = signing_key.sign(&message);
        let sig_b64 = base64ct::Base64UrlUnpadded::encode_string(&signature.to_bytes());

        // A different audience (replay to a different service) must fail closed.
        let tampered = ProofSignedFields {
            audience: "https://evil.example/_arkret",
            challenge: "challenge-abc",
            nonce: Some("nonce-abc"),
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let err = verify_proof_signature(&multibase, &tampered, &sig_b64)
            .expect_err("tampered audience must reject");
        assert_eq!(err.reason_code(), Some("proof_invalid"));
    }

    #[test]
    fn proof_signature_rejects_tampered_nonce() {
        use base64ct::Encoding as _;
        use ed25519_dalek::Signer as _;

        let signing_key = derive_ed25519_from_seed(&[10u8; 32]);
        let multibase = multicodec_ed25519_public_key(&signing_key.verifying_key());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let signed = ProofSignedFields {
            audience: "https://arkret.example/_arkret",
            challenge: "challenge-abc",
            nonce: Some("nonce-abc"),
            expires_at,
            request_canonical_digest: "sha256:aa",
            verification_method: "did:web:agent.example#runtime-key-1",
        };
        let message = canonical_json_bytes(&signed).expect("canonical bytes");
        let signature = signing_key.sign(&message);
        let sig_b64 = base64ct::Base64UrlUnpadded::encode_string(&signature.to_bytes());

        let tampered = ProofSignedFields {
            nonce: Some("nonce-def"),
            ..signed
        };
        let err = verify_proof_signature(&multibase, &tampered, &sig_b64)
            .expect_err("tampered nonce must reject");
        assert_eq!(err.reason_code(), Some("proof_invalid"));
    }
}
