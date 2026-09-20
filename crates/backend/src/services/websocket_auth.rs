//! Formal admission for the `challenge_dpop_session_v1` WebSocket proof.
//!
//! This service consumes the canonical SDK frame and verifier.  In
//! particular, it does not route the application proof through the HTTP DPoP
//! verifier.  The commit port is the only mutation boundary: signature and
//! challenge binding, followed by the formal test-material policy, all run
//! before it is called.

use arkret_identity::test_material::{
    FormalTestMaterialPolicyError, PublicKeyFingerprintInput, enforce_formal_test_material_policy,
};
use arkret_models_collaboration::sync_frames::websocket::WebSocketClientFrame;
use arkret_signatures::websocket_auth::{
    VerifiedWebSocketAuth, WebSocketAuthError, WebSocketAuthVerificationRequest,
    verify_websocket_auth_proof,
};
use arkret_wire::websocket_binding::WebSocketChallengeRecord;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Result of the atomic challenge/replay/auth-state commit.
///
/// Implementations must perform the three effects in one transaction: mark
/// the exact challenge consumed, insert `verified.replay_ledger_key`, and
/// establish the connection's authenticated state.  A conflict performs none
/// of those effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebSocketAuthenticationCommit {
    Authenticated,
    ChallengeUnavailable,
    Replay,
}

/// The state mutation boundary used after all formal admission checks pass.
#[async_trait]
pub trait WebSocketAuthenticationState: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn commit_verified_authentication(
        &mut self,
        challenge: &WebSocketChallengeRecord,
        verified: &VerifiedWebSocketAuth,
    ) -> Result<WebSocketAuthenticationCommit, Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum WebSocketAuthenticationError {
    #[error("the WebSocket frame is not authenticate")]
    ExpectedAuthenticateFrame,
    #[error(transparent)]
    Proof(#[from] WebSocketAuthError),
    #[error("test_signing_material_denied")]
    TestSigningMaterialDenied,
    #[error("the WebSocket confirmation key is not valid Ed25519 material")]
    InvalidConfirmationKey,
    #[error("the WebSocket authentication challenge is unavailable")]
    ChallengeUnavailable,
    #[error("the WebSocket authentication proof was replayed")]
    Replay,
    #[error("WebSocket authentication state commit failed: {0}")]
    State(String),
}

/// Verify and admit one canonical WebSocket `authenticate` frame.
///
/// A valid signature made by a published test key is deliberately verified
/// first and then rejected by policy.  This proves that the terminal denial is
/// the formal-material guard, while guaranteeing that no replay, cache or
/// authenticated-session mutation has occurred: the state port is not invoked
/// until after the guard returns `Ok(())`.
pub async fn admit_websocket_authentication<S: WebSocketAuthenticationState>(
    frame: &WebSocketClientFrame,
    socket_origin: &str,
    challenge: &WebSocketChallengeRecord,
    grant_cnf_jkt: &str,
    now: DateTime<Utc>,
    state: &mut S,
) -> Result<VerifiedWebSocketAuth, WebSocketAuthenticationError> {
    let WebSocketClientFrame::Authenticate {
        connection_id,
        session_grant,
        dpop_proof,
    } = frame
    else {
        return Err(WebSocketAuthenticationError::ExpectedAuthenticateFrame);
    };

    // Replay is committed (and race-checked) only through the atomic state
    // port below.  Passing false here cannot admit a replay because an `Ok`
    // from the crypto verifier is not itself an authentication decision.
    let verified = verify_websocket_auth_proof(&WebSocketAuthVerificationRequest {
        compact_jws: dpop_proof,
        connection_id,
        session_grant,
        socket_origin,
        challenge,
        grant_cnf_jkt,
        replay_ledger_hit: false,
        now,
    })?;

    let key_bytes = arkret_canonical::base64url_decode(&verified.proof.protected.jwk.x)
        .map_err(|_| WebSocketAuthenticationError::InvalidConfirmationKey)?;
    enforce_formal_test_material_policy(
        Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&key_bytes)),
        None,
        None,
        None,
    )
    .map_err(|error| match error {
        FormalTestMaterialPolicyError::Denied(_) => {
            WebSocketAuthenticationError::TestSigningMaterialDenied
        }
        FormalTestMaterialPolicyError::InvalidPublicKey(_) => {
            WebSocketAuthenticationError::InvalidConfirmationKey
        }
    })?;

    match state
        .commit_verified_authentication(challenge, &verified)
        .await
        .map_err(|error| WebSocketAuthenticationError::State(error.to_string()))?
    {
        WebSocketAuthenticationCommit::Authenticated => Ok(verified),
        WebSocketAuthenticationCommit::ChallengeUnavailable => {
            Err(WebSocketAuthenticationError::ChallengeUnavailable)
        }
        WebSocketAuthenticationCommit::Replay => Err(WebSocketAuthenticationError::Replay),
    }
}

#[cfg(test)]
mod tests {
    use arkret_signatures::websocket_auth::{
        WebSocketAuthProofRequest, build_websocket_auth_proof,
    };
    use arkret_wire::WebOrigin;
    use ed25519_dalek_3::SigningKey;

    use super::*;

    const BASE_URL: &str = "wss://server.example/_arkret/ws";
    const ORIGIN: &str = "https://app.example";
    const CONNECTION_ID: &str = "Y29ubmVjdGlvbi0wMTIzNDU2Nzg5YWJjZGVm";
    const NONCE: &str = "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZg";
    const GRANT: &str = "ak.session.grant.fixture.websocket.v1";
    const RFC8032_TEST_1_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    #[derive(Default)]
    struct RecordingState {
        commit_calls: usize,
        challenge_consumed: bool,
        replay_rows: usize,
        cache_rows: usize,
        authenticated_sessions: usize,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("recording state failure")]
    struct RecordingStateError;

    #[async_trait]
    impl WebSocketAuthenticationState for RecordingState {
        type Error = RecordingStateError;

        async fn commit_verified_authentication(
            &mut self,
            _challenge: &WebSocketChallengeRecord,
            _verified: &VerifiedWebSocketAuth,
        ) -> Result<WebSocketAuthenticationCommit, Self::Error> {
            self.commit_calls += 1;
            self.challenge_consumed = true;
            self.replay_rows += 1;
            self.cache_rows += 1;
            self.authenticated_sessions += 1;
            Ok(WebSocketAuthenticationCommit::Authenticated)
        }
    }

    fn challenge(now: DateTime<Utc>) -> WebSocketChallengeRecord {
        WebSocketChallengeRecord {
            connection_id: CONNECTION_ID.to_owned(),
            nonce: NONCE.to_owned(),
            canonical_origin: WebOrigin::new(ORIGIN).expect("canonical origin"),
            canonical_base_url: BASE_URL.to_owned(),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(5),
            consumed: false,
        }
    }

    fn frame(key: &SigningKey, now: DateTime<Utc>, jti: &str) -> (WebSocketClientFrame, String) {
        let proof = build_websocket_auth_proof(
            &WebSocketAuthProofRequest {
                base_url: BASE_URL,
                session_grant: GRANT,
                nonce: NONCE,
                issued_at: now,
                jti,
            },
            key,
        )
        .expect("proof builds");
        (
            WebSocketClientFrame::Authenticate {
                connection_id: CONNECTION_ID.to_owned(),
                session_grant: GRANT.to_owned(),
                dpop_proof: proof.compact_jws,
            },
            proof.jkt,
        )
    }

    #[tokio::test]
    async fn published_key_is_denied_before_every_state_effect() {
        let now = DateTime::from_timestamp(1_785_283_200, 0).expect("fixed instant");
        let challenge = challenge(now);
        let (frame, jkt) = frame(
            &SigningKey::from_bytes(&RFC8032_TEST_1_SEED),
            now,
            "d3MtYXV0aC1qdGktMDAwMQ",
        );
        let mut state = RecordingState::default();

        let error =
            admit_websocket_authentication(&frame, ORIGIN, &challenge, &jkt, now, &mut state)
                .await
                .expect_err("published material is terminal");

        assert!(matches!(
            error,
            WebSocketAuthenticationError::TestSigningMaterialDenied
        ));
        assert_eq!(error.to_string(), "test_signing_material_denied");
        assert_eq!(state.commit_calls, 0);
        assert!(!state.challenge_consumed);
        assert_eq!(state.replay_rows, 0);
        assert_eq!(state.cache_rows, 0);
        assert_eq!(state.authenticated_sessions, 0);
    }

    #[tokio::test]
    async fn unlisted_key_reaches_the_single_atomic_commit_boundary() {
        let now = DateTime::from_timestamp(1_785_283_200, 0).expect("fixed instant");
        let challenge = challenge(now);
        let (frame, jkt) = frame(
            &SigningKey::from_bytes(&[91; 32]),
            now,
            "d3MtYXV0aC1qdGktMDAwMg",
        );
        let mut state = RecordingState::default();

        admit_websocket_authentication(&frame, ORIGIN, &challenge, &jkt, now, &mut state)
            .await
            .expect("unlisted key is admitted");

        assert_eq!(state.commit_calls, 1);
        assert!(state.challenge_consumed);
        assert_eq!(state.replay_rows, 1);
        assert_eq!(state.cache_rows, 1);
        assert_eq!(state.authenticated_sessions, 1);
    }
}
