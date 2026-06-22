//! Onboarding-time + passkey-enrolment-time starid wire-in.
//!
//! Two entry points, both deferred until the user enrols a passkey:
//!
//! * [`mint_principal_did_for_first_credential`] — called from the passkey `register_finish` admin
//!   handler the **first** time an account enrols a credential. Derives an `update_key` from the
//!   passkey's COSE public key
//!   ([`crate::services::passkey_derive::derive_update_key_from_credential`]), posts `POST
//!   /_starid/root/webvh/dids` to starid, persists `(account → did, update_key, version_id)`, and
//!   flips `user.starid_backend = true` for deployments that explicitly use the
//!   personal-node `did:web` principal method.
//!
//! * [`rotate_principal_did_for_credential`] — called from the same handler on **subsequent**
//!   passkey enrolments (account already has a starid-minted DID). Derives the new device's
//!   `update_key`, looks up the prior `version_id` from the binding row, posts `POST
//!   /_starid/root/webvh/dids/{did}/update` to starid, and persists the bumped version.
//!
//! Round 37.4 contract change (rip-and-replace): the old
//! `mint_principal_did_if_configured` + `PLACEHOLDER_UPDATE_KEY` pair
//! is gone. Onboarding no longer mints a DID at user-creation time.
//! Accounts that never enrol a passkey no longer get an implicit `did:web`
//! principal in non-personal deployments; those paths must mint or load a
//! persisted `did:webvh` principal DID.

use coauth_data::{BoxRepository, RepositoryAccess, User};
use thiserror::Error;
use webauthn_rs::prelude::Passkey;

use crate::services::passkey_derive::derive_update_key_from_credential;
use crate::services::starid_adapter::{StaridError, StaridMintResult, StaridRegistryHandle};

/// Errors raised by the onboarding-starid wire-up.
#[derive(Debug, Error)]
pub enum OnboardingStaridError {
    #[error("starid call failed: {0}")]
    Starid(#[from] StaridError),

    #[error("repository error while persisting starid_backend flag: {0}")]
    Repository(#[from] coauth_data::RepositoryError),
}

/// Outcome of a successful mint or rotate. Returned so the caller can
/// surface the new `did` / `version_id` in the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalDidUpdate {
    pub user: User,
    pub mint: StaridMintResult,
}

/// Mint a managed `did:webvh` for `user`, controlled by an `update_key`
/// derived from `passkey`'s COSE public key. Flips
/// `user.starid_backend = true` in the same repository transaction.
///
/// Returns `Ok(None)` when no `StaridRegistryHandle` is wired into the
/// request (i.e., `[cokret.starid]` unset). The caller should treat
/// `None` as "starid integration disabled" and continue without a
/// managed DID — the account stays on the local derivation.
pub async fn mint_principal_did_for_first_credential(
    repo: &mut BoxRepository,
    registry: Option<&StaridRegistryHandle>,
    user: User,
    passkey: &Passkey,
) -> Result<Option<PrincipalDidUpdate>, OnboardingStaridError> {
    let Some(registry) = registry else {
        return Ok(None);
    };

    let update_key = derive_update_key_from_credential(passkey);
    let account_id = user.id.to_string();
    let mint = registry
        .create_principal_did(&account_id, &update_key)
        .await?;
    tracing::info!(
        account_id = %account_id,
        did = %mint.did,
        version_id = %mint.version_id,
        "starid: minted principal DID from first passkey enrolment",
    );

    let user = repo.user().set_starid_backend(user, true).await?;
    Ok(Some(PrincipalDidUpdate { user, mint }))
}

/// Rotate the existing DID's `update_keys` slot to a new device-bound
/// key derived from `new_passkey`. The prior `version_id` is supplied
/// by the caller — typically read from the
/// `account_identity_binding` row that was persisted by the original
/// [`mint_principal_did_for_first_credential`] call.
///
/// `did` is the canonical `did:webvh:…` that starid minted. Returns
/// `Ok(None)` when no `StaridRegistryHandle` is wired (matching the
/// mint helper).
pub async fn rotate_principal_did_for_credential(
    registry: Option<&StaridRegistryHandle>,
    did: &str,
    prev_version_id: &str,
    new_passkey: &Passkey,
) -> Result<Option<StaridMintResult>, OnboardingStaridError> {
    let Some(registry) = registry else {
        return Ok(None);
    };

    let new_update_key = derive_update_key_from_credential(new_passkey);
    let mint = registry
        .rotate_update_key(did, prev_version_id, &new_update_key)
        .await?;
    tracing::info!(
        did = %did,
        prev_version_id = %prev_version_id,
        new_version_id = %mint.version_id,
        "starid: rotated principal DID update_key on passkey re-enrolment",
    );
    Ok(Some(mint))
}

#[cfg(test)]
mod tests {
    //! Round 37.4 onboarding-starid tests.
    //!
    //! These exercise the contract between
    //! `mint_principal_did_for_first_credential` /
    //! `rotate_principal_did_for_credential` and a wiremock-backed
    //! `StaridResolver`. Pure unit tests against the real adapter (not
    //! a fake `StaridRegistry`) so the wire format stays under test.
    //!
    //! The mint test does *not* feed a real `Passkey` (constructing one
    //! requires a full `WebAuthn` registration ceremony with a fake
    //! authenticator that's out of scope here) — instead we exercise
    //! `StaridRegistry::create_principal_did` directly with the
    //! deterministic derived key string. The derivation contract itself
    //! is locked down in `services::passkey_derive::tests`.

    use std::sync::{Arc, Once};

    use coauth_config::{
        CokretConfig, DeploymentProfileConfig, PrincipalMethodConfig, StaridConfig,
    };
    use serde_json::json;
    use ulid::Ulid;
    use url::Url;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::services::did_resolver::{DefaultDidResolverService, DidResolverService};
    use crate::services::passkey_derive::derive_update_key_from_cose_bytes;
    use crate::services::starid_adapter::{StaridRegistryHandle, StaridResolver};

    /// rustls's process-wide default crypto provider; required for the
    /// `reqwest` client `StaridResolver::from_config` builds.
    fn install_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn starid_config(base: &str) -> StaridConfig {
        StaridConfig {
            base_url: Url::parse(base).unwrap(),
            did_host: Some("starid.local".to_owned()),
            path_prefix: "accounts".to_owned(),
            admin_token: None,
        }
    }

    /// `StaridRegistry::create_principal_did` produces a `did:webvh:…`
    /// when wiremock returns a healthy mint response, and the resolver
    /// adapter parses out the canonical DID + `version_id`. The
    /// `update_key` posted is the multibase-encoded passkey-derived
    /// string — not the pre-37.4 placeholder.
    #[tokio::test]
    async fn create_principal_did_returns_minted_did_from_starid_response() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let derived = derive_update_key_from_cose_bytes(b"fake-cose-key-bytes-for-test");
        Mock::given(method("POST"))
            .and(path("/_starid/root/webvh/dids"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "did": "did:webvh:ztest:starid.local:accounts:01arz3ndektsv4rrffq69g5fav",
                "scid": "ztest",
                "version_id": "1-zhead",
                "raw_document_digest": "zhash",
                "host": "starid.local",
                "path": "accounts/01arz3ndektsv4rrffq69g5fav",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = starid_config(&server.uri());
        let resolver: StaridRegistryHandle = Arc::new(StaridResolver::from_config(&cfg).unwrap());
        let result = resolver
            .create_principal_did("01ARZ3NDEKTSV4RRFFQ69G5FAV", &derived)
            .await
            .expect("starid mint succeeds");
        assert_eq!(
            result.did,
            "did:webvh:ztest:starid.local:accounts:01arz3ndektsv4rrffq69g5fav"
        );
        assert_eq!(result.version_id, "1-zhead");
        assert!(
            derived.starts_with("z6Mk"),
            "passkey-derived update_key uses the multibase ed25519 envelope",
        );
    }

    /// `StaridRegistry::rotate_update_key` posts to the `/update`
    /// endpoint with the new device-derived key, and parses the bumped
    /// `version_id` out of the response.
    #[tokio::test]
    async fn rotate_update_key_returns_bumped_version_id() {
        install_crypto_provider();
        let server = MockServer::start().await;
        let new_key = derive_update_key_from_cose_bytes(b"second-passkey-cose-bytes");
        Mock::given(method("POST"))
            .and(path_regex(r"^/_starid/root/webvh/dids/.+/update$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "did": "did:webvh:ztest:starid.local:accounts:01arz3ndektsv4rrffq69g5fav",
                "scid": "ztest",
                "version_id": "2-zrotated",
                "raw_document_digest": "zhash",
                "host": "starid.local",
                "path": "accounts/01arz3ndektsv4rrffq69g5fav",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = starid_config(&server.uri());
        let resolver: StaridRegistryHandle = Arc::new(StaridResolver::from_config(&cfg).unwrap());
        let result = resolver
            .rotate_update_key(
                "did:webvh:ztest:starid.local:accounts:01arz3ndektsv4rrffq69g5fav",
                "1-zhead",
                &new_key,
            )
            .await
            .expect("starid rotate succeeds");
        assert_eq!(result.version_id, "2-zrotated");
    }

    /// When `starid_backend = true` and `[cokret.starid]` is configured,
    /// `DefaultDidResolverService::primary_did_for_user` returns the
    /// deterministic `did:web:<host>:<path_prefix>:<slug>` form (the
    /// alias of what starid minted).
    #[tokio::test]
    async fn primary_did_for_user_routes_to_starid_form_when_flag_set() {
        install_crypto_provider();
        let resolver = DefaultDidResolverService;
        let cokret_config = CokretConfig {
            deployment_profile: DeploymentProfileConfig::PersonalNode,
            principal_method: PrincipalMethodConfig::DidWeb,
            starid: Some(StaridConfig {
                base_url: Url::parse("https://starid.example").unwrap(),
                did_host: Some("starid.local".to_owned()),
                path_prefix: "accounts".to_owned(),
                admin_token: None,
            }),
            ..CokretConfig::default()
        };

        let user_id = Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let mut user = sample_user(user_id);
        user.starid_backend = true;
        let did = resolver
            .primary_did_for_user(&cokret_config, &user)
            .await
            .unwrap();
        assert_eq!(
            did, "did:web:starid.local:accounts:01arz3ndektsv4rrffq69g5fav",
            "starid_backend=true must produce the starid alias form, not the local derivation",
        );

        // Sanity: same user without the flag stays on the local form.
        user.starid_backend = false;
        let local = resolver
            .primary_did_for_user(&cokret_config, &user)
            .await
            .unwrap();
        assert_eq!(
            local, "did:web:coauth.invalid:accounts:01arz3ndektsv4rrffq69g5fav",
            "starid_backend=false uses the local derivation",
        );
    }

    #[tokio::test]
    async fn primary_did_for_user_rejects_did_web_without_explicit_personal_node_gate() {
        let resolver = DefaultDidResolverService;
        let user_id = Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let user = sample_user(user_id);

        let error = resolver
            .primary_did_for_user(&CokretConfig::default(), &user)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::handlers::cokret::SessionGrantError::DidWebPrincipalNotExplicit
        ));
    }

    fn sample_user(id: Ulid) -> coauth_data::User {
        coauth_data::User {
            id,
            localpart: "alice".to_owned(),
            sub: id.to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            status: cokret_core::AccountStatus::Active,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: false,
            display_name: None,
            avatar_url: None,
            preferred_locale: None,
            starid_backend: false,
            handle_aliases: Vec::new(),
        }
    }
}
