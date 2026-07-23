use chrono::Duration;
use coauth_data::audit::{HandleAuditEventType, NewHandleAuditEvent};
use coauth_data::clock::MockClock;
use coauth_data::upstream_oauth::{UpstreamOAuthProviderParams, UpstreamOAuthSessionFilter};
use coauth_data::user::{
    BrowserSessionFilter, BrowserSessionRepository, PrincipalDidRepository, UserEmailFilter,
    UserEmailRepository, UserFilter, UserPasswordRepository, UserRepository,
    VerifiedPrincipalDidBindingInput,
};
use coauth_data::{
    Clock, NewUserPrimaryHandlePreference, Pagination, RepositoryAccess as _,
    RepositoryFactory as _, UserEmailPatch, UserPatch, UserProfilePatch,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_oauth_types::scope::{OPENID, Scope};
use diesel_async::RunQueryDsl;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use crate::PgRepositoryFactory;

fn principal_binding_test_material(
    label: &str,
) -> (
    String,
    arkret_identifiers::Hash,
    arkret_identifiers::Did,
    String,
) {
    let principal_id = format!("did:webvh:z{label}:example.com:users:alice");
    let key_log_head = arkret_identifiers::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    let enrollment_authority_did = arkret_identifiers::Did::new("did:key:z6Mkenrollment").unwrap();
    let enrollment_authority_ref = format!("{principal_id}#arkret-device-enrollment-authority");
    (
        principal_id,
        key_log_head,
        enrollment_authority_did,
        enrollment_authority_ref,
    )
}

fn verified_principal_binding_input(
    audience: impl Into<String>,
    principal_id: String,
    key_log_head: arkret_identifiers::Hash,
    enrollment_authority_did: arkret_identifiers::Did,
    enrollment_authority_ref: String,
) -> VerifiedPrincipalDidBindingInput {
    VerifiedPrincipalDidBindingInput {
        audience: audience.into(),
        principal_id,
        key_log_head,
        enrollment_authority_did,
        enrollment_authority_ref,
    }
}

/// Test the user repository, by adding and looking up a user
#[tokio::test]
async fn test_user_repo() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    const USERNAME: &str = "john";

    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let all = UserFilter::new();
    let admin = all.can_request_admin_only();
    let non_admin = all.cannot_request_admin_only();
    let active = all.active_only();
    let locked = all.locked_only();
    let deactivated = all.deactivated_only();

    // Initially, the user shouldn't exist
    assert!(!repo.user().exists(USERNAME).await.unwrap());
    assert!(
        repo.user()
            .find_by_handle(USERNAME)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(repo.user().count(all).await.unwrap(), 0);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(active).await.unwrap(), 0);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Adding the user should work
    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // And now it should exist
    assert!(repo.user().exists(USERNAME).await.unwrap());
    assert!(
        repo.user()
            .find_by_handle(USERNAME)
            .await
            .unwrap()
            .is_some()
    );
    assert!(repo.user().lookup(user.id).await.unwrap().is_some());

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 1);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Adding a second time should give a conflict
    // It should not poison the transaction though
    assert!(
        repo.user()
            .add(&mut rng, &clock, USERNAME.to_owned())
            .await
            .is_err()
    );

    // Try locking a user
    assert!(user.is_valid());
    let user = repo.user().lock(&clock, user).await.unwrap();
    assert!(!user.is_valid());

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 0);
    assert_eq!(repo.user().count(locked).await.unwrap(), 1);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(!user.is_valid());

    // Locking a second time should not fail
    let user = repo.user().lock(&clock, user).await.unwrap();
    assert!(!user.is_valid());

    // Try unlocking a user
    let user = repo.user().unlock(user).await.unwrap();
    assert!(user.is_valid());

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(user.is_valid());

    // Unlocking a second time should not fail
    let user = repo.user().unlock(user).await.unwrap();
    assert!(user.is_valid());

    // Set the can_request_admin flag
    let user = repo.user().set_can_request_admin(user, true).await.unwrap();
    assert!(user.can_request_admin);

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(active).await.unwrap(), 1);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(user.can_request_admin);

    // Unset the can_request_admin flag
    let user = repo
        .user()
        .set_can_request_admin(user, false)
        .await
        .unwrap();
    assert!(!user.can_request_admin);

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(!user.can_request_admin);

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 1);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 0);

    // Deactivating the user should work
    let user = repo.user().deactivate(&clock, user).await.unwrap();
    assert!(user.deactivated_at.is_some());

    // Check that the property is retrieved on lookup
    let user = repo.user().lookup(user.id).await.unwrap().unwrap();
    assert!(user.deactivated_at.is_some());

    // Deactivating a second time should not fail
    let user = repo.user().deactivate(&clock, user).await.unwrap();
    assert!(user.deactivated_at.is_some());

    assert_eq!(repo.user().count(all).await.unwrap(), 1);
    assert_eq!(repo.user().count(admin).await.unwrap(), 0);
    assert_eq!(repo.user().count(non_admin).await.unwrap(), 1);
    assert_eq!(repo.user().count(active).await.unwrap(), 0);
    assert_eq!(repo.user().count(locked).await.unwrap(), 0);
    assert_eq!(repo.user().count(deactivated).await.unwrap(), 1);

    // Test the search filter
    assert_eq!(
        repo.user()
            .count(all.matching_search("alice"))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        repo.user().count(all.matching_search("JO")).await.unwrap(),
        1
    );

    // Check the list method
    let list = repo.user().list(all, Pagination::first(10)).await.unwrap();
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node.id, user.id);

    let list = repo
        .user()
        .list(admin, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 0);

    let list = repo
        .user()
        .list(non_admin, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node.id, user.id);

    let list = repo
        .user()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 0);

    let list = repo
        .user()
        .list(locked, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 0);

    let list = repo
        .user()
        .list(deactivated, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(list.edges.len(), 1);
    assert_eq!(list.edges[0].node.id, user.id);

    repo.save().await.unwrap();
}

#[tokio::test]
async fn primary_handle_preference_versions_current_and_as_of() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };

    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(0x4844_4c31);
    let clock = MockClock::default();
    let user = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();
    let handle = "alice:example.com";

    assert!(
        repo.user_primary_handle_preference()
            .current(user.id)
            .await
            .unwrap()
            .is_none()
    );

    let claim = repo
        .handle_audit()
        .record(
            &mut rng,
            &clock,
            NewHandleAuditEvent::new(HandleAuditEventType::ClaimIssued)
                .with_user(user.id)
                .with_handle(handle)
                .with_claim_digest("sha256:primary"),
        )
        .await
        .unwrap();

    let verified = repo
        .user_primary_handle_preference()
        .verified_handle_claim(user.id, handle, clock.now())
        .await
        .unwrap()
        .expect("claim_issued audit event should verify the holder handle");
    assert_eq!(verified.id, claim.id);
    assert_eq!(verified.claim_digest, "sha256:primary");

    let first = repo
        .user_primary_handle_preference()
        .set(
            &mut rng,
            &clock,
            NewUserPrimaryHandlePreference::self_service(
                user.id,
                Some(handle.to_owned()),
                Some(&verified),
                user.id,
            ),
        )
        .await
        .unwrap();
    assert_eq!(first.handle.as_deref(), Some(handle));
    let first_effective_at = first.effective_at;

    clock.advance(Duration::seconds(60));
    let cleared = repo
        .user_primary_handle_preference()
        .set(
            &mut rng,
            &clock,
            NewUserPrimaryHandlePreference::self_service(user.id, None, None, user.id),
        )
        .await
        .unwrap();
    assert_eq!(cleared.handle, None);

    let current = repo
        .user_primary_handle_preference()
        .current(user.id)
        .await
        .unwrap()
        .expect("clear operation is persisted as current version");
    assert_eq!(current.id, cleared.id);
    assert_eq!(current.handle, None);

    let as_of_first = repo
        .user_primary_handle_preference()
        .at(user.id, first_effective_at)
        .await
        .unwrap()
        .expect("as-of lookup should return historical preference");
    assert_eq!(as_of_first.id, first.id);
    assert_eq!(as_of_first.handle.as_deref(), Some(handle));
}

#[tokio::test]
async fn primary_handle_verified_claim_rejects_unknown_wrong_holder_and_expired_claims() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };

    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(0x4844_4c32);
    let clock = MockClock::default();
    let alice = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();
    let bob = repo
        .user()
        .add(&mut rng, &clock, "bob".to_owned())
        .await
        .unwrap();
    let handle = "alice:example.com";

    assert!(
        repo.user_primary_handle_preference()
            .verified_handle_claim(alice.id, handle, clock.now())
            .await
            .unwrap()
            .is_none()
    );

    repo.handle_audit()
        .record(
            &mut rng,
            &clock,
            NewHandleAuditEvent::new(HandleAuditEventType::ClaimIssued)
                .with_user(alice.id)
                .with_handle(handle)
                .with_claim_digest("sha256:alice"),
        )
        .await
        .unwrap();

    assert!(
        repo.user_primary_handle_preference()
            .verified_handle_claim(bob.id, handle, clock.now())
            .await
            .unwrap()
            .is_none(),
        "a different holder must not be able to use alice's handle claim"
    );

    clock.advance(Duration::seconds(60));
    repo.handle_audit()
        .record(
            &mut rng,
            &clock,
            NewHandleAuditEvent::new(HandleAuditEventType::ClaimExpired)
                .with_user(alice.id)
                .with_handle(handle),
        )
        .await
        .unwrap();

    assert!(
        repo.user_primary_handle_preference()
            .verified_handle_claim(alice.id, handle, clock.now())
            .await
            .unwrap()
            .is_none(),
        "expired claim evidence must not verify a preference"
    );

    clock.advance(Duration::seconds(60));
    repo.handle_audit()
        .record(
            &mut rng,
            &clock,
            NewHandleAuditEvent::new(HandleAuditEventType::ClaimIssued)
                .with_user(alice.id)
                .with_handle(handle)
                .with_claim_digest("sha256:alice-renewed"),
        )
        .await
        .unwrap();
    assert!(
        repo.user_primary_handle_preference()
            .verified_handle_claim(alice.id, handle, clock.now())
            .await
            .unwrap()
            .is_some(),
        "renewed claim evidence should verify again before revocation"
    );

    clock.advance(Duration::seconds(60));
    repo.handle_audit()
        .record(
            &mut rng,
            &clock,
            NewHandleAuditEvent::new(HandleAuditEventType::Revoked)
                .with_user(alice.id)
                .with_handle(handle),
        )
        .await
        .unwrap();
    assert!(
        repo.user_primary_handle_preference()
            .verified_handle_claim(alice.id, handle, clock.now())
            .await
            .unwrap()
            .is_none(),
        "revoked claim evidence must not verify a preference"
    );
}

/// Test [`UserRepository::find_by_handle`] with equivalent profile inputs.
#[tokio::test]
async fn test_user_repo_find_by_handle() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let alice = repo
        .user()
        .add(&mut rng, &clock, "Alice".to_owned())
        .await
        .unwrap();
    assert_eq!(alice.localpart, "alice");

    let xiaoming = repo
        .user()
        .add(&mut rng, &clock, "小明".to_owned())
        .await
        .unwrap();

    assert_eq!(
        repo.user().find_by_handle("alice").await.unwrap(),
        Some(alice.clone())
    );
    assert_eq!(
        repo.user().find_by_handle("ＡＬＩＣＥ").await.unwrap(),
        Some(alice)
    );
    assert_eq!(
        repo.user().find_by_handle("小明").await.unwrap(),
        Some(xiaoming)
    );
    assert!(repo.user().find_by_handle("bob").await.unwrap().is_none());

    let duplicate = repo
        .user()
        .add(&mut rng, &clock, "ALICE".to_owned())
        .await
        .unwrap_err();
    assert!(duplicate.is_unique_violation());
}

#[tokio::test]
async fn test_user_patch_updates_profile_and_state() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();

    clock.advance(chrono::Duration::seconds(5));

    let updated = repo
        .user()
        .patch(
            &clock,
            user,
            UserPatch {
                display_name: Some(Some("Alice Example".to_owned())),
                avatar_url: Some(Some("mxc://example.com/alice".to_owned())),
                preferred_locale: Some(Some("zh-CN".to_owned())),
                can_request_admin: Some(true),
                status: None,
                locked: Some(true),
                deactivated: Some(true),
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(
        updated.avatar_url.as_deref(),
        Some("mxc://example.com/alice")
    );
    assert_eq!(updated.preferred_locale.as_deref(), Some("zh-CN"));
    assert!(updated.can_request_admin);
    assert!(updated.locked_at.is_some());
    assert!(updated.deactivated_at.is_some());

    let reloaded = repo.user().lookup(updated.id).await.unwrap().unwrap();
    assert_eq!(reloaded.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(
        reloaded.avatar_url.as_deref(),
        Some("mxc://example.com/alice")
    );
    assert_eq!(reloaded.preferred_locale.as_deref(), Some("zh-CN"));
    assert!(reloaded.can_request_admin);
    assert!(reloaded.locked_at.is_some());
    assert!(reloaded.deactivated_at.is_some());
}

#[tokio::test]
async fn test_user_update_profile_empty_patch_is_noop() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();

    let updated = repo
        .user()
        .update_profile(&clock, user.clone(), UserProfilePatch::default())
        .await
        .unwrap();

    assert_eq!(updated, user);
}

#[tokio::test]
async fn test_user_email_patch_swaps_primary_email() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();
    let primary = repo
        .user_email()
        .add(&mut rng, &clock, &user, "alice@example.com".to_owned())
        .await
        .unwrap();
    let secondary = repo
        .user_email()
        .add(
            &mut rng,
            &clock,
            &user,
            "alice+secondary@example.com".to_owned(),
        )
        .await
        .unwrap();

    clock.advance(chrono::Duration::seconds(5));

    let updated = repo
        .user_email()
        .patch(
            &clock,
            secondary,
            UserEmailPatch {
                email: Some("alice+updated@example.com".to_owned()),
                confirmed: Some(false),
                is_primary: Some(true),
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.email, "alice+updated@example.com");
    assert!(updated.confirmed_at.is_none());
    assert!(updated.is_primary);

    let reloaded_primary = repo.user_email().lookup(primary.id).await.unwrap().unwrap();
    let reloaded_updated = repo.user_email().lookup(updated.id).await.unwrap().unwrap();
    assert!(!reloaded_primary.is_primary);
    assert!(reloaded_updated.is_primary);
}

/// Test the user email repository, by trying out most of its methods
#[tokio::test]
async fn test_user_email_repo() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    const USERNAME: &str = "john";
    const EMAIL: &str = "john@example.com";
    // This is what is stored in the database, making sure that:
    //  1. we don't normalize the email address when storing it
    //  2. looking it up is case-incensitive
    const UPPERCASE_EMAIL: &str = "JOHN@EXAMPLE.COM";

    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // The user email should not exist yet
    assert!(
        repo.user_email()
            .find(&user, EMAIL)
            .await
            .unwrap()
            .is_none()
    );

    let all = UserEmailFilter::new().for_user(&user);

    // Check the counts
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);

    let user_email = repo
        .user_email()
        .add(&mut rng, &clock, &user, UPPERCASE_EMAIL.to_owned())
        .await
        .unwrap();

    assert_eq!(user_email.user_id, user.id);
    assert_eq!(user_email.email, UPPERCASE_EMAIL);

    // Check the counts
    assert_eq!(repo.user_email().count(all).await.unwrap(), 1);

    assert!(
        repo.user_email()
            .find(&user, EMAIL)
            .await
            .unwrap()
            .is_some()
    );

    let user_email = repo
        .user_email()
        .lookup(user_email.id)
        .await
        .unwrap()
        .expect("user email was not found");

    assert_eq!(user_email.user_id, user.id);
    assert_eq!(user_email.email, UPPERCASE_EMAIL);

    // Listing the user emails should work
    let emails = repo
        .user_email()
        .list(all, Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert_eq!(emails.edges.len(), 1);
    assert_eq!(emails.edges[0].node, user_email);

    // Listing emails from the email address should work
    let emails = repo
        .user_email()
        .list(all.for_email(EMAIL), Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert_eq!(emails.edges.len(), 1);
    assert_eq!(emails.edges[0].node, user_email);

    // Filtering on another email should not return anything
    let emails = repo
        .user_email()
        .list(all.for_email("hello@example.com"), Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert!(emails.edges.is_empty());

    // Counting also works with the email filter
    assert_eq!(
        repo.user_email().count(all.for_email(EMAIL)).await.unwrap(),
        1
    );
    assert_eq!(
        repo.user_email()
            .count(all.for_email("hello@example.com"))
            .await
            .unwrap(),
        0
    );

    // Deleting the user email should work
    repo.user_email().remove(user_email).await.unwrap();
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);

    // Add a few emails
    for i in 0..5 {
        let email = format!("email{i}@example.com");
        repo.user_email()
            .add(&mut rng, &clock, &user, email)
            .await
            .unwrap();
    }
    assert_eq!(repo.user_email().count(all).await.unwrap(), 5);

    // Try removing all the emails
    let affected = repo.user_email().remove_bulk(all).await.unwrap();
    assert_eq!(affected, 5);
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);

    repo.save().await.unwrap();
}

/// Test the authentication codes methods in the user email repository
#[tokio::test]
async fn test_user_email_repo_authentications() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    // Create a user and a user session so that we can create an authentication
    let user = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();

    let browser_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, None)
        .await
        .unwrap();

    // Create an authentication session
    let authentication = repo
        .user_email()
        .add_authentication_for_session(
            &mut rng,
            &clock,
            "alice@example.com".to_owned(),
            &browser_session,
        )
        .await
        .unwrap();

    assert_eq!(authentication.email, "alice@example.com");
    assert_eq!(authentication.user_session_id, Some(browser_session.id));
    assert_eq!(authentication.created_at, clock.now());
    assert_eq!(authentication.completed_at, None);

    // Check that we can find the authentication by its ID
    let lookup = repo
        .user_email()
        .lookup_authentication(authentication.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lookup.id, authentication.id);
    assert_eq!(lookup.email, "alice@example.com");
    assert_eq!(lookup.user_session_id, Some(browser_session.id));
    assert_eq!(lookup.created_at, clock.now());
    assert_eq!(lookup.completed_at, None);

    // Add a code to the session
    let code = repo
        .user_email()
        .add_authentication_code(
            &mut rng,
            &clock,
            Duration::minutes(5),
            &authentication,
            "123456".to_owned(),
        )
        .await
        .unwrap();

    assert_eq!(code.code, "123456");
    assert_eq!(code.created_at, clock.now());
    assert_eq!(code.expires_at, clock.now() + Duration::minutes(5));

    // Check that we can find the code by its ID
    let id = code.id;
    let lookup = repo
        .user_email()
        .find_authentication_code(&authentication, "123456")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(lookup.id, id);
    assert_eq!(lookup.code, "123456");
    assert_eq!(lookup.created_at, clock.now());
    assert_eq!(lookup.expires_at, clock.now() + Duration::minutes(5));

    // Complete the authentication
    let authentication = repo
        .user_email()
        .complete_authentication_with_code(&clock, authentication, &code)
        .await
        .unwrap();

    assert_eq!(authentication.id, authentication.id);
    assert_eq!(authentication.email, "alice@example.com");
    assert_eq!(authentication.user_session_id, Some(browser_session.id));
    assert_eq!(authentication.created_at, clock.now());
    assert_eq!(authentication.completed_at, Some(clock.now()));

    // Check that we can find the completed authentication by its ID
    let lookup = repo
        .user_email()
        .lookup_authentication(authentication.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lookup.id, authentication.id);
    assert_eq!(lookup.email, "alice@example.com");
    assert_eq!(lookup.user_session_id, Some(browser_session.id));
    assert_eq!(lookup.created_at, clock.now());
    assert_eq!(lookup.completed_at, Some(clock.now()));

    // Completing a second time should fail
    let res = repo
        .user_email()
        .complete_authentication_with_code(&clock, authentication, &code)
        .await;
    assert!(res.is_err());
}

/// Test the user password repository implementation.
#[tokio::test]
async fn test_user_password_repo() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    const USERNAME: &str = "john";
    const FIRST_PASSWORD_HASH: &str = "doesntmatter";
    const SECOND_PASSWORD_HASH: &str = "alsodoesntmatter";

    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // User should have no active password
    assert!(repo.user_password().active(&user).await.unwrap().is_none());

    // Insert a first password
    let first_password = repo
        .user_password()
        .add(
            &mut rng,
            &clock,
            &user,
            1,
            FIRST_PASSWORD_HASH.to_owned(),
            None,
        )
        .await
        .unwrap();

    // User should now have an active password
    let first_password_lookup = repo
        .user_password()
        .active(&user)
        .await
        .unwrap()
        .expect("user should have an active password");

    assert_eq!(first_password.id, first_password_lookup.id);
    assert_eq!(first_password_lookup.hashed_password, FIRST_PASSWORD_HASH);
    assert_eq!(first_password_lookup.version, 1);
    assert_eq!(first_password_lookup.upgraded_from_id, None);

    // Getting the last inserted password is based on the clock, so we need to
    // advance it
    clock.advance(Duration::microseconds(10 * 1000 * 1000));

    let second_password = repo
        .user_password()
        .add(
            &mut rng,
            &clock,
            &user,
            2,
            SECOND_PASSWORD_HASH.to_owned(),
            Some(&first_password),
        )
        .await
        .unwrap();

    // User should now have an active password
    let second_password_lookup = repo
        .user_password()
        .active(&user)
        .await
        .unwrap()
        .expect("user should have an active password");

    assert_eq!(second_password.id, second_password_lookup.id);
    assert_eq!(second_password_lookup.hashed_password, SECOND_PASSWORD_HASH);
    assert_eq!(second_password_lookup.version, 2);
    assert_eq!(
        second_password_lookup.upgraded_from_id,
        Some(first_password.id)
    );

    repo.save().await.unwrap();
}

#[tokio::test]
async fn test_user_session() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let alice = repo
        .user()
        .add(&mut rng, &clock, "alice".to_owned())
        .await
        .unwrap();

    let bob = repo
        .user()
        .add(&mut rng, &clock, "bob".to_owned())
        .await
        .unwrap();

    let all = BrowserSessionFilter::default();
    let active = all.active_only();
    let finished = all.finished_only();

    assert_eq!(repo.browser_session().count(all).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 0);

    let session = repo
        .browser_session()
        .add(&mut rng, &clock, &alice, None)
        .await
        .unwrap();
    assert_eq!(session.user.id, alice.id);
    assert!(session.finished_at.is_none());

    assert_eq!(repo.browser_session().count(all).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 0);

    // The session should be in the list of active sessions
    let session_list = repo
        .browser_session()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert!(!session_list.has_next_page);
    assert_eq!(session_list.edges.len(), 1);
    assert_eq!(session_list.edges[0].node, session);

    let session_lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("user session not found");

    assert_eq!(session_lookup.id, session.id);
    assert_eq!(session_lookup.user.id, alice.id);
    assert!(session_lookup.finished_at.is_none());

    // Finish the session
    repo.browser_session()
        .finish(&clock, session_lookup)
        .await
        .unwrap();

    // The active session counter should be 0, and the finished one should be 1
    assert_eq!(repo.browser_session().count(all).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 1);

    // The session should not be in the list of active sessions anymore
    let session_list = repo
        .browser_session()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert!(!session_list.has_next_page);
    assert!(session_list.edges.is_empty());

    // Reload the session
    let session_lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("user session not found");

    assert_eq!(session_lookup.id, session.id);
    assert_eq!(session_lookup.user.id, alice.id);
    // This time the session is finished
    assert!(session_lookup.finished_at.is_some());

    // Create a bunch of other sessions
    for _ in 0..5 {
        for user in &[&alice, &bob] {
            repo.browser_session()
                .add(&mut rng, &clock, user, None)
                .await
                .unwrap();
        }
    }

    let all_alice = BrowserSessionFilter::new().for_user(&alice);
    let active_alice = BrowserSessionFilter::new().for_user(&alice).active_only();
    let all_bob = BrowserSessionFilter::new().for_user(&bob);
    let active_bob = BrowserSessionFilter::new().for_user(&bob).active_only();
    assert_eq!(repo.browser_session().count(all).await.unwrap(), 11);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 10);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(all_alice).await.unwrap(), 6);
    assert_eq!(repo.browser_session().count(active_alice).await.unwrap(), 5);
    assert_eq!(repo.browser_session().count(all_bob).await.unwrap(), 5);
    assert_eq!(repo.browser_session().count(active_bob).await.unwrap(), 5);

    // Finish all the sessions for alice
    let affected = repo
        .browser_session()
        .finish_bulk(&clock, active_alice)
        .await
        .unwrap();
    assert_eq!(affected, 5);
    assert_eq!(repo.browser_session().count(all_alice).await.unwrap(), 6);
    assert_eq!(repo.browser_session().count(active_alice).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 6);

    // Finish all the sessions for bob
    let affected = repo
        .browser_session()
        .finish_bulk(&clock, active_bob)
        .await
        .unwrap();
    assert_eq!(affected, 5);
    assert_eq!(repo.browser_session().count(all_bob).await.unwrap(), 5);
    assert_eq!(repo.browser_session().count(active_bob).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 11);

    // Checking the 'authenticaated by upstream sessions' filter
    // We need a provider
    let provider = repo
        .upstream_oauth_provider()
        .add(
            &mut rng,
            &clock,
            UpstreamOAuthProviderParams {
                issuer: None,
                human_name: None,
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: coauth_data::UpstreamOAuthProviderTokenAuthMethod::None,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                client_id: "client".to_owned(),
                encrypted_client_secret: None,
                claims_imports: coauth_data::UpstreamOAuthProviderClaimsImports::default(),
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                userinfo_endpoint_override: None,
                jwks_uri_override: None,
                discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Disabled,
                pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Disabled,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                ui_order: 0,
                on_backchannel_logout:
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )
        .await
        .unwrap();

    // Start a authorization session
    let upstream_oauth_session = repo
        .upstream_oauth_session()
        .add(&mut rng, &clock, &provider, "state".to_owned(), None, None)
        .await
        .unwrap();

    // Start a browser session
    let session = repo
        .browser_session()
        .add(&mut rng, &clock, &alice, None)
        .await
        .unwrap();

    // Make the session from alice authenticated by this session
    repo.browser_session()
        .authenticate_with_upstream(&mut rng, &clock, &session, &upstream_oauth_session)
        .await
        .unwrap();

    // This will match all authorization sessions, which matches exactly that one
    // authorization session
    let upstream_oauth_session_filter = UpstreamOAuthSessionFilter::new();
    let filter = BrowserSessionFilter::new()
        .authenticated_by_upstream_sessions_only(upstream_oauth_session_filter);

    // Now try to look it up
    let page = repo
        .browser_session()
        .list(filter, Pagination::first(10))
        .await
        .unwrap();
    assert_eq!(page.edges.len(), 1);
    assert_eq!(page.edges[0].node.id, session.id);

    // Try counting
    assert_eq!(repo.browser_session().count(filter).await.unwrap(), 1);

    // Try finishing the session
    let affected = repo
        .browser_session()
        .finish_bulk(&clock, filter)
        .await
        .unwrap();
    assert_eq!(affected, 1);

    // Lookup the session by its ID
    let lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("session to be found in the database");
    // It should be finished
    assert!(lookup.finished_at.is_some());
}

#[tokio::test]
async fn test_user_terms() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let mut repo = PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, "john".to_owned())
        .await
        .unwrap();

    // Accepting the terms should work
    repo.user_terms()
        .accept_terms(
            &mut rng,
            &clock,
            &user,
            "https://example.com/terms".parse().unwrap(),
        )
        .await
        .unwrap();

    // Accepting a second time should also work
    repo.user_terms()
        .accept_terms(
            &mut rng,
            &clock,
            &user,
            "https://example.com/terms".parse().unwrap(),
        )
        .await
        .unwrap();

    // Accepting a different terms should also work
    repo.user_terms()
        .accept_terms(
            &mut rng,
            &clock,
            &user,
            "https://example.com/terms?v=2".parse().unwrap(),
        )
        .await
        .unwrap();

    repo.save().await.unwrap();

    #[derive(diesel::QueryableByName)]
    struct CountResult {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }

    // We should have two rows, as the first terms was deduped
    let mut conn = pool.get().await.unwrap();
    let res = diesel::sql_query("SELECT COUNT(*) FROM user_terms")
        .get_result::<CountResult>(&mut *conn)
        .await
        .unwrap()
        .count;
    assert_eq!(res, 2);
}

#[tokio::test]
async fn principal_did_has_one_global_owner_under_concurrent_binding() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = PgRepositoryFactory::new(pool);
    let label = uuid::Uuid::now_v7().simple().to_string();
    let clock = MockClock::default();
    let mut rng = ChaChaRng::seed_from_u64(71);

    let mut repo = factory.create().await.unwrap();
    let alice = repo
        .user()
        .add(&mut rng, &clock, format!("alice-{label}"))
        .await
        .unwrap();
    let bob = repo
        .user()
        .add(&mut rng, &clock, format!("bob-{label}"))
        .await
        .unwrap();
    let alice_id = alice.id;
    let bob_id = bob.id;
    repo.save().await.unwrap();

    let (principal_id, key_log_head, enrollment_authority_did, authority_ref) =
        principal_binding_test_material(&label);
    let first_factory = factory.clone();
    let first_principal_id = principal_id.clone();
    let first_head = key_log_head.clone();
    let first_authority = enrollment_authority_did.clone();
    let first_ref = authority_ref.clone();
    let first = async move {
        let mut repo = first_factory.create().await.unwrap();
        let mut rng = ChaChaRng::seed_from_u64(72);
        let result = repo
            .principal_did()
            .add_verified(
                &mut rng,
                &MockClock::default(),
                &alice,
                verified_principal_binding_input(
                    "https://ps-a.example",
                    first_principal_id,
                    first_head,
                    first_authority,
                    first_ref,
                ),
            )
            .await;
        if result.is_ok() {
            repo.save().await.unwrap();
            true
        } else {
            repo.cancel().await.unwrap();
            false
        }
    };

    let second_factory = factory.clone();
    let second_principal_id = principal_id.clone();
    let second = async move {
        let mut repo = second_factory.create().await.unwrap();
        let mut rng = ChaChaRng::seed_from_u64(73);
        let result = repo
            .principal_did()
            .add_verified(
                &mut rng,
                &MockClock::default(),
                &bob,
                verified_principal_binding_input(
                    "https://ps-b.example",
                    second_principal_id,
                    key_log_head,
                    enrollment_authority_did,
                    authority_ref,
                ),
            )
            .await;
        if result.is_ok() {
            repo.save().await.unwrap();
            true
        } else {
            repo.cancel().await.unwrap();
            false
        }
    };

    let (first_won, second_won) = tokio::join!(first, second);
    assert_ne!(
        first_won, second_won,
        "exactly one account must own the DID"
    );

    let mut repo = factory.create().await.unwrap();
    let binding = repo
        .principal_did()
        .get_by_did(&principal_id)
        .await
        .unwrap()
        .expect("winning DID owner must remain queryable");
    assert_eq!(binding.user_id, if first_won { alice_id } else { bob_id });
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn principal_did_rejects_a_second_did_for_the_same_user_and_audience() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = PgRepositoryFactory::new(pool);
    let label = uuid::Uuid::now_v7().simple().to_string();
    let clock = MockClock::default();
    let audience = "https://ps.example";
    let mut rng = ChaChaRng::seed_from_u64(74);

    let mut repo = factory.create().await.unwrap();
    let alice = repo
        .user()
        .add(&mut rng, &clock, format!("alice-conflict-{label}"))
        .await
        .unwrap();
    repo.save().await.unwrap();

    let (first_did, first_head, first_authority, first_ref) =
        principal_binding_test_material(&format!("first{label}"));
    let mut repo = factory.create().await.unwrap();
    repo.principal_did()
        .add_verified(
            &mut rng,
            &clock,
            &alice,
            verified_principal_binding_input(
                audience,
                first_did.clone(),
                first_head,
                first_authority,
                first_ref,
            ),
        )
        .await
        .unwrap();
    repo.save().await.unwrap();

    let (second_did, second_head, second_authority, second_ref) =
        principal_binding_test_material(&format!("second{label}"));
    let mut repo = factory.create().await.unwrap();
    let conflict = repo
        .principal_did()
        .add_verified(
            &mut rng,
            &clock,
            &alice,
            verified_principal_binding_input(
                audience,
                second_did.clone(),
                second_head,
                second_authority,
                second_ref,
            ),
        )
        .await;
    assert!(conflict.is_err());
    repo.cancel().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    let binding = repo
        .principal_did()
        .get_for_user_and_audience(&alice, audience)
        .await
        .unwrap()
        .expect("the original audience binding must remain intact");
    assert_eq!(binding.principal_id, first_did);
    assert!(
        repo.principal_did()
            .get_by_did(&second_did)
            .await
            .unwrap()
            .is_none()
    );
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn principal_did_binding_does_not_overwrite_the_verified_enrollment_authority() {
    let Some(pool) = crate::test_utils::setup_test_pool().await else {
        return;
    };
    let factory = PgRepositoryFactory::new(pool);
    let label = uuid::Uuid::now_v7().simple().to_string();
    let clock = MockClock::default();
    let mut rng = ChaChaRng::seed_from_u64(75);
    let (principal_id, key_log_head, enrollment_authority_did, authority_ref) =
        principal_binding_test_material(&format!("authority{label}"));

    let mut repo = factory.create().await.unwrap();
    let alice = repo
        .user()
        .add(&mut rng, &clock, format!("alice-authority-{label}"))
        .await
        .unwrap();
    repo.principal_did()
        .add_verified(
            &mut rng,
            &clock,
            &alice,
            verified_principal_binding_input(
                "https://ps-a.example",
                principal_id.clone(),
                key_log_head.clone(),
                enrollment_authority_did.clone(),
                authority_ref.clone(),
            ),
        )
        .await
        .unwrap();
    repo.save().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    let replacement = repo
        .principal_did()
        .add_verified(
            &mut rng,
            &clock,
            &alice,
            verified_principal_binding_input(
                "https://ps-b.example",
                principal_id.clone(),
                key_log_head,
                arkret_identifiers::Did::new("did:key:z6Mkreplacement").unwrap(),
                authority_ref,
            ),
        )
        .await;
    assert!(replacement.is_err());
    repo.cancel().await.unwrap();

    let mut repo = factory.create().await.unwrap();
    let persisted = repo
        .principal_did()
        .get_by_did(&principal_id)
        .await
        .unwrap()
        .expect("original verified binding must remain");
    assert_eq!(persisted.enrollment_authority_did, enrollment_authority_did);
    assert!(
        repo.principal_did()
            .get_by_did_and_audience(&principal_id, "https://ps-b.example")
            .await
            .unwrap()
            .is_none()
    );
    repo.cancel().await.unwrap();
}
