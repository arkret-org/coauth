use chrono::{DateTime, Duration, TimeZone, Utc};
use coauth_data::clock::MockClock;
use coauth_data::user::UserRepository as _;
use coauth_data::{
    BoxRepository, RepositoryAccess as _, RepositoryFactory as _, UserEmailAuthentication,
    UserRegistration,
};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use ulid::Ulid;

use super::*;

fn sample_registration(created_at: DateTime<Utc>) -> UserRegistration {
    UserRegistration {
        id: Ulid::generate(),
        localpart: "alice".into(),
        display_name: None,
        avatar_url: None,
        terms_url: None,
        email_authentication_id: None,
        phone_authentication_id: None,
        user_registration_token_id: None,
        password: None,
        upstream_oauth_authorization_session_id: None,
        post_auth_action: None,
        ip_address: None,
        user_agent: None,
        created_at,
        completed_at: None,
    }
}

/// Returns `Some((database, repo))` when `DATABASE_URL` is configured; `None`
/// otherwise. Test bodies should early-return on `None`.
///
/// The [`TestDatabase`](coauth_storage_postgres::test_utils::TestDatabase)
/// guard is handed back rather than dropped here: dropping it releases the
/// advisory lock that keeps the shared test database exclusive, which would let
/// another test truncate the rows under this one.
async fn test_repo() -> Option<(
    coauth_storage_postgres::test_utils::TestDatabase,
    BoxRepository,
)> {
    let pool = coauth_storage_postgres::test_utils::setup_test_pool().await?;
    let repo = coauth_storage_postgres::PgRepositoryFactory::new(pool.clone())
        .create()
        .await
        .unwrap();
    Some((pool, repo))
}

#[tokio::test]
async fn prepare_admin_bootstrap_requires_exact_token_to_grant_admin() {
    let Some((_database, mut repo)) = test_repo().await else {
        return;
    };

    assert!(
        !prepare_admin_bootstrap(&mut repo, Some("bootstrap-secret"), None)
            .await
            .unwrap()
    );
    assert!(
        prepare_admin_bootstrap(
            &mut repo,
            Some("bootstrap-secret"),
            Some("bootstrap-secret")
        )
        .await
        .unwrap()
    );

    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn prepare_admin_bootstrap_rejects_invalid_token_while_no_admin_exists() {
    let Some((_database, mut repo)) = test_repo().await else {
        return;
    };

    let error = prepare_admin_bootstrap(&mut repo, Some("bootstrap-secret"), Some("wrong"))
        .await
        .unwrap_err();

    assert!(matches!(error, PrepareAdminBootstrapError::InvalidToken));

    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn prepare_admin_bootstrap_stops_granting_after_first_admin_exists() {
    let Some((_database, mut repo)) = test_repo().await else {
        return;
    };
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, "admin".to_owned())
        .await
        .unwrap();
    repo.user().set_can_request_admin(user, true).await.unwrap();

    assert!(
        !prepare_admin_bootstrap(
            &mut repo,
            Some("bootstrap-secret"),
            Some("bootstrap-secret")
        )
        .await
        .unwrap()
    );

    repo.cancel().await.unwrap();
}

#[test]
fn workflow_snapshot_tracks_pending_email_verification() {
    let created_at = Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap();
    let email_authentication = UserEmailAuthentication {
        id: Ulid::generate(),
        user_session_id: None,
        user_registration_id: Some(Ulid::generate()),
        email: "alice@example.com".into(),
        created_at: created_at + Duration::minutes(1),
        completed_at: None,
    };

    let mut registration = sample_registration(created_at);
    registration.email_authentication_id = Some(email_authentication.id);

    let progress = RegistrationProgress {
        registration,
        email_authentication: Some(email_authentication),
        phone_authentication: None,
    };

    let snapshot = progress.workflow_snapshot();

    assert_eq!(
        snapshot.state,
        RegistrationWorkflowState::PendingEmailVerification
    );
    assert_eq!(snapshot.next_step, Some("verify_email"));
    assert_eq!(snapshot.deadlines.len(), 1);
    assert_eq!(
        snapshot.deadlines[0].due_at,
        created_at + Duration::hours(1)
    );
    assert_eq!(snapshot.events.len(), 2);
    assert_eq!(
        snapshot.events[0].kind,
        RegistrationWorkflowEventKind::Started
    );
    assert_eq!(
        snapshot.events[1].kind,
        RegistrationWorkflowEventKind::EmailVerificationRequested
    );
}

#[test]
fn workflow_snapshot_tracks_completed_registration() {
    let created_at = Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap();
    let completed_at = created_at + Duration::minutes(10);
    let email_verified_at = created_at + Duration::minutes(2);

    let email_authentication = UserEmailAuthentication {
        id: Ulid::generate(),
        user_session_id: None,
        user_registration_id: Some(Ulid::generate()),
        email: "alice@example.com".into(),
        created_at: created_at + Duration::minutes(1),
        completed_at: Some(email_verified_at),
    };

    let mut registration = sample_registration(created_at);
    registration.display_name = Some("Alice".into());
    registration.email_authentication_id = Some(email_authentication.id);
    registration.completed_at = Some(completed_at);

    let progress = RegistrationProgress {
        registration,
        email_authentication: Some(email_authentication),
        phone_authentication: None,
    };

    let snapshot = progress.workflow_snapshot();

    assert_eq!(snapshot.state, RegistrationWorkflowState::Completed);
    assert_eq!(snapshot.next_step, None);
    assert!(snapshot.deadlines.is_empty());
    assert!(snapshot.completed_steps.contains(&"finish"));
    assert_eq!(
        snapshot.events.last().map(|event| event.kind),
        Some(RegistrationWorkflowEventKind::Completed)
    );
}
