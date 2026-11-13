use std::sync::Arc;

use chrono::Duration;
use coauth_data::journey::{JourneySessionStatus, StageSubmission};
use rand_core::SeedableRng as _;
use serde_json::json;
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::*;
use crate::handlers::journey::{JourneyExecutor, default_recovery_journey};

fn fixture(
    status: JourneySessionStatus,
    expires_at: DateTime<Utc>,
) -> (JourneyPlan, JourneySession) {
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(906);
    let (definition, bindings) = default_recovery_journey(&mut rng);
    let plan = JourneyExecutor::plan(definition, bindings);
    let now = Utc::now();
    let session = JourneySession {
        id: coauth_data::new_id(Utc::now(), &mut rand_chacha::ChaChaRng::from_entropy()),
        journey_id: plan.journey.id,
        current_stage_index: 0,
        status,
        context: json!({}),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
        expires_at,
        completed_at: None,
    };
    (plan, session)
}

#[tokio::test]
async fn terminal_and_active_sessions_all_expire() {
    let store = JourneySessions::new(10);
    for status in [
        JourneySessionStatus::InProgress,
        JourneySessionStatus::Completed,
        JourneySessionStatus::Cancelled,
        JourneySessionStatus::Expired,
    ] {
        let (plan, session) = fixture(status, Utc::now() - Duration::seconds(1));
        let id = session.id;
        store.insert(plan, session).await;
        assert!(store.get(id).await.is_none());
    }
    assert!(store.entries.read().await.is_empty());
}

#[tokio::test]
async fn another_session_can_progress_while_one_response_waits() {
    let store = Arc::new(JourneySessions::new(10));
    let (plan, session) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::hours(1),
    );
    let id = session.id;
    store.insert(plan, session).await;
    let lease = store.get(id).await.unwrap();
    let (entered, ready) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let waiting_store = Arc::clone(&store);
    let waiting = tokio::spawn(async move {
        let mut state = lease.state.lock().await;
        {
            let _admission = waiting_store.admit(&lease).await.unwrap();
        }
        entered.send(()).unwrap();
        released.await.unwrap();
        let _admission = waiting_store.admit(&lease).await.unwrap();
        state.session.context = json!({"uid_field": "first"});
    });
    ready.await.unwrap();
    timeout(std::time::Duration::from_secs(2), async {
        let (plan, session) = fixture(
            JourneySessionStatus::InProgress,
            Utc::now() + Duration::hours(1),
        );
        let id = session.id;
        store.insert(plan, session).await;
        let lease = store.get(id).await.unwrap();
        let mut state = lease.state.lock().await;
        let _admission = store.admit(&lease).await.unwrap();
        let JourneyState { plan, session } = &mut *state;
        JourneyExecutor::current_challenge(plan, session).unwrap();
    })
    .await
    .expect("an unrelated session must not wait for external verification");
    release.send(()).unwrap();
    waiting.await.unwrap();
}

#[tokio::test]
async fn a_queued_response_observes_the_preceding_stage_commit() {
    let store = Arc::new(JourneySessions::new(10));
    let (plan, session) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::hours(1),
    );
    let id = session.id;
    store.insert(plan, session).await;
    let lease = store.get(id).await.unwrap();
    let mut first = lease.state.lock().await;
    let second_lease = store.get(id).await.unwrap();
    let second_store = Arc::clone(&store);
    let second = tokio::spawn(async move {
        let state = second_lease.state.lock().await;
        {
            let _admission = second_store.admit(&second_lease).await.unwrap();
        }
        let (outcome, _) = JourneyExecutor::process_response(
            &state.plan,
            &state.session,
            StageSubmission::Identification {
                uid_field: "second".into(),
                password: None,
            },
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            coauth_data::journey::StageOutcome::Retry { .. }
        ));
        assert_eq!(state.session.current_stage_index, 1);
    });
    let (outcome, context) = JourneyExecutor::process_response(
        &first.plan,
        &first.session,
        StageSubmission::Identification {
            uid_field: "first".into(),
            password: None,
        },
        None,
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        coauth_data::journey::StageOutcome::Continue
    ));
    {
        let _admission = store.admit(&lease).await.unwrap();
        first.session.context = context;
        first.session.current_stage_index += 1;
    }
    drop(first);
    timeout(std::time::Duration::from_secs(2), second)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn eviction_during_verification_rejects_the_old_lease() {
    let store = JourneySessions::new(1);
    let (plan, session) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::minutes(1),
    );
    let id = session.id;
    store.insert(plan, session).await;
    let lease = store.get(id).await.unwrap();
    let state = lease.state.lock().await;
    {
        let _admission = store.admit(&lease).await.unwrap();
    }
    let (plan, next) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::minutes(2),
    );
    let next_id = next.id;
    store.insert(plan, next).await;
    assert!(store.admit(&lease).await.is_none());
    assert_eq!(state.session.context, json!({}));
    assert!(store.get(id).await.is_none());
    assert!(store.get(next_id).await.is_some());
    assert_eq!(store.entries.read().await.len(), 1);
}

#[tokio::test]
async fn expiry_during_verification_rejects_the_result() {
    let store = JourneySessions::new(10);
    let (plan, session) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::hours(1),
    );
    let id = session.id;
    store.insert(plan, session).await;
    let lease = store.get(id).await.unwrap();
    let state = lease.state.lock().await;
    {
        let _admission = store.admit(&lease).await.unwrap();
    }
    // Advance the metadata deadline while the external result is outstanding.
    store.entries.write().await.get_mut(&id).unwrap().expires_at =
        Utc::now() - Duration::seconds(1);
    assert!(store.admit(&lease).await.is_none());
    assert_eq!(state.session.context, json!({}));
    assert!(store.get(id).await.is_none());
}

#[tokio::test]
async fn replacing_an_entry_does_not_admit_its_old_handle() {
    let store = JourneySessions::new(10);
    let (plan, session) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::hours(1),
    );
    let id = session.id;
    store.insert(plan, session).await;
    let old = store.get(id).await.unwrap();
    let (plan, mut session) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::hours(1),
    );
    session.id = id;
    store.insert(plan, session).await;
    assert!(store.admit(&old).await.is_none());
    let current = store.get(id).await.unwrap();
    assert!(store.admit(&current).await.is_some());
}

#[tokio::test]
async fn cancellation_releases_the_session_without_committing_partial_context() {
    let store = Arc::new(JourneySessions::new(10));
    let (plan, session) = fixture(
        JourneySessionStatus::InProgress,
        Utc::now() + Duration::hours(1),
    );
    let id = session.id;
    store.insert(plan, session).await;
    let lease = store.get(id).await.unwrap();
    let (entered, ready) = oneshot::channel();
    let waiting_store = Arc::clone(&store);
    let waiting = tokio::spawn(async move {
        let state = lease.state.lock().await;
        {
            let _admission = waiting_store.admit(&lease).await.unwrap();
        }
        let mut candidate = state.session.context.clone();
        candidate["uid_field"] = json!("uncommitted");
        entered.send(()).unwrap();
        std::future::pending::<()>().await;
        candidate
    });
    ready.await.unwrap();
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    let lease = store.get(id).await.unwrap();
    let state = timeout(std::time::Duration::from_secs(2), lease.state.lock())
        .await
        .unwrap();
    let _admission = store.admit(&lease).await.unwrap();
    assert_eq!(state.session.context, json!({}));
    assert_eq!(state.session.current_stage_index, 0);
}
