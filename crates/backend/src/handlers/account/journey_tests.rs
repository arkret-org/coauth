use chrono::Duration;
use coauth_data::journey::JourneySessionStatus;
use rand_core::SeedableRng as _;
use salvo::test::{ResponseExt as _, TestClient};
use serde_json::json;

use super::*;

async fn insert_session(status: JourneySessionStatus, expired: bool) -> Ulid {
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(906);
    let (definition, bindings) = crate::handlers::journey::default_recovery_journey(&mut rng);
    let plan = JourneyExecutor::plan(definition, bindings);
    let id = coauth_data::new_id(Utc::now(), &mut rand_chacha::ChaChaRng::from_entropy());
    let now = Utc::now();
    let session = JourneySession {
        id,
        journey_id: plan.journey.id,
        current_stage_index: 0,
        status,
        context: json!({}),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
        expires_at: now
            + if expired {
                Duration::seconds(-1)
            } else {
                Duration::hours(1)
            },
        completed_at: None,
    };
    SESSIONS.insert(plan, session).await;
    id
}

fn service() -> Service {
    Service::new(
        Router::with_path("_coauth/self/journey/session/{id}")
            .get(get_journey_session)
            .push(Router::with_path("respond").post(respond_journey)),
    )
}

#[tokio::test]
async fn expired_terminal_and_active_sessions_are_not_found_on_both_http_routes() {
    for status in [
        JourneySessionStatus::InProgress,
        JourneySessionStatus::Completed,
        JourneySessionStatus::Cancelled,
        JourneySessionStatus::Expired,
    ] {
        let id = insert_session(status, true).await;
        let url = format!("http://localhost/_coauth/self/journey/session/{id}");
        let get = TestClient::get(&url).send(&service()).await;
        assert_eq!(get.status_code, Some(StatusCode::NOT_FOUND));
        let respond = TestClient::post(format!("{url}/respond"))
            .json(&json!({"response": {"type": "identification", "uid_field": "alice", "password": null}}))
            .send(&service()).await;
        assert_eq!(respond.status_code, Some(StatusCode::NOT_FOUND));
    }
}

#[tokio::test]
async fn unexpired_terminal_sessions_remain_readable_but_cannot_advance() {
    let id = insert_session(JourneySessionStatus::Completed, false).await;
    let url = format!("http://localhost/_coauth/self/journey/session/{id}");
    let mut get = TestClient::get(&url).send(&service()).await;
    assert_eq!(get.status_code, Some(StatusCode::OK));
    let body: Value = get.take_json().await.unwrap();
    assert_eq!(body["challenge"]["type"], "journey_done");
    let respond = TestClient::post(format!("{url}/respond"))
        .json(&json!({"response": {"type": "identification", "uid_field": "alice", "password": null}}))
        .send(&service()).await;
    assert_eq!(respond.status_code, Some(StatusCode::BAD_REQUEST));
}
