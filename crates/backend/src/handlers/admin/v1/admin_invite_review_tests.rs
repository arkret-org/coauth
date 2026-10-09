// Copyright 2026 Taidge Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

//! Real PostgreSQL and HTTP coverage of the administrator-owned review outbox.
//! Run with `cedar` and a freshly migrated scratch `DATABASE_URL`.

use diesel::QueryableByName;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl as _;
use hyper::{Request, StatusCode};
use serde_json::{Value, json};

use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct ReviewAuditRow {
    #[diesel(sql_type = Text)]
    operation: String,
    #[diesel(sql_type = Jsonb)]
    details: Value,
}

fn batch_body(consent_id: &str, count: u32) -> Value {
    json!({
        "count": count,
        "usage_limit": 3,
        "expires_in_hours": 24,
        "consent_gate": {
            "peer_principal_id": "ak:did_core:web:issuing-admin.example",
            "target_holder_principal_id": "ak:did_core:web:recipient.example",
            "consent_id": consent_id,
            "scope": "invite",
            "consent_required": false
        }
    })
}

async fn token_count(pool: &coauth_storage_postgres::test_utils::TestDatabase) -> i64 {
    let mut connection = pool.get().await.unwrap();
    diesel::sql_query("SELECT count(*) AS count FROM user_registration_tokens")
        .get_result::<CountRow>(&mut *connection)
        .await
        .unwrap()
        .count
}

async fn pending(state: &TestState, token: &str) -> Vec<Value> {
    let response = state
        .request(
            Request::get("/_coauth/admin/invite-reviews")
                .bearer(token)
                .empty(),
        )
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    body["data"].as_array().unwrap().clone()
}

#[tokio::test]
async fn admin_invite_review_enqueue_list_approve_reject_repeat_and_audit() {
    setup();
    let pool = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("admin invite review coverage requires a real scratch DATABASE_URL");
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let token = state.token_with_scope("urn:coauth:admin").await;
    assert_eq!(token_count(&pool).await, 0);

    for (consent_id, count) in [("review-approve", 2), ("review-reject", 4)] {
        let response = state
            .request(
                Request::post("/_coauth/admin/accounts/batch-invite")
                    .bearer(&token)
                    .json(batch_body(consent_id, count)),
            )
            .await;
        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
        let body: Value = response.json();
        assert!(body.to_string().contains("admin_invite_review_required"));
    }
    assert_eq!(token_count(&pool).await, 0, "enqueue must not mint tokens");
    let entries = pending(&state, &token).await;
    assert_eq!(entries.len(), 2);

    for (consent_id, decision, expected_status, minted_count) in [
        ("review-approve", "approve", "approved", 2),
        ("review-reject", "reject", "rejected", 0),
    ] {
        let entry = entries
            .iter()
            .find(|entry| entry["consent_id"] == consent_id)
            .unwrap();
        assert_eq!(entry["status"], "pending");
        assert_eq!(
            entry["peer_principal_id"],
            "ak:did_core:web:issuing-admin.example"
        );
        assert_eq!(
            entry["target_holder_principal_id"],
            "ak:did_core:web:recipient.example"
        );
        let id = entry["id"].as_str().unwrap();
        let path = format!("/_coauth/admin/invite-reviews/{id}/resolve");
        let response = state
            .request(Request::post(&path).bearer(&token).json(json!({
                "decision": decision, "note": "administrator reviewed mint parameters"
            })))
            .await;
        response.assert_status(StatusCode::OK);
        let body: Value = response.json();
        assert_eq!(body["entry"]["id"], id);
        assert_eq!(body["entry"]["status"], expected_status);
        assert!(body["entry"]["resolved_at"].is_string());
        let minted = body["minted_tokens"].as_array().map_or(0, Vec::len);
        assert_eq!(minted, minted_count);
        if let Some(tokens) = body["minted_tokens"].as_array() {
            for token in tokens {
                assert_eq!(token["data"]["attributes"]["usage_limit"], 3);
                assert!(token["data"]["attributes"]["expires_at"].is_string());
            }
        }
        let response = state
            .request(
                Request::post(&path)
                    .bearer(&token)
                    .json(json!({"decision": decision})),
            )
            .await;
        response.assert_status(StatusCode::NOT_FOUND);
        assert_eq!(
            token_count(&pool).await,
            2,
            "repeat resolution must not mint again"
        );
    }
    assert!(pending(&state, &token).await.is_empty());
    let mut connection = pool.get().await.unwrap();
    let audits = diesel::sql_query(
        "SELECT operation, details FROM admin_operation_logs \
         WHERE resource_type = 'admin_invite_review_queue' ORDER BY created_at, id",
    )
    .get_results::<ReviewAuditRow>(&mut *connection)
    .await
    .unwrap();
    assert_eq!(
        audits.len(),
        2,
        "replayed resolution must not add another audit row"
    );
    for (decision, minted_count) in [("approve", 2), ("reject", 0)] {
        let audit = audits
            .iter()
            .find(|audit| audit.details["decision"] == decision)
            .unwrap();
        let operation: coauth_data::audit::AdminOperation =
            serde_json::from_str(&audit.operation).unwrap();
        assert_eq!(
            operation,
            coauth_data::audit::AdminOperation::Other(format!("admin_invite_review.{decision}"))
        );
        assert_eq!(audit.details["minted_token_count"], minted_count);
        assert!(audit.details["admin_invite_review_id"].is_string());
        assert!(audit.details.get("quarantine_id").is_none());
    }
}

#[tokio::test]
async fn admin_invite_review_permissions_precede_input_and_resource_lookup() {
    setup();
    let pool = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("admin invite review coverage requires a real scratch DATABASE_URL");
    let mut state = TestState::from_pool(pool.clone()).await.unwrap();
    let unprivileged = state.token_with_scope("").await;
    let admin = state.token_with_scope("urn:coauth:admin").await;
    let response = state
        .request(
            Request::get("/_coauth/admin/invite-reviews?limit=not-a-number")
                .bearer(&unprivileged)
                .empty(),
        )
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let path = "/_coauth/admin/invite-reviews/not-a-uuid/resolve";
    let response = state
        .request(
            Request::post(path)
                .bearer(&unprivileged)
                .json(json!({"decision": "approve"})),
        )
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let response = state
        .request(
            Request::post(path)
                .bearer(&admin)
                .json(json!({"decision": "approve"})),
        )
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    // Preserve the current parse-error contract: invalid decisions fail before
    // a missing row is looked up. They must never resolve a row or mint tokens.
    let path = format!(
        "/_coauth/admin/invite-reviews/{}/resolve",
        uuid::Uuid::now_v7()
    );
    let response = state
        .request(
            Request::post(&path)
                .bearer(&admin)
                .json(json!({"decision": "maybe"})),
        )
        .await;
    response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    // The retired management route is a negative case, never an alias.
    let response = state
        .request(
            Request::get("/_coauth/admin/invite-quarantine")
                .bearer(&admin)
                .empty(),
        )
        .await;
    response.assert_status(StatusCode::NOT_FOUND);
    assert_eq!(token_count(&pool).await, 0);
}
