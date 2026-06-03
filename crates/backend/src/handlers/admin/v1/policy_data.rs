// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use coauth_data::{RepositoryAccess, audit::AdminOperation};
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    AppError, CreatedJsonResult, JsonResult,
    handlers::{
        admin::{
            CreatedJson, call_context::extract_call_context, model::PolicyData,
            params::extract_ulid_param, response::SingleResponse,
        },
        common::DepotExt,
    },
};

/// Fetch a single policy data record by its ULID.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.policy_data.get", skip_all)]
pub async fn get_by_id(req: &mut Request, depot: &Depot) -> JsonResult<SingleResponse<PolicyData>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let record_id = extract_ulid_param(req)?;

    let entry =
        repo.policy_data().get().await?.ok_or_else(|| {
            AppError::not_found(format!("Policy data with ID {record_id} not found"))
        })?;

    Ok(Json(SingleResponse::new_canonical(entry.into())))
}

/// Retrieve the most recent policy data record.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.policy_data.get_latest", skip_all)]
pub async fn get_latest(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<PolicyData>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;

    let entry = repo
        .policy_data()
        .get()
        .await?
        .ok_or_else(|| AppError::not_found("No policy data found"))?;

    Ok(Json(SingleResponse::new_canonical(entry.into())))
}

fn data_example() -> serde_json::Value {
    serde_json::json!({
        "hello": "world",
        "foo": 42,
        "bar": true
    })
}

/// Request body for creating a new policy data record.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "SetPolicyDataRequest")]
pub struct SetPolicyDataRequest {
    #[schemars(example = data_example())]
    pub data: serde_json::Value,
}

/// Store a new policy data snapshot, replacing the active policy in memory.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.policy_data.set", skip_all)]
pub async fn set_data(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleResponse<PolicyData>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let factory = depot.policy_factory()?;

    let body: SetPolicyDataRequest = req.parse_json().await.map_err(AppError::internal)?;

    let record = repo.policy_data().set(&mut rng, &clock, body.data).await?;

    // Validate by attempting to load the new data into the policy engine.
    // Rolls back on failure since we haven't called save() yet.
    factory
        .set_dynamic_data(record.clone())
        .await
        .map_err(|err| {
            AppError::with_source(
                salvo::http::StatusCode::BAD_REQUEST,
                "Provided data could not be loaded as a valid policy",
                Box::new(err),
                false,
            )
        })?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::PolicyDataUpdated,
        "policy_data",
        Some(record.id),
        serde_json::json!({}),
    )
    .await?;

    repo.save().await?;

    Ok(CreatedJson(SingleResponse::new_canonical(record.into())))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use ulid::Ulid;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_get() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let policy_data = repo
            .policy_data()
            .set(
                &mut rng,
                &state.clock,
                serde_json::json!({"hello": "world"}),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get(format!("/_cokret/local/admin/policy-data/{}", policy_data.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "policy-data",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "data": {
                "hello": "world"
              }
            },
            "links": {
              "self": "/_cokret/local/admin/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/_cokret/local/admin/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_get_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::get(format!("/_cokret/local/admin/policy-data/{}", Ulid::nil()))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Policy data with ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_get_latest() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        repo.policy_data()
            .set(
                &mut rng,
                &state.clock,
                serde_json::json!({"hello": "world"}),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get("/_cokret/local/admin/policy-data/latest")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "policy-data",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "data": {
                "hello": "world"
              }
            },
            "links": {
              "self": "/_cokret/local/admin/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/_cokret/local/admin/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_get_no_latest() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::get("/_cokret/local/admin/policy-data/latest")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "No policy data found"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_create() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::post("/_cokret/local/admin/policy-data")
            .bearer(&token)
            .json(serde_json::json!({
                "data": {
                    "hello": "world"
                }
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "policy-data",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "data": {
                "hello": "world"
              }
            },
            "links": {
              "self": "/_cokret/local/admin/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/_cokret/local/admin/policy-data/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "###);
    }
}
