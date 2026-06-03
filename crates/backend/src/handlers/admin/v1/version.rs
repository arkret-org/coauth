// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use salvo::{oapi::ToSchema, prelude::*};
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    handlers::{admin::call_context::extract_call_context, common::DepotExt},
    salvo_utils::InternalError,
};

/// Payload returned by the version endpoint.
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct Version {
    /// Semver string of the running application
    pub version: &'static str,
}

/// Return the application version.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.version", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> Result<Json<Version>, InternalError> {
    let _ctx = extract_call_context(req, depot).await?;
    let coauth_data::AppVersion(ver) = depot.app_version()?;

    Ok(Json(Version { version: ver }))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;

    use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[tokio::test]
    async fn test_add_user() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let request = Request::get("/_cokret/local/admin/version")
            .bearer(&token)
            .empty();

        let response = state.request(request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "version": "v0.0.0-test"
        }
        "#);
    }
}
