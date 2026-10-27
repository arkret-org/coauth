//! The unimplemented network-isolated IVS provider cannot mint or redeem material.
use std::sync::Arc;

use arkret_models_collaboration::governance::third_party_invite::*;
use coauth_data::{RepositoryAccess, RepositoryFactory};
use salvo::prelude::*;

use super::ArkretRouteError;
use crate::services::third_party_invite::{self as custody, PrivateInviteCustody};

fn unsupported() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::NOT_IMPLEMENTED,
        "unsupported_feature",
        "network-isolated third-party invite provider is not implemented",
    )
}

fn private_custody(depot: &Depot) -> Result<Arc<PrivateInviteCustody>, ArkretRouteError> {
    depot
        .get::<Arc<PrivateInviteCustody>>("private_invite_custody")
        .cloned()
        .map_err(|_| unsupported())
}

#[handler]
pub async fn provision_third_party_invite()
-> Result<Json<ThirdPartyInviteProvisionResponseBody>, ArkretRouteError> {
    Err(unsupported())
}
#[handler]
pub async fn activate_third_party_invite()
-> Result<Json<ThirdPartyInviteActivationResponseBody>, ArkretRouteError> {
    Err(unsupported())
}
#[handler]
pub async fn third_party_invite_status()
-> Result<Json<ThirdPartyInviteProvisioningStatusResponseBody>, ArkretRouteError> {
    Err(unsupported())
}
#[handler]
pub async fn present_third_party_invite()
-> Result<Json<ThirdPartyInvitePresentResponseBody>, ArkretRouteError> {
    Err(unsupported())
}

#[cfg(test)]
mod isolation_tests {
    use salvo::test::{ResponseExt, TestClient};

    use super::*;

    #[tokio::test]
    async fn withdrawn_provider_routes_cannot_enter_custody_or_foreign_authority() {
        let service = salvo::Service::new(
            Router::new()
                .push(Router::with_path("provision").post(provision_third_party_invite))
                .push(Router::with_path("activate").post(activate_third_party_invite))
                .push(Router::with_path("status").post(third_party_invite_status))
                .push(Router::with_path("present").post(present_third_party_invite)),
        );
        // No repository, key store, foreign service or injected runtime exists.
        for operation in ["provision", "activate", "status", "present"] {
            let mut response = TestClient::post(format!("http://isolated.test/{operation}"))
                .raw_json("{}")
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_IMPLEMENTED));
            let body: serde_json::Value = response.take_json().await.unwrap();
            assert_eq!(
                body["type"],
                "https://arkret.org/problems/unsupported_feature"
            );
            assert!(body.get("provisioning_id").is_none());
            assert!(body.get("binding_proof").is_none());
        }
    }
}

#[cfg(test)]
pub(super) fn render_present_result(
    result: Result<ThirdPartyInvitePresentResponseBody, ArkretRouteError>,
    res: &mut Response,
) -> Result<(), ArkretRouteError> {
    match result {
        Ok(outcome) => {
            res.render(Json(outcome));
            Ok(())
        }
        Err(ArkretRouteError::Coded {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            ..
        }) => {
            // Spec third-party-invites §6.1 requires byte-identical negative
            // bodies. Keep per-request correlation in the response header;
            // a fresh problem instance would distinguish otherwise equal 404s.
            super::render_problem(
                res,
                StatusCode::NOT_FOUND,
                arkret_wire::problem_details::Problem::from_code(
                    arkret_wire::ErrorCode::NOT_FOUND,
                    "third-party invite unavailable",
                ),
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Reject URL credentials before selector validation or request-body reads.
#[handler]
pub async fn reject_third_party_invite_url_credentials(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    const PRESENT: &str = "/_arkret/open/third-party-invites/present";
    if req.uri().path() == PRESENT && req.uri().query().is_none() {
        ctrl.call_next(req, depot, res).await;
        return;
    }
    if req.uri().path() != PRESENT && !req.uri().path().starts_with(&format!("{PRESENT}/")) {
        ctrl.call_next(req, depot, res).await;
        return;
    }
    if let Ok(runtime) = private_custody(depot) {
        let mut tokens: Vec<String> =
            url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .filter(|(key, _)| matches!(key.as_ref(), "invite_token" | "token"))
                .map(|(_, value)| value.into_owned())
                .collect();
        if let Some(path_token) = req.uri().path().strip_prefix(&format!("{PRESENT}/")) {
            tokens.push(path_token.to_owned());
        }
        for token in tokens {
            if let Ok(mut repo) = runtime.factory.create().await {
                let found = repo
                    .third_party_invite()
                    .find_token(&custody::token_selector(&token))
                    .await;
                if let Ok(Some(row)) = found
                    && let Ok(mut c) = custody::decrypt(&row, &runtime.encrypter)
                    && custody::matches_token(&c, &token)
                {
                    c.state = ThirdPartyInviteProvisioningState::Revoked;
                    c.secrets = None;
                    if custody::update(&mut repo, row, &c, &runtime.encrypter)
                        .await
                        .is_ok()
                    {
                        let _ = repo.save().await;
                    }
                }
            }
        }
    }
    ArkretRouteError::CodedDetailed {
        status: StatusCode::CONFLICT,
        code: "failed_precondition",
        message: "invitation credentials belong only in the request body".into(),
        details: vec![(
            "reason_code",
            serde_json::json!("third_party_invite_token_in_query"),
        )],
    }
    .render(res);
    ctrl.skip_rest();
}
