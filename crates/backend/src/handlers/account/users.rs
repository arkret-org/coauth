use coauth_account_types::{
    PatchViewerProfileOutcome, PrincipalUser as PrincipalUserData,
    ViewerUserProfile as ViewerProfileData,
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{DepotExt, RouteError, make_clock, make_rng};
use crate::handlers::account::service::profile::{
    AccountProfileError, DeactivateAccountOutcome, deactivate_current_account,
};
use crate::services::user_profile;

// ── PATCH /_coauth/self/viewer/profile ────────────────────────────────

#[derive(Deserialize)]
pub struct PatchViewerProfileInput {
    #[serde(default, with = "serde_with::rust::double_option")]
    pub display_name: Option<Option<String>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub avatar_url: Option<Option<String>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub preferred_locale: Option<Option<String>>,
}

#[endpoint]
pub async fn patch_profile(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PatchViewerProfileOutcome>, RouteError> {
    let input: PatchViewerProfileInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let station = depot.station()?;
    let clock = make_clock();

    let (requester, mut repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

    let preferred_locale = coauth_data::parse_locale_preference_patch(input.preferred_locale)
        .map_err(|tag| {
            RouteError::BadRequest(format!(
                "unsupported preferred_locale {tag:?}; this deployment ships en and zh"
            ))
        })?;

    let patch = coauth_data::UserProfilePatch {
        display_name: input.display_name,
        avatar_url: input.avatar_url,
        preferred_locale,
    };

    let user =
        user_profile::patch_viewer_profile(&mut repo, &requester, &clock, station.as_ref(), patch)
            .await
            .map_err(super::map_user_profile_error)?;

    repo.save().await?;

    Ok(Json(PatchViewerProfileOutcome {
        profile: ViewerProfileData {
            display_name: user.display_name.clone(),
            avatar_url: user.avatar_url.clone(),
            preferred_locale: user.preferred_locale.map(|locale| locale.code().to_owned()),
            updated_at: arkret_canonical::format_timestamp_canonical(user.updated_at),
        },
        principal: PrincipalUserData {
            principal_address: station.principal_address(&user.localpart),
            display_name: user.display_name,
        },
    }))
}

// ── POST /_coauth/self/viewer/deactivate ─────────────────────────────

#[derive(Deserialize, salvo::oapi::ToSchema)]
pub struct DeactivateUserInput {
    pub principal_erase: bool,
    pub password: Option<String>,
}

#[derive(Serialize, salvo::oapi::ToSchema)]
pub struct DeactivateUserOutcome {
    pub status: &'static str,
}

#[endpoint]
pub async fn deactivate_user(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DeactivateUserOutcome>, RouteError> {
    let input: DeactivateUserInput = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid json body".into()))?;

    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let station = depot.station()?;
    let key_store = depot.key_store()?;
    let arkret_config = depot.arkret_config()?;
    let service_id = crate::handlers::arkret::owning_station_id_for(&arkret_config);
    let clock = make_clock();
    let mut rng = make_rng();

    let (requester, repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

    let status = match deactivate_current_account(
        repo,
        &requester,
        &mut rng,
        &clock,
        &config,
        &password_manager,
        station.as_ref(),
        &key_store,
        service_id.as_str(),
        input.password,
        input.principal_erase,
    )
    .await
    .map_err(map_account_profile_error)?
    {
        DeactivateAccountOutcome::IncorrectPassword => "INCORRECT_PASSWORD",
        DeactivateAccountOutcome::Deactivated => "DEACTIVATED",
    };

    Ok(Json(DeactivateUserOutcome { status }))
}

fn map_account_profile_error(error: AccountProfileError) -> RouteError {
    match error {
        AccountProfileError::BrowserSessionRequired => RouteError::Unauthorized,
        AccountProfileError::DeactivationDisabled => {
            RouteError::BadRequest("Account deactivation is not allowed".into())
        }
        AccountProfileError::Password(error) => RouteError::Internal(error.into()),
        AccountProfileError::Repository(error) => RouteError::from(error),
        AccountProfileError::AccountStatusPublication(error) => RouteError::Internal(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use coauth_data::RepositoryAccess;
    use coauth_data::user::{BrowserSessionRepository, UserRepository};
    use coauth_principal::{ConnectorAdmin, ConnectorProvisionRequest};
    use hyper::{Request, StatusCode};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;

    use super::*;
    use crate::handlers::test_utils::{
        CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };
    use crate::salvo_utils::SessionInfoExt;

    #[test]
    fn profile_patch_distinguishes_omitted_null_and_value() {
        let omitted: PatchViewerProfileInput =
            serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(omitted.avatar_url, None);

        let cleared: PatchViewerProfileInput =
            serde_json::from_value(serde_json::json!({"avatar_url": null})).unwrap();
        assert_eq!(cleared.avatar_url, Some(None));

        let assigned: PatchViewerProfileInput = serde_json::from_value(serde_json::json!({
            "avatar_url": "https://example.test/avatar.png"
        }))
        .unwrap();
        assert_eq!(
            assigned.avatar_url,
            Some(Some("https://example.test/avatar.png".to_owned()))
        );
    }

    #[tokio::test]
    async fn test_patch_profile_updates_user_and_principal_profile() {
        setup();
        let Some(pool) = coauth_storage_postgres::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let username = format!("alice{}", Ulid::generate().to_string().to_lowercase());

        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.clone())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        state
            .station_admin
            .provision_user(&ConnectorProvisionRequest::new(&user.localpart, &user.sub))
            .await
            .unwrap();

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&session));

        let request = cookies.with_cookies(Request::patch("/_coauth/self/viewer/profile").json(
            serde_json::json!({
                "display_name": "Alice Example",
                "avatar_url": "mxc://example.com/alice",
                "preferred_locale": "zh-CN"
            }),
        ));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["profile"]["display_name"], "Alice Example");
        assert_eq!(body["profile"]["avatar_url"], "mxc://example.com/alice");
        // `zh-CN` is accepted and folded onto the stored base language, so the
        // response echoes the canonical value the server will actually honour
        // rather than the request string.
        assert_eq!(body["profile"]["preferred_locale"], "zh");
        assert_eq!(body["principal"]["display_name"], "Alice Example");

        let mut repo = state.repository().await.unwrap();
        let stored = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert_eq!(stored.display_name.as_deref(), Some("Alice Example"));
        assert_eq!(
            stored.avatar_url.as_deref(),
            Some("mxc://example.com/alice")
        );
        assert_eq!(stored.preferred_locale, Some(arkret_locale::UiLocale::Zh));

        let clear_request = cookies.with_cookies(
            Request::patch("/_coauth/self/viewer/profile")
                .json(serde_json::json!({"avatar_url": null})),
        );
        let clear_response = state.request(clear_request).await;
        clear_response.assert_status(StatusCode::OK);
        let clear_body: serde_json::Value = clear_response.json();
        assert!(clear_body["profile"]["avatar_url"].is_null());

        let mut repo = state.repository().await.unwrap();
        let cleared = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert_eq!(cleared.display_name.as_deref(), Some("Alice Example"));
        assert!(cleared.avatar_url.is_none());

        let principal_user = state.station_admin.query_user(&username).await.unwrap();
        assert_eq!(principal_user.displayname.as_deref(), Some("Alice Example"));
    }
}
