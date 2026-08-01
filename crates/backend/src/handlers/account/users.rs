use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock, make_rng,
};
use crate::handlers::account::service::profile::{
    AccountProfileError, DeactivateAccountOutcome, deactivate_current_account,
};
use crate::services::user_profile::{self, UserProfileServiceError};

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

#[derive(Serialize, ToSchema)]
pub struct PatchViewerProfileOutcome {
    pub profile: ViewerProfileData,
    pub principal: PrincipalUserData,
}

#[derive(Serialize, ToSchema)]
pub struct ViewerProfileData {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub preferred_locale: Option<String>,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct PrincipalUserData {
    pub principal_id: String,
    pub display_name: Option<String>,
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

    let repo_factory = depot.repo_factory()?;
    let principal_server = depot.principal_server()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let preferred_locale = coauth_data::parse_locale_preference_patch(input.preferred_locale)
        .map_err(|tag| {
            RouteError::BadRequest(
                format!("unsupported preferred_locale {tag:?}; this deployment ships en and zh"),
            )
        })?;

    let patch = coauth_data::UserProfilePatch {
        display_name: input.display_name,
        avatar_url: input.avatar_url,
        preferred_locale,
    };

    let user = user_profile::patch_viewer_profile(
        &mut repo,
        &requester,
        &clock,
        principal_server.as_ref(),
        patch,
    )
    .await
    .map_err(map_user_profile_error)?;

    repo.save().await?;

    Ok(Json(PatchViewerProfileOutcome {
        profile: ViewerProfileData {
            display_name: user.display_name.clone(),
            avatar_url: user.avatar_url.clone(),
            preferred_locale: user.preferred_locale.map(|locale| locale.code().to_owned()),
            updated_at: arkret_canonical::format_timestamp_canonical(user.updated_at),
        },
        principal: PrincipalUserData {
            principal_id: principal_server.principal_id(&user.localpart),
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

    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let password_manager = depot.password_manager()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, repo) = get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let status = match deactivate_current_account(
        repo,
        &requester,
        &mut rng,
        &clock,
        &config,
        &password_manager,
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
    }
}

fn map_user_profile_error(error: UserProfileServiceError) -> RouteError {
    match error {
        UserProfileServiceError::NotFound => RouteError::NotFound,
        UserProfileServiceError::Unauthorized => RouteError::Unauthorized,
        UserProfileServiceError::InvalidDisplayName => {
            RouteError::BadRequest("Invalid display name".into())
        }
        UserProfileServiceError::UnsupportedNotificationChannel(channel) => {
            RouteError::BadRequest(format!("Unsupported notification channel: {channel}"))
        }
        UserProfileServiceError::DuplicateNotificationChannel(channel) => {
            RouteError::BadRequest(format!("Duplicate notification channel: {channel}"))
        }
        UserProfileServiceError::PrincipalServer(error) => RouteError::Internal(error.into()),
        UserProfileServiceError::Repository(error) => RouteError::from(error),
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
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());

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
            .principal_server_admin
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

        let principal_user = state
            .principal_server_admin
            .query_user(&username)
            .await
            .unwrap();
        assert_eq!(principal_user.displayname.as_deref(), Some("Alice Example"));
    }
}
