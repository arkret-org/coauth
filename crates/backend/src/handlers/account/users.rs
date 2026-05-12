use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, NodeType, RouteError, extract_bound_activity_tracker, extract_session_info,
    get_requester, make_clock, make_rng,
};
use crate::{
    handlers::account::service::profile::{
        AccountProfileError, DeactivateAccountOutcome, deactivate_current_account,
    },
    services::user_profile::{self, UserProfileServiceError},
};

// ── PATCH /api/v1/viewer/profile ────────────────────────────────

#[derive(Deserialize)]
pub struct PatchViewerProfileInput {
    pub display_name: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
    pub preferred_locale: Option<Option<String>>,
}

#[derive(Serialize, ToSchema)]
pub struct PatchViewerProfileResponse {
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
) -> Result<Json<PatchViewerProfileResponse>, RouteError> {
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

    let patch = coauth_data::UserProfilePatch {
        display_name: input.display_name,
        avatar_url: input.avatar_url,
        preferred_locale: input.preferred_locale,
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

    Ok(Json(PatchViewerProfileResponse {
        profile: ViewerProfileData {
            display_name: user.display_name.clone(),
            avatar_url: user.avatar_url.clone(),
            preferred_locale: user.preferred_locale.clone(),
            updated_at: user.updated_at.to_rfc3339(),
        },
        principal: PrincipalUserData {
            principal_id: principal_server.principal_id(&user.username),
            display_name: user.display_name,
        },
    }))
}

// ── POST /api/v1/viewer/deactivate ─────────────────────────────

#[derive(Deserialize, salvo::oapi::ToSchema)]
pub struct DeactivateUserInput {
    pub principal_erase: bool,
    pub password: Option<String>,
}

#[derive(Serialize, salvo::oapi::ToSchema)]
pub struct DeactivateUserResponse {
    pub status: &'static str,
}

#[endpoint]
pub async fn deactivate_user(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DeactivateUserResponse>, RouteError> {
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

    Ok(Json(DeactivateUserResponse { status }))
}

fn map_account_profile_error(error: AccountProfileError) -> RouteError {
    match error {
        AccountProfileError::NotFound => RouteError::NotFound,
        AccountProfileError::Unauthorized | AccountProfileError::BrowserSessionRequired => {
            RouteError::Unauthorized
        }
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
    use coauth_data::{
        RepositoryAccess,
        user::{BrowserSessionRepository, UserRepository},
    };
    use coauth_principal::{PrincipalProvisionRequest, PrincipalServerAdmin};
    use hyper::{Request, StatusCode};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;

    use crate::{
        handlers::test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
        },
        salvo_utils::SessionInfoExt,
    };

    #[tokio::test]
    async fn test_patch_profile_updates_user_and_principal_profile() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
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
            .provision_user(&PrincipalProvisionRequest::new(&user.username, &user.sub))
            .await
            .unwrap();

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&session));

        let request = cookies.with_cookies(Request::patch("/api/v1/viewer/profile").json(
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
        assert_eq!(body["profile"]["preferred_locale"], "zh-CN");
        assert_eq!(body["principal"]["display_name"], "Alice Example");

        let mut repo = state.repository().await.unwrap();
        let stored = repo.user().lookup(user.id).await.unwrap().unwrap();
        assert_eq!(stored.display_name.as_deref(), Some("Alice Example"));
        assert_eq!(
            stored.avatar_url.as_deref(),
            Some("mxc://example.com/alice")
        );
        assert_eq!(stored.preferred_locale.as_deref(), Some("zh-CN"));

        let principal_user = state
            .principal_server_admin
            .query_user(&username)
            .await
            .unwrap();
        assert_eq!(principal_user.displayname.as_deref(), Some("Alice Example"));
    }
}
