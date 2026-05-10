//! REST endpoints for user notification preferences.
//!
//! - `GET   /api/v1/viewer/preferences` — returns available channels and the
//!   user's current preference settings.
//! - `PATCH /api/v1/viewer/preferences` — updates the user's notification
//!   preferences.

use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock, make_rng,
};
use crate::services::user_profile::{
    self, NotificationPreferenceState, UserProfileServiceError, notification_channel_from_key,
    notification_channel_key,
};

// ── Response / request types ─────────────────────────────────

/// Availability status of a single notification channel.
#[derive(Serialize, Deserialize, Clone, salvo::oapi::ToSchema)]
pub struct ChannelAvailability {
    /// Channel name, e.g. `"email"` or `"sms"`.
    pub channel: String,

    /// Whether this channel is enabled on the server.
    pub enabled: bool,
}

/// Per-channel preference of the current user.
#[derive(Serialize, Deserialize, Clone, salvo::oapi::ToSchema)]
pub struct ChannelPreference {
    /// Channel name, e.g. `"email"` or `"sms"`.
    pub channel: String,

    /// Whether the user wants to receive notifications on this channel.
    pub enabled: bool,
}

/// Response for `GET /api/v1/viewer/preferences`.
#[derive(Serialize, salvo::oapi::ToSchema)]
pub struct NotificationPreferencesResponse {
    /// Server-side channel availability.
    pub available_channels: Vec<ChannelAvailability>,

    /// The user's current preferences (one entry per channel).
    pub preferences: Vec<ChannelPreference>,
}

/// Request body for `PATCH /api/v1/viewer/preferences`.
#[derive(Deserialize, salvo::oapi::ToSchema)]
pub struct PatchNotificationPreferencesRequest {
    /// The per-channel preferences to update.
    pub preferences: Vec<ChannelPreference>,
}

/// Response for `PATCH /api/v1/viewer/preferences`.
#[derive(Serialize, salvo::oapi::ToSchema)]
pub struct PatchNotificationPreferencesResponse {
    /// The preferences as persisted by the server.
    pub preferences: Vec<ChannelPreference>,
}

// ── GET handler ──────────────────────────────────────────────

/// Returns the available notification channels and the current user's
/// preferences.
#[endpoint]
pub async fn get_notification_preferences(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<NotificationPreferencesResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;
    let user = requester.user().ok_or(RouteError::Unauthorized)?;

    let data = user_profile::load_notification_preferences(&mut repo, &config, user)
        .await
        .map_err(map_user_profile_error)?;

    repo.cancel().await?;

    Ok(Json(NotificationPreferencesResponse {
        available_channels: data
            .available_channels
            .into_iter()
            .map(|channel| ChannelAvailability {
                channel: notification_channel_key(channel.channel).to_owned(),
                enabled: channel.enabled,
            })
            .collect(),
        preferences: data
            .preferences
            .into_iter()
            .map(|preference| ChannelPreference {
                channel: notification_channel_key(preference.channel).to_owned(),
                enabled: preference.enabled,
            })
            .collect(),
    }))
}

// ── PATCH handler ────────────────────────────────────────────

/// Updates the user's notification preferences.
#[endpoint]
pub async fn patch_notification_preferences(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<PatchNotificationPreferencesResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let config = depot.site_config()?;
    let clock = make_clock();
    let mut rng = make_rng();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;
    let user = requester.user().ok_or(RouteError::Unauthorized)?;

    let body: PatchNotificationPreferencesRequest = req
        .parse_json()
        .await
        .map_err(|e| RouteError::BadRequest(e.to_string()))?;

    let preferences = body
        .preferences
        .into_iter()
        .map(|preference| {
            notification_channel_from_key(&preference.channel).map(|channel| {
                NotificationPreferenceState {
                    channel,
                    enabled: preference.enabled,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_user_profile_error)?;

    let updated = user_profile::patch_notification_preferences(
        &mut repo,
        &mut rng,
        &clock,
        &config,
        user,
        preferences,
    )
    .await
    .map_err(map_user_profile_error)?;

    repo.save().await?;

    Ok(Json(PatchNotificationPreferencesResponse {
        preferences: updated
            .preferences
            .into_iter()
            .map(|preference| ChannelPreference {
                channel: notification_channel_key(preference.channel).to_owned(),
                enabled: preference.enabled,
            })
            .collect(),
    }))
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
        UserProfileServiceError::Homeserver(error) => RouteError::Internal(error.into()),
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
    async fn test_patch_notification_preferences_persists_changes() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else { return; };
        let state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let username = format!("alice{}", Ulid::new().to_string().to_lowercase());

        let user = repo
            .user()
            .add(&mut rng, &state.clock, username)
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&session));

        let patch_request = cookies.with_cookies(
            Request::patch("/api/v1/viewer/preferences").json(serde_json::json!({
                "preferences": [
                    { "channel": "email", "enabled": false },
                    { "channel": "sms", "enabled": true }
                ]
            })),
        );

        let patch_response = state.request(patch_request).await;
        patch_response.assert_status(StatusCode::OK);
        let patch_body: serde_json::Value = patch_response.json();
        assert_eq!(patch_body["preferences"][0]["channel"], "email");
        assert_eq!(patch_body["preferences"][0]["enabled"], false);
        assert_eq!(patch_body["preferences"][1]["channel"], "sms");
        assert_eq!(patch_body["preferences"][1]["enabled"], true);

        let get_request = cookies.with_cookies(Request::get("/api/v1/viewer/preferences").empty());
        let get_response = state.request(get_request).await;
        get_response.assert_status(StatusCode::OK);
        let get_body: serde_json::Value = get_response.json();
        assert_eq!(get_body["preferences"][0]["channel"], "email");
        assert_eq!(get_body["preferences"][0]["enabled"], false);
        assert_eq!(get_body["preferences"][1]["channel"], "sms");
        assert_eq!(get_body["preferences"][1]["enabled"], true);
    }
}
