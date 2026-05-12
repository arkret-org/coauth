use std::collections::{BTreeMap, BTreeSet};

use anyhow::Error as AnyhowError;
use coauth_data::{
    BoxRepository, Clock, NotificationChannel, RepositoryAccess, RepositoryError, SiteConfig, User,
    UserEmail, UserProfile, UserProfilePatch,
    notification::NotificationRepository,
    user::{UserEmailRepository, UserPasswordRepository, UserRepository},
};
use coauth_principal::PrincipalServerAdmin;
use rand_core::RngCore;
use thiserror::Error;

use crate::handlers::account::Requester;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerProfile {
    pub profile: UserProfile,
    pub emails: Vec<UserEmail>,
    pub has_password: bool,
    pub principal_display_name: Option<String>,
    pub principal_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationAvailability {
    pub channel: NotificationChannel,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationPreferenceState {
    pub channel: NotificationChannel,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerNotificationPreferences {
    pub available_channels: Vec<NotificationAvailability>,
    pub preferences: Vec<NotificationPreferenceState>,
}

#[derive(Debug, Error)]
pub enum UserProfileServiceError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("display name is invalid")]
    InvalidDisplayName,

    #[error("unsupported notification channel: {0}")]
    UnsupportedNotificationChannel(String),

    #[error("duplicate notification channel: {0}")]
    DuplicateNotificationChannel(String),

    #[error(transparent)]
    PrincipalServer(AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn patch_viewer_profile(
    repo: &mut BoxRepository,
    requester: &Requester,
    clock: &dyn Clock,
    principal_server: &dyn PrincipalServerAdmin,
    patch: UserProfilePatch,
) -> Result<User, UserProfileServiceError> {
    let requester_user = requester
        .user()
        .ok_or(UserProfileServiceError::Unauthorized)?;
    validate_display_name_patch(&patch)?;

    let user = repo
        .user()
        .lookup(requester_user.id)
        .await?
        .ok_or(UserProfileServiceError::NotFound)?;

    if patch.is_empty() {
        return Ok(user);
    }

    let display_name_patch = patch.display_name.clone();
    let user = repo.user().update_profile(clock, user, patch).await?;

    sync_display_name_patch(principal_server, &user, display_name_patch).await?;

    Ok(user)
}

pub async fn load_viewer_profile(
    repo: &mut BoxRepository,
    principal_server: &dyn PrincipalServerAdmin,
    user: &User,
) -> Result<ViewerProfile, UserProfileServiceError> {
    let principal_id = principal_server.principal_id(&user.username);
    let principal_display_name = match principal_server.query_user(&user.username).await {
        Ok(info) => info.displayname.or_else(|| user.display_name.clone()),
        Err(_) => user.display_name.clone(),
    };

    let mut emails = repo.user_email().all(user).await?;
    emails.sort_by(|left, right| {
        right
            .is_primary
            .cmp(&left.is_primary)
            .then_with(|| left.created_at.cmp(&right.created_at))
    });

    let has_password = repo.user_password().active(user).await?.is_some();

    Ok(ViewerProfile {
        profile: user.profile(),
        emails,
        has_password,
        principal_display_name,
        principal_id,
    })
}

pub async fn load_notification_preferences(
    repo: &mut BoxRepository,
    config: &SiteConfig,
    user: &User,
) -> Result<ViewerNotificationPreferences, UserProfileServiceError> {
    let available = supported_notification_channels(config);
    let persisted = repo.notification().list_preferences(user).await?;
    let mut state = BTreeMap::new();

    for preference in persisted {
        state.insert(
            notification_channel_key(preference.channel).to_owned(),
            preference.enabled,
        );
    }

    Ok(build_preferences_view(&available, &state))
}

pub async fn patch_notification_preferences(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    config: &SiteConfig,
    user: &User,
    patch: Vec<NotificationPreferenceState>,
) -> Result<ViewerNotificationPreferences, UserProfileServiceError> {
    let available = supported_notification_channels(config);
    let available_set: BTreeSet<_> = available
        .iter()
        .map(|item| notification_channel_key(item.channel))
        .collect();
    let mut seen = BTreeSet::new();
    let mut state = BTreeMap::new();

    for persisted in repo.notification().list_preferences(user).await? {
        state.insert(
            notification_channel_key(persisted.channel).to_owned(),
            persisted.enabled,
        );
    }

    for NotificationPreferenceState { channel, enabled } in patch {
        let channel_key = notification_channel_key(channel);
        if !available_set.contains(channel_key) {
            return Err(UserProfileServiceError::UnsupportedNotificationChannel(
                channel_key.to_owned(),
            ));
        }
        if !seen.insert(channel_key) {
            return Err(UserProfileServiceError::DuplicateNotificationChannel(
                channel_key.to_owned(),
            ));
        }
        state.insert(channel_key.to_owned(), enabled);
    }

    let normalized_preferences: Vec<_> = available
        .iter()
        .map(|item| {
            (
                item.channel,
                state
                    .get(notification_channel_key(item.channel))
                    .copied()
                    .unwrap_or(item.enabled),
            )
        })
        .collect();

    let persisted = repo
        .notification()
        .replace_preferences(rng, clock, user, normalized_preferences)
        .await?;

    let state: BTreeMap<String, bool> = persisted
        .into_iter()
        .map(|preference| {
            (
                notification_channel_key(preference.channel).to_owned(),
                preference.enabled,
            )
        })
        .collect();

    Ok(build_preferences_view(&available, &state))
}

pub(crate) fn validate_display_name_patch(
    patch: &UserProfilePatch,
) -> Result<(), UserProfileServiceError> {
    let Some(display_name) = patch.display_name.as_ref() else {
        return Ok(());
    };

    match display_name {
        Some(name) if name.is_empty() || name.len() > 256 => {
            Err(UserProfileServiceError::InvalidDisplayName)
        }
        _ => Ok(()),
    }
}

pub(crate) async fn sync_display_name_patch(
    principal_server: &dyn PrincipalServerAdmin,
    user: &User,
    patch: Option<Option<String>>,
) -> Result<(), UserProfileServiceError> {
    let Some(display_name) = patch else {
        return Ok(());
    };

    match display_name {
        Some(name) => principal_server
            .set_displayname(&user.username, &name)
            .await
            .map_err(UserProfileServiceError::PrincipalServer),
        None => principal_server
            .unset_displayname(&user.username)
            .await
            .map_err(UserProfileServiceError::PrincipalServer),
    }
}

pub fn notification_channel_key(channel: NotificationChannel) -> &'static str {
    match channel {
        NotificationChannel::Email => "email",
        NotificationChannel::Sms => "sms",
        NotificationChannel::Webhook => "webhook",
        NotificationChannel::InApp => "in_app",
    }
}

pub fn notification_channel_from_key(
    channel: &str,
) -> Result<NotificationChannel, UserProfileServiceError> {
    match channel {
        "email" => Ok(NotificationChannel::Email),
        "sms" => Ok(NotificationChannel::Sms),
        "webhook" => Ok(NotificationChannel::Webhook),
        "in_app" => Ok(NotificationChannel::InApp),
        other => Err(UserProfileServiceError::UnsupportedNotificationChannel(
            other.to_owned(),
        )),
    }
}

fn supported_notification_channels(config: &SiteConfig) -> Vec<NotificationAvailability> {
    vec![
        NotificationAvailability {
            channel: NotificationChannel::Email,
            enabled: config.account_recovery_allowed || config.email_change_allowed,
        },
        NotificationAvailability {
            channel: NotificationChannel::Sms,
            enabled: config.password_registration_contact_required,
        },
    ]
}

fn build_preferences_view(
    available: &[NotificationAvailability],
    state: &BTreeMap<String, bool>,
) -> ViewerNotificationPreferences {
    ViewerNotificationPreferences {
        available_channels: available.to_vec(),
        preferences: available
            .iter()
            .map(|item| NotificationPreferenceState {
                channel: item.channel,
                enabled: state
                    .get(notification_channel_key(item.channel))
                    .copied()
                    .unwrap_or(item.enabled),
            })
            .collect(),
    }
}
