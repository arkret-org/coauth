// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
pub use coauth_admin_types::{
    OAuthSession, PersonalSession, Resource, UpstreamOAuthLink, UpstreamOAuthProvider, UserEmail,
    UserRegistrationToken, UserSession,
};
use coauth_data::PolicyDataDocument;
use coauth_data::personal::PersonalAccessToken as DataModelPersonalAccessToken;
use coauth_data::personal::session::{
    PersonalSession as DataModelPersonalSession, PersonalSessionOwner,
};
use salvo::oapi::ToSchema;
use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;
use ulid::Ulid;

pub fn to_user_email(value: coauth_data::UserEmail) -> UserEmail {
    UserEmail {
        id: value.id.to_string(),
        created_at: value.created_at,
        updated_at: value.updated_at,
        user_id: value.user_id.to_string(),
        email: value.email,
        confirmed_at: value.confirmed_at,
        is_primary: value.is_primary,
    }
}

pub fn to_oauth_session(session: coauth_data::Session) -> OAuthSession {
    OAuthSession {
        id: session.id.to_string(),
        created_at: session.created_at,
        finished_at: session.finished_at(),
        user_id: session.user_id.map(|id| id.to_string()),
        user_session_id: session.user_session_id.map(|id| id.to_string()),
        client_id: session.client_id.to_string(),
        scope: session.scope.to_string(),
        user_agent: session.user_agent,
        last_active_at: session.last_active_at,
        last_active_ip: session.last_active_ip,
        human_name: session.human_name,
    }
}

pub fn to_user_session(value: coauth_data::BrowserSession) -> UserSession {
    UserSession {
        id: value.id.to_string(),
        created_at: value.created_at,
        finished_at: value.finished_at,
        user_id: value.user.id.to_string(),
        user_agent: value.user_agent,
        last_active_at: value.last_active_at,
        last_active_ip: value.last_active_ip,
    }
}

pub fn to_upstream_oauth_link(value: coauth_data::UpstreamOAuthLink) -> UpstreamOAuthLink {
    UpstreamOAuthLink {
        id: value.id.to_string(),
        created_at: value.created_at,
        updated_at: value.updated_at,
        provider_id: value.provider_id.to_string(),
        subject: value.subject,
        user_id: value.user_id.map(|id| id.to_string()),
        human_account_name: value.human_account_name,
    }
}

#[derive(Serialize, JsonSchema, ToSchema)]
pub struct PolicyData {
    #[serde(skip)]
    id: Ulid,
    created_at: DateTime<Utc>,
    data: PolicyDataDocument,
}

impl From<coauth_data::PolicyData> for PolicyData {
    fn from(policy_data: coauth_data::PolicyData) -> Self {
        Self {
            id: policy_data.id,
            created_at: policy_data.created_at,
            data: policy_data.data,
        }
    }
}

impl Resource for PolicyData {
    const KIND: &'static str = "policy-data";
    const PATH: &'static str = "/_coauth/admin/policy-data";

    fn id(&self) -> String {
        self.id.to_string()
    }
}

pub fn to_user_registration_token(
    token: coauth_data::UserRegistrationToken,
    now: DateTime<Utc>,
) -> UserRegistrationToken {
    UserRegistrationToken {
        id: token.id.to_string(),
        valid: token.is_valid(now),
        token: token.token,
        usage_limit: token.usage_limit,
        times_used: token.times_used,
        created_at: token.created_at,
        last_used_at: token.last_used_at,
        expires_at: token.expires_at,
        revoked_at: token.revoked_at,
    }
}

pub fn to_upstream_oauth_provider(
    provider: coauth_data::UpstreamOAuthProvider,
) -> UpstreamOAuthProvider {
    UpstreamOAuthProvider {
        id: provider.id.to_string(),
        issuer: provider.issuer,
        human_name: provider.human_name,
        brand_name: provider.brand_name,
        created_at: provider.created_at,
        disabled_at: provider.disabled_at,
        source: provider.source.as_str().to_owned(),
    }
}

#[derive(Debug, Error)]
#[error(
    "personal session {session_id} in inconsistent state: not revoked but no valid access token"
)]
pub struct InconsistentPersonalSession {
    pub session_id: Ulid,
}

pub fn to_personal_session(
    (session, token): (
        DataModelPersonalSession,
        Option<DataModelPersonalAccessToken>,
    ),
) -> Result<PersonalSession, InconsistentPersonalSession> {
    let expires_at = if let Some(token) = token {
        token.expires_at
    } else {
        if !session.is_revoked() {
            return Err(InconsistentPersonalSession {
                session_id: session.id,
            });
        }
        None
    };

    let (owner_user_id, owner_client_id) = match session.owner {
        PersonalSessionOwner::User(id) => (Some(id.to_string()), None),
        PersonalSessionOwner::OAuthClient(id) => (None, Some(id.to_string())),
    };

    Ok(PersonalSession {
        id: session.id.to_string(),
        created_at: session.created_at,
        revoked_at: session.revoked_at(),
        owner_user_id,
        owner_client_id,
        actor_user_id: session.actor_user_id.to_string(),
        human_name: session.human_name,
        scope: session.scope.to_string(),
        last_active_at: session.last_active_at,
        last_active_ip: session.last_active_ip,
        expires_at,
        access_token: None,
    })
}

#[cfg(test)]
pub fn registration_token_samples() -> [UserRegistrationToken; 2] {
    [
        UserRegistrationToken {
            id: Ulid::from_bytes([0x01; 16]).to_string(),
            token: "abc123def456".to_owned(),
            valid: true,
            usage_limit: Some(10),
            times_used: 5,
            created_at: DateTime::default(),
            last_used_at: Some(DateTime::default()),
            expires_at: Some(DateTime::default() + chrono::Duration::days(30)),
            revoked_at: None,
        },
        UserRegistrationToken {
            id: Ulid::from_bytes([0x02; 16]).to_string(),
            token: "xyz789abc012".to_owned(),
            valid: false,
            usage_limit: None,
            times_used: 0,
            created_at: DateTime::default(),
            last_used_at: None,
            expires_at: None,
            revoked_at: Some(DateTime::default()),
        },
    ]
}
