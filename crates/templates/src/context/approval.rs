//! Approval and policy-violation template contexts.

use std::collections::BTreeMap;

use chrono::Duration;
use coauth_data::{AuthorizationGrant, Client, DeviceCodeGrant, PostAuthAction, PrincipalUser};
use oauth_types::scope::OPENID;
use rand_core::RngCore as Rng;
use serde::Serialize;

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};

/// Generate a random alphanumeric string of the given length.
fn rand_alphanumeric_string(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}

// -- Approval ---------------------------------------------------------------

/// Data passed to the OAuth approval template.
#[derive(Serialize)]
pub struct ApprovalContext {
    grant: AuthorizationGrant,
    client: Client,
    action: PostAuthAction,
    principal_user: PrincipalUser,
}

impl ApprovalContext {
    /// Build an approval-page context for the given grant, client and principal
    /// user.
    #[must_use]
    pub fn new(grant: AuthorizationGrant, client: Client, principal_user: PrincipalUser) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant,
            client,
            action,
            principal_user,
        }
    }
}

impl TemplateContext for ApprovalContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .map(|client| {
                    let mut grant = AuthorizationGrant::sample(now, rng);
                    let action = PostAuthAction::continue_grant(grant.id);
                    grant.client_id = client.id;
                    Self {
                        grant,
                        client,
                        action,
                        principal_user: PrincipalUser {
                            principal_id: "alice@example.com".to_owned(),
                            display_name: Some("Alice".to_owned()),
                        },
                    }
                })
                .collect(),
        )
    }
}

// -- Policy violation -------------------------------------------------------

#[derive(Serialize)]
#[serde(tag = "grant_type")]
enum PolicyViolationGrant {
    #[serde(rename = "authorization_code")]
    Authorization(AuthorizationGrant),
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode(DeviceCodeGrant),
}

/// Data passed to the `policy_violation.html` template.
#[derive(Serialize)]
pub struct PolicyViolationContext {
    grant: PolicyViolationGrant,
    client: Client,
    action: PostAuthAction,
}

impl PolicyViolationContext {
    /// Build a policy-violation page context for an authorization grant.
    #[must_use]
    pub const fn for_authorization_grant(grant: AuthorizationGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::Authorization(grant),
            client,
            action,
        }
    }

    /// Build a policy-violation page context for a device-code grant.
    #[must_use]
    pub const fn for_device_code_grant(grant: DeviceCodeGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_device_code_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::DeviceCode(grant),
            client,
            action,
        }
    }
}

impl TemplateContext for PolicyViolationContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .flat_map(|client| {
                    let mut grant = AuthorizationGrant::sample(now, rng);
                    grant.client_id = client.id;

                    let auth_ctx = Self::for_authorization_grant(grant, client.clone());
                    let device_ctx = Self::for_device_code_grant(
                        DeviceCodeGrant {
                            id: coauth_data::new_id(now, rng),
                            state: coauth_data::DeviceCodeGrantState::Pending,
                            client_id: client.id,
                            scope: [OPENID].into_iter().collect(),
                            user_code: rand_alphanumeric_string(rng, 6).to_uppercase(),
                            device_code: rand_alphanumeric_string(rng, 32),
                            created_at: now - Duration::try_minutes(5).unwrap(),
                            expires_at: now + Duration::try_minutes(25).unwrap(),
                            ip_address: None,
                            user_agent: None,
                        },
                        client,
                    );

                    [auth_ctx, device_ctx]
                })
                .collect(),
        )
    }
}
