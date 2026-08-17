//! Upstream OAuth provider template contexts.

use std::collections::BTreeMap;

use coauth_account_types::PostAuthAction;
use coauth_data::{
    UpstreamOAuthLink, UpstreamOAuthProvider, UpstreamOAuthProviderClaimsImports,
    UpstreamOAuthProviderDiscoveryMode, UpstreamOAuthProviderOnBackchannelLogout,
    UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod, User,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_oauth_types::scope::{OPENID, Scope};
use rand_core::RngCore as Rng;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::wrappers::{SampleIdentifier, TemplateContext, sample_list};
use crate::{FormField, FormState};

// -- Existing link ----------------------------------------------------------

/// Data for the `pages/upstream_oauth/link_mismatch.html` template.
#[derive(Serialize)]
pub struct UpstreamExistingLinkContext {
    linked_user: User,
}

impl UpstreamExistingLinkContext {
    /// Build the context from an already-linked user.
    #[must_use]
    pub fn new(linked_user: User) -> Self {
        Self { linked_user }
    }
}

impl TemplateContext for UpstreamExistingLinkContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .map(|u| Self { linked_user: u })
                .collect(),
        )
    }
}

// -- Suggest link -----------------------------------------------------------

/// Data for the `pages/upstream_oauth/suggest_link.html` template.
#[derive(Serialize)]
pub struct UpstreamSuggestLink {
    post_logout_action: PostAuthAction,
}

impl UpstreamSuggestLink {
    /// Build the context from an upstream OAuth link.
    #[must_use]
    pub fn new(link: &UpstreamOAuthLink) -> Self {
        Self::for_link_id(link.id)
    }

    fn for_link_id(id: Ulid) -> Self {
        Self {
            post_logout_action: PostAuthAction::link_upstream(id),
        }
    }
}

impl TemplateContext for UpstreamSuggestLink {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        let link_id = coauth_data::new_id(now, rng);
        sample_list(vec![Self::for_link_id(link_id)])
    }
}

// -- Upstream registration --------------------------------------------------

/// User-editable fields on the upstream account registration form.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamRegisterFormField {
    /// Handle field
    Handle,
    /// Terms-of-service acceptance
    AcceptTerms,
}

impl FormField for UpstreamRegisterFormField {
    fn keep(&self) -> bool {
        true
    }
}

/// Data for the `pages/upstream_oauth/do_register.html` template.
#[derive(Serialize)]
pub struct UpstreamRegister {
    upstream_oauth_link: UpstreamOAuthLink,
    upstream_oauth_provider: UpstreamOAuthProvider,
    imported_handle: Option<String>,
    force_handle: bool,
    imported_display_name: Option<String>,
    force_display_name: bool,
    imported_email: Option<String>,
    force_email: bool,
    form_state: FormState<UpstreamRegisterFormField>,
}

impl UpstreamRegister {
    /// Build the context for registering via an upstream provider.
    #[must_use]
    pub fn new(
        upstream_oauth_link: UpstreamOAuthLink,
        upstream_oauth_provider: UpstreamOAuthProvider,
    ) -> Self {
        Self {
            upstream_oauth_link,
            upstream_oauth_provider,
            imported_handle: None,
            force_handle: false,
            imported_display_name: None,
            force_display_name: false,
            imported_email: None,
            force_email: false,
            form_state: FormState::default(),
        }
    }

    /// Set the imported handle
    #[must_use]
    pub fn with_handle(self, handle: String, force: bool) -> Self {
        Self {
            imported_handle: Some(handle),
            force_handle: force,
            ..self
        }
    }

    /// Set the imported display name
    pub fn set_display_name(&mut self, display_name: String, force: bool) {
        self.imported_display_name = Some(display_name);
        self.force_display_name = force;
    }

    /// Set the imported email
    #[must_use]
    pub fn with_email(self, email: String, force: bool) -> Self {
        Self {
            imported_email: Some(email),
            force_email: force,
            ..self
        }
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form_state: FormState<UpstreamRegisterFormField>) -> Self {
        Self { form_state, ..self }
    }
}

impl TemplateContext for UpstreamRegister {
    fn sample<R: Rng>(
        now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[coauth_i18n::Locale],
    ) -> BTreeMap<SampleIdentifier, Self> {
        sample_list(vec![Self::new(
            UpstreamOAuthLink {
                id: Ulid::nil(),
                provider_id: Ulid::nil(),
                user_id: None,
                subject: "subject".to_owned(),
                human_account_name: Some("@john".to_owned()),
                created_at: now,
                updated_at: now,
            },
            UpstreamOAuthProvider {
                id: Ulid::nil(),
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client-id".to_owned(),
                encrypted_client_secret: None,
                claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                jwks_uri_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                created_at: now,
                disabled_at: None,
                on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                source: coauth_data::UpstreamOAuthProviderSource::Config,
            },
        )])
    }
}
