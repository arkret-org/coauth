use anyhow::Context;
use coauth_data::{PostAuthAction, UrlBuilder};
use coauth_data::{
    RepositoryAccess,
    oauth2::OAuth2AuthorizationGrantRepository,
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
};
use coauth_templates::{PostAuthContext, PostAuthContextInner};
use serde::{Deserialize, Serialize};

use crate::handlers::post_auth::post_auth_action_redirect;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub(crate) struct OptionalPostAuthAction {
    #[serde(flatten)]
    pub post_auth_action: Option<PostAuthAction>,
}

impl From<Option<PostAuthAction>> for OptionalPostAuthAction {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

impl OptionalPostAuthAction {
    pub fn go_next_or_default(
        &self,
        url_builder: &UrlBuilder,
        default_path: &str,
    ) -> salvo::writing::Redirect {
        self.post_auth_action.as_ref().map_or_else(
            || salvo::writing::Redirect::other(&url_builder.relative_url(default_path)),
            |action| post_auth_action_redirect(action, url_builder),
        )
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> salvo::writing::Redirect {
        self.go_next_or_default(url_builder, "/")
    }

    pub async fn load_context<'a>(
        &'a self,
        repo: &'a mut impl RepositoryAccess,
    ) -> anyhow::Result<Option<PostAuthContext>> {
        let Some(action) = self.post_auth_action.clone() else {
            return Ok(None);
        };
        let ctx = match action {
            PostAuthAction::ContinueAuthorizationGrant { id } => {
                let grant = repo
                    .oauth2_authorization_grant()
                    .lookup(id)
                    .await?
                    .context("Failed to load authorization grant")?;
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueAuthorizationGrant { grant }
            }

            PostAuthAction::ContinueDeviceCodeGrant { id } => {
                let grant = repo
                    .oauth2_device_code_grant()
                    .lookup(id)
                    .await?
                    .context("Failed to load device code grant")?;
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueDeviceCodeGrant { grant }
            }

            PostAuthAction::ChangePassword => PostAuthContextInner::ChangePassword,

            PostAuthAction::LinkUpstream { id } => {
                let link = repo
                    .upstream_oauth_link()
                    .lookup(id)
                    .await?
                    .context("Failed to load upstream OAuth 2.0 link")?;

                let provider = repo
                    .upstream_oauth_provider()
                    .lookup(link.provider_id)
                    .await?
                    .context("Failed to load upstream OAuth 2.0 provider")?;

                let provider = Box::new(provider);
                let link = Box::new(link);
                PostAuthContextInner::LinkUpstream { provider, link }
            }

            PostAuthAction::ManageAccount { .. } => PostAuthContextInner::ManageAccount,
        };

        Ok(Some(PostAuthContext {
            params: action.clone(),
            ctx,
        }))
    }
}
