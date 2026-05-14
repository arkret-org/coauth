use anyhow::Context;
use coauth_data::{
    PostAuthAction, RepositoryAccess, UrlBuilder,
    oauth::OAuthAuthorizationGrantRepository,
    upstream_oauth::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
};
use coauth_templates::{PostAuthContext, PostAuthContextInner};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct OptionalPostAuthAction {
    #[serde(flatten)]
    pub post_auth_action: Option<PostAuthAction>,
}

impl From<Option<PostAuthAction>> for OptionalPostAuthAction {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

impl OptionalPostAuthAction {
    pub fn next_relative_url(&self, url_builder: &UrlBuilder) -> String {
        self.post_auth_action.as_ref().map_or_else(
            || url_builder.relative_url("/"),
            |action| match action {
                PostAuthAction::ContinueAuthorizationGrant { id } => {
                    url_builder.relative_url(&format!("/consent/{id}"))
                }
                PostAuthAction::ContinueDeviceCodeGrant { id } => {
                    url_builder.relative_url(&format!("/device/{id}"))
                }
                PostAuthAction::ChangePassword => {
                    url_builder.relative_url("/account/password/change")
                }
                PostAuthAction::LinkUpstream { id } => {
                    url_builder.relative_url(&format!("/upstream/link/{id}"))
                }
                PostAuthAction::ManageAccount { action } => {
                    let base = "/account/";
                    if let Some(action) = action {
                        let query = serde_urlencoded::to_string(action).unwrap_or_default();
                        if query.is_empty() {
                            url_builder.relative_url(base)
                        } else {
                            url_builder.relative_url(&format!("{base}?{query}"))
                        }
                    } else {
                        url_builder.relative_url(base)
                    }
                }
            },
        )
    }

    pub fn go_next_or_default(
        &self,
        url_builder: &UrlBuilder,
        default_path: &str,
    ) -> salvo::writing::Redirect {
        let url = self.post_auth_action.as_ref().map_or_else(
            || url_builder.relative_url(default_path),
            |action| post_auth_action_relative_url(action, url_builder),
        );
        salvo::writing::Redirect::other(&url)
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
                    .oauth_authorization_grant()
                    .lookup(id)
                    .await?
                    .context("Failed to load authorization grant")?;
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueAuthorizationGrant { grant }
            }

            PostAuthAction::ContinueDeviceCodeGrant { id } => {
                let grant = repo
                    .oauth_device_code_grant()
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
                    .context("Failed to load upstream OAuth link")?;

                let provider = repo
                    .upstream_oauth_provider()
                    .lookup(link.provider_id)
                    .await?
                    .context("Failed to load upstream OAuth provider")?;

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

/// Compute the relative URL for a `PostAuthAction`.
pub fn post_auth_action_relative_url(action: &PostAuthAction, url_builder: &UrlBuilder) -> String {
    match action {
        PostAuthAction::ContinueAuthorizationGrant { id } => {
            url_builder.relative_url(&format!("/consent/{id}"))
        }
        PostAuthAction::ContinueDeviceCodeGrant { id } => {
            url_builder.relative_url(&format!("/device/{id}"))
        }
        PostAuthAction::ChangePassword => url_builder.relative_url("/account/password/change"),
        PostAuthAction::LinkUpstream { id } => {
            url_builder.relative_url(&format!("/upstream/link/{id}"))
        }
        PostAuthAction::ManageAccount { action } => {
            let base = "/account/";
            if let Some(action) = action {
                let query = serde_urlencoded::to_string(action).unwrap_or_default();
                if query.is_empty() {
                    url_builder.relative_url(base)
                } else {
                    url_builder.relative_url(&format!("{base}?{query}"))
                }
            } else {
                url_builder.relative_url(base)
            }
        }
    }
}

/// Produce a redirect response for a `PostAuthAction`.
pub fn post_auth_action_redirect(
    action: &PostAuthAction,
    url_builder: &UrlBuilder,
) -> salvo::writing::Redirect {
    let url = post_auth_action_relative_url(action, url_builder);
    salvo::writing::Redirect::other(&url)
}
