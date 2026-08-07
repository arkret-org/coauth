use coauth_data::{PostAuthAction, UrlBuilder};
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
    #[must_use]
    pub fn next_relative_url(&self, url_builder: &UrlBuilder) -> String {
        self.post_auth_action.as_ref().map_or_else(
            || url_builder.relative_url("/"),
            |action| match action {
                PostAuthAction::ContinueAuthorizationGrant { id } => {
                    url_builder.relative_url(&format!("/oauth/approval/{id}"))
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

    #[must_use]
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
}

/// Compute the relative URL for a `PostAuthAction`.
#[must_use]
pub fn post_auth_action_relative_url(action: &PostAuthAction, url_builder: &UrlBuilder) -> String {
    match action {
        PostAuthAction::ContinueAuthorizationGrant { id } => {
            url_builder.relative_url(&format!("/oauth/approval/{id}"))
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
