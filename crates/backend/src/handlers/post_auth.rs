use coauth_account_types::PostAuthAction;
use coauth_data::UrlBuilder;
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
        crate::services::post_auth::next_relative_url(self.post_auth_action.as_ref(), url_builder)
    }
}
