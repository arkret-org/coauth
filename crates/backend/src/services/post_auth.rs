use coauth_account_types::PostAuthAction;
use coauth_data::UrlBuilder;

pub(crate) fn next_relative_url(
    post_auth_action: Option<&PostAuthAction>,
    url_builder: &UrlBuilder,
) -> String {
    post_auth_action.map_or_else(
        || url_builder.relative_url("/"),
        |action| match action {
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
        },
    )
}
