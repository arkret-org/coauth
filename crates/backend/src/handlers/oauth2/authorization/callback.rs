#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

use oauth2_types::requests::ResponseMode;
use coauth_data::AuthorizationGrant;
use coauth_i18n::DataLocale;
use coauth_templates::{FormPostContext, Templates};
use salvo::{
    prelude::*,
    writing::{Redirect, Text},
};
use serde::Serialize;
use thiserror::Error;
use url::Url;

/// Information about the redirect URL and mode, returned by
/// [`CallbackDestination::redirect_url`] for use in JSON API responses.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectInfo {
    /// The fully-constructed redirect URL.
    pub url: String,
    /// The OAuth 2.0 response mode (`"query"`, `"fragment"`, or `"form_post"`).
    pub response_mode: &'static str,
}

#[derive(Debug, Clone)]
enum CallbackDestinationMode {
    Query {
        existing_params: HashMap<String, String>,
    },
    Fragment,
    FormPost,
}

#[derive(Debug, Clone)]
pub struct CallbackDestination {
    mode: CallbackDestinationMode,
    safe_redirect_uri: Url,
    state: Option<String>,
}

#[derive(Debug, Error)]
pub enum IntoCallbackDestinationError {
    #[error("Redirect URI can't have a fragment")]
    RedirectUriFragmentNotAllowed,

    #[error("Existing query parameters are not valid")]
    RedirectUriInvalidQueryParams(#[from] serde_urlencoded::de::Error),

    #[error("Requested response_mode is not supported")]
    UnsupportedResponseMode,
}

#[derive(Debug, Error)]
pub enum CallbackDestinationError {
    #[error("Failed to render the form_post template")]
    FormPostRender(#[from] coauth_templates::TemplateError),

    #[error("Failed to serialize parameters query string")]
    ParamsSerialization(#[from] serde_urlencoded::ser::Error),
}

impl TryFrom<&AuthorizationGrant> for CallbackDestination {
    type Error = IntoCallbackDestinationError;

    fn try_from(value: &AuthorizationGrant) -> Result<Self, Self::Error> {
        Self::try_new(
            &value.response_mode,
            value.redirect_uri.clone(),
            value.state.clone(),
        )
    }
}

impl CallbackDestination {
    pub fn try_new(
        mode: &ResponseMode,
        mut redirect_uri: Url,
        state: Option<String>,
    ) -> Result<Self, IntoCallbackDestinationError> {
        if redirect_uri.fragment().is_some() {
            return Err(IntoCallbackDestinationError::RedirectUriFragmentNotAllowed);
        }

        let mode = match mode {
            ResponseMode::Query => {
                let existing_params = redirect_uri
                    .query()
                    .map(serde_urlencoded::from_str)
                    .transpose()?
                    .unwrap_or_default();

                // Remove the query from the URL
                redirect_uri.set_query(None);

                CallbackDestinationMode::Query { existing_params }
            }
            ResponseMode::Fragment => CallbackDestinationMode::Fragment,
            ResponseMode::FormPost => CallbackDestinationMode::FormPost,
            _ => return Err(IntoCallbackDestinationError::UnsupportedResponseMode),
        };

        Ok(Self {
            mode,
            safe_redirect_uri: redirect_uri,
            state,
        })
    }

    /// Build the final redirect URL as a string (for use in REST API JSON
    /// responses). For `query` and `fragment` modes this is the full URL with
    /// parameters attached. For `form_post` mode it returns the base
    /// redirect URI; the SPA is responsible for building and submitting the
    /// POST form with the supplied parameters.
    pub fn redirect_url<T: Serialize>(
        &self,
        params: &T,
    ) -> Result<RedirectInfo, CallbackDestinationError> {
        #[derive(Serialize)]
        struct AllParams<'s, T> {
            #[serde(flatten, skip_serializing_if = "Option::is_none")]
            existing: Option<&'s HashMap<String, String>>,

            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<String>,

            #[serde(flatten)]
            params: T,
        }

        match &self.mode {
            CallbackDestinationMode::Query { existing_params } => {
                let merged = AllParams {
                    existing: Some(existing_params),
                    state: self.state.clone(),
                    params,
                };
                let new_qs = serde_urlencoded::to_string(merged)?;
                let mut url = self.safe_redirect_uri.clone();
                url.set_query(Some(&new_qs));
                Ok(RedirectInfo {
                    url: url.to_string(),
                    response_mode: "query",
                })
            }
            CallbackDestinationMode::Fragment => {
                let merged = AllParams {
                    existing: None,
                    state: self.state.clone(),
                    params,
                };
                let new_qs = serde_urlencoded::to_string(merged)?;
                let mut url = self.safe_redirect_uri.clone();
                url.set_fragment(Some(&new_qs));
                Ok(RedirectInfo {
                    url: url.to_string(),
                    response_mode: "fragment",
                })
            }
            CallbackDestinationMode::FormPost => {
                // For form_post, the SPA must POST the params to the URI.
                // We return the base URI; the caller can include the params
                // alongside it.
                let merged = AllParams {
                    existing: None,
                    state: self.state.clone(),
                    params,
                };
                let new_qs = serde_urlencoded::to_string(merged)?;
                let mut url = self.safe_redirect_uri.clone();
                url.set_query(Some(&new_qs));
                Ok(RedirectInfo {
                    url: url.to_string(),
                    response_mode: "form_post",
                })
            }
        }
    }

    pub fn go<T: Serialize + Send + Sync>(
        self,
        templates: &Templates,
        locale: &DataLocale,
        params: T,
    ) -> Result<Response, CallbackDestinationError> {
        #[derive(Serialize)]
        struct AllParams<'s, T> {
            #[serde(flatten, skip_serializing_if = "Option::is_none")]
            existing: Option<&'s HashMap<String, String>>,

            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<String>,

            #[serde(flatten)]
            params: T,
        }

        let mut redirect_uri = self.safe_redirect_uri;
        let state = self.state;

        match self.mode {
            CallbackDestinationMode::Query { existing_params } => {
                let merged = AllParams {
                    existing: Some(&existing_params),
                    state,
                    params,
                };

                let new_qs = serde_urlencoded::to_string(merged)?;

                redirect_uri.set_query(Some(&new_qs));

                let mut res = Response::new();
                res.render(Redirect::other(redirect_uri.as_str()));
                Ok(res)
            }

            CallbackDestinationMode::Fragment => {
                let merged = AllParams {
                    existing: None,
                    state,
                    params,
                };

                let new_qs = serde_urlencoded::to_string(merged)?;

                redirect_uri.set_fragment(Some(&new_qs));

                let mut res = Response::new();
                res.render(Redirect::other(redirect_uri.as_str()));
                Ok(res)
            }

            CallbackDestinationMode::FormPost => {
                let merged = AllParams {
                    existing: None,
                    state,
                    params,
                };
                let ctx = FormPostContext::new_for_url(redirect_uri, merged).with_language(locale);
                let rendered = templates.render_form_post(&ctx)?;
                let mut res = Response::new();
                res.render(Text::Html(rendered));
                Ok(res)
            }
        }
    }
}
