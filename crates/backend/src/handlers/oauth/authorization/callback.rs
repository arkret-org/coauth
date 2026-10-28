#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, HashMap};

use base64ct::{Base64, Encoding as _};
use coauth_data::AuthorizationGrant;
use coauth_i18n::Locale;
use coauth_oauth_types::requests::ResponseMode;
use coauth_templates::{FormPostContext, Templates};
use salvo::prelude::*;
use salvo::writing::{Redirect, Text};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;

/// Information about the redirect URL and mode, returned by
/// [`CallbackDestination::redirect_url`] for use in JSON API responses.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectInfo {
    /// The fully-constructed redirect URL.
    pub url: String,
    /// The OAuth response mode (`"query"`, `"fragment"`, or `"form_post"`).
    pub response_mode: &'static str,
}

/// A trusted callback for a browser navigation or an actual form POST.
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct BrowserCallback {
    pub redirect_url: String,
    pub response_mode: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub form_parameters: Vec<(String, String)>,
}

impl BrowserCallback {
    pub fn form_post_response(
        &self,
        templates: &Templates,
        locale: &Locale,
    ) -> Result<Response, CallbackDestinationError> {
        if self.response_mode != "form_post" {
            let mut response = Response::new();
            response.render(Redirect::other(&self.redirect_url));
            return Ok(response);
        }
        let redirect = self
            .redirect_url
            .parse()
            .map_err(CallbackDestinationError::CallbackUrl)?;
        let parameters = self
            .form_parameters
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<BTreeMap<_, _>>();
        render_form_post(templates, locale, redirect, parameters)
    }
}

fn render_form_post<T: Serialize>(
    templates: &Templates,
    locale: &Locale,
    redirect: Url,
    parameters: T,
) -> Result<Response, CallbackDestinationError> {
    let origin = redirect.origin().ascii_serialization();
    let context = FormPostContext::new_for_url(redirect, parameters).with_language(locale);
    let rendered = templates.render_form_post(&context)?;
    // Hash the rendered inline script, including its exact whitespace. HTML
    // parsing normalizes CRLF/CR to LF before CSP checks inline script bytes.
    let (_, tail) = rendered
        .split_once("<script>")
        .ok_or(CallbackDestinationError::FormPostScript)?;
    let (script, rest) = tail
        .split_once("</script>")
        .ok_or(CallbackDestinationError::FormPostScript)?;
    if rest.contains("<script") {
        return Err(CallbackDestinationError::FormPostScript);
    }
    let script = script.replace("\r\n", "\n").replace('\r', "\n");
    let hash = Base64::encode_string(&Sha256::digest(script.as_bytes()));
    let policy = format!(
        "default-src 'none'; script-src 'sha256-{hash}'; form-action {origin}; base-uri 'none'; frame-ancestors 'none'"
    );
    let mut response = Response::new();
    response.render(Text::Html(rendered));
    crate::server::override_response_csp(&mut response, &policy)?;
    Ok(response)
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

    #[error("form_post template must contain one inline submission script")]
    FormPostScript,

    #[error("invalid trusted callback URL")]
    CallbackUrl(url::ParseError),

    #[error("invalid form_post content security policy")]
    FormPostCsp(#[from] http::header::InvalidHeaderValue),
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
    pub fn browser_callback<T: Serialize>(
        &self,
        parameters: &T,
    ) -> Result<BrowserCallback, CallbackDestinationError> {
        if matches!(self.mode, CallbackDestinationMode::FormPost) {
            #[derive(Serialize)]
            struct Parameters<'a, T> {
                #[serde(skip_serializing_if = "Option::is_none")]
                state: &'a Option<String>,
                #[serde(flatten)]
                parameters: T,
            }
            let encoded = serde_urlencoded::to_string(Parameters {
                state: &self.state,
                parameters,
            })?;
            Ok(BrowserCallback {
                redirect_url: self.safe_redirect_uri.to_string(),
                response_mode: "form_post",
                form_parameters: url::form_urlencoded::parse(encoded.as_bytes())
                    .into_owned()
                    .collect(),
            })
        } else {
            let redirect = self.redirect_url(parameters)?;
            Ok(BrowserCallback {
                redirect_url: redirect.url,
                response_mode: redirect.response_mode,
                form_parameters: Vec::new(),
            })
        }
    }

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
        parameters: &T,
    ) -> Result<RedirectInfo, CallbackDestinationError> {
        #[derive(Serialize)]
        struct AllParams<'s, T> {
            #[serde(flatten, skip_serializing_if = "Option::is_none")]
            existing: Option<&'s HashMap<String, String>>,

            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<String>,

            #[serde(flatten)]
            parameters: T,
        }

        match &self.mode {
            CallbackDestinationMode::Query { existing_params } => {
                let merged = AllParams {
                    existing: Some(existing_params),
                    state: self.state.clone(),
                    parameters,
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
                    parameters,
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
                // For form_post, the SPA must POST the parameters to the URI.
                // We return the base URI; the caller can include the parameters
                // alongside it.
                let merged = AllParams {
                    existing: None,
                    state: self.state.clone(),
                    parameters,
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
        locale: &Locale,
        parameters: T,
    ) -> Result<Response, CallbackDestinationError> {
        #[derive(Serialize)]
        struct AllParams<'s, T> {
            #[serde(flatten, skip_serializing_if = "Option::is_none")]
            existing: Option<&'s HashMap<String, String>>,

            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<String>,

            #[serde(flatten)]
            parameters: T,
        }

        let mut redirect_uri = self.safe_redirect_uri;
        let state = self.state;

        match self.mode {
            CallbackDestinationMode::Query { existing_params } => {
                let merged = AllParams {
                    existing: Some(&existing_params),
                    state,
                    parameters,
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
                    parameters,
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
                    parameters,
                };
                render_form_post(templates, locale, redirect_uri, merged)
            }
        }
    }
}
