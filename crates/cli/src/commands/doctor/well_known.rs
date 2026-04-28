//! Well-known document discovery and validation

use tracing::{error, info, warn};
use url::Url;

use super::DOCS_BASE;

/// Attempt to fetch and validate the Matrix client well-known document.
///
/// Returns the discovered client-server API base URL on success, or `None` if
/// the document could not be retrieved / parsed / validated.
pub(super) async fn check_well_known(
    http: &reqwest::Client,
    matrix_domain: &url::Host,
    issuer: &str,
    base_url: &str,
) -> Option<Url> {
    let uri = format!("https://{matrix_domain}/.well-known/matrix/client");

    let expected = serde_json::json!({
        "m.homeserver": {
            "base_url": "...",
        },
        "org.matrix.msc2965.authentication": {
            "issuer": issuer,
            "account": format!("{base_url}account/"),
        },
    });

    let response = match http.get(&uri).send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                r#"Could not fetch well-known document at "{uri}".
The homeserver may be unreachable, or the well-known document may be missing.
Ensure the homeserver is running.
Navigating to {uri:?} in a browser should return JSON similar to:

{expected:#}

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
            );
            return None;
        }
    };

    let status = response.status();
    if !status.is_success() {
        warn!(
            r#"Matrix client well-known replied with {status}, expected 2xx.
Ensure the homeserver is reachable and the document is available at "{uri}""#,
        );
    }

    let body: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(
                r#"Invalid JSON in well-known document at "{uri}".
Navigating to {uri:?} in a browser should return valid JSON similar to:

{expected:#}

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
            );
            return None;
        }
    };

    validate_auth_section(&body, &uri, issuer, &expected);

    // Extract the homeserver base URL from the well-known payload
    body.get("m.homeserver")
        .and_then(|hs| hs.get("base_url"))
        .and_then(|u| u.as_str())
        .and_then(|u| Url::parse(u).ok())
}

/// Inspect the `org.matrix.msc2965.authentication` section (if present) and
/// log appropriate diagnostics.
fn validate_auth_section(
    body: &serde_json::Value,
    uri: &str,
    issuer: &str,
    expected: &serde_json::Value,
) {
    let Some(auth) = body.get("org.matrix.msc2965.authentication") else {
        warn!(
            r#"Matrix client well-known is missing the "org.matrix.msc2965.authentication" section.
Check the well-known document at "{uri}"
Make sure Palpo has delegated auth enabled:

  matrix_authentication_service:
    enabled: true
    endpoint: {issuer:?}
    # ...

If it is not Palpo handling the well-known document, update it to include the following:

{expected:#}

See {DOCS_BASE}/setup/homeserver.html
"#
        );
        return;
    };

    let Some(wk_issuer) = auth.get("issuer").and_then(|v| v.as_str()) else {
        error!(
            r#"The well-known "org.matrix.msc2965.authentication" section is missing a valid "issuer" field.
Check the well-known document at "{uri}"
"#
        );
        return;
    };

    if issuer == wk_issuer {
        info!(r#"Well-known at "{uri}" contains a valid authentication section"#);
    } else {
        warn!(
            r#"The well-known "org.matrix.msc2965.authentication" issuer does not match the configured one.
Check the well-known document at "{uri}"
This can happen because Pasion parses the URL in its config differently from the homeserver.
Some OIDC-native clients might not work.
Ensure that the Pasion config contains:

  http:
    public_base: {issuer:?}

And in the Palpo config:

  matrix_authentication_service:
    enabled: true
    # This must point to where Pasion is reachable by Palpo
    endpoint: {issuer:?}
    # ...

See {DOCS_BASE}/setup/homeserver.html
"#
        );
    }
}
