//! Homeserver connectivity and Pasion API integration checks

use hyper::StatusCode;
use tracing::{error, info, warn};
use url::{Host, Url};

use super::DOCS_BASE;

/// Verify that the homeserver's client-server API is reachable.
///
/// Returns `true` when the versions endpoint responds with a 2xx status.
pub(super) async fn verify_reachability(
    http: &reqwest::Client,
    hs_api: &Url,
    matrix_domain: &Host,
) -> bool {
    let versions_url = match hs_api.join("/_matrix/client/versions") {
        Ok(u) => u,
        Err(e) => {
            error!("Unable to construct versions URL: {e}");
            return false;
        }
    };

    match http.get(versions_url.as_str()).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(r#"Homeserver is reachable at "{versions_url}""#);
            true
        }
        Ok(resp) => {
            let code = resp.status();
            error!(
                r#"Homeserver at "{versions_url}" responded with {code}.
Ensure the homeserver is running.
This may indicate a misconfiguration in the `matrix` config section.

  matrix:
    homeserver: "{matrix_domain}"
    # The homeserver should be reachable at this URL
    endpoint: "{hs_api}"

See {DOCS_BASE}/setup/homeserver.html
"#
            );
            false
        }
        Err(e) => {
            error!(
                r#"Unable to reach the homeserver at "{versions_url}".
This may indicate a misconfiguration in the `matrix` config section.

  matrix:
    homeserver: "{matrix_domain}"
    # The homeserver should be reachable at this URL
    endpoint: "{hs_api}"

See {DOCS_BASE}/setup/homeserver.html

Error details: {e}
"#
            );
            false
        }
    }
}

/// Send a `whoami` request with a deliberately invalid token to verify that
/// the homeserver correctly rejects it (HTTP 401).  Other status codes hint
/// at connectivity or configuration problems.
pub(super) async fn check_whoami(http: &reqwest::Client, hs_api: &Url, issuer: &str) {
    let whoami_url = match hs_api.join("/_matrix/client/v3/account/whoami") {
        Ok(u) => u,
        Err(e) => {
            error!("Unable to construct whoami URL: {e}");
            return;
        }
    };

    let result = http
        .get(whoami_url.as_str())
        .bearer_auth("averyinvalidtokenireallyhopethisisnotvalid")
        .send()
        .await;

    match result {
        Ok(resp) => {
            let code = resp.status();
            let body_text = resp.text().await.unwrap_or_else(|_| "???".into());
            diagnose_whoami_status(code, &whoami_url, &body_text, issuer);
        }
        Err(e) => error!(
            r#"Unable to reach the homeserver at "{whoami_url}".

Error details: {e}
"#
        ),
    }
}

/// Interpret the HTTP status returned by the `whoami` endpoint.
fn diagnose_whoami_status(status: StatusCode, whoami_url: &Url, body: &str, _issuer: &str) {
    match status.as_u16() {
        401 => info!(r#"Homeserver at "{whoami_url}" correctly rejected an invalid token."#),

        0..=399 => error!(
            r#"Homeserver at "{whoami_url}" replied with {status}.
This is highly unexpected — it may indicate that a fake token was accepted.
"#
        ),

        503 => error!(
            r#"Homeserver at "{whoami_url}" replied with {status}.
This likely means the homeserver was unable to contact Pasion for token validation.
Ensure Pasion is running and reachable from Palpo.
Check your homeserver logs.

Response body:

    {body}

See {DOCS_BASE}/setup/homeserver.html
"#
        ),

        _ => warn!(
            r#"Homeserver at "{whoami_url}" replied with {status}.
Verify that the homeserver is running."#
        ),
    }
}

/// Try to call an authenticated Pasion API endpoint exposed through Palpo.
///
/// We intentionally omit required parameters so that a 400 response signals
/// successful authentication, while 403 or 404 signals a problem.
pub(super) async fn check_coauth_api(
    http: &reqwest::Client,
    hs_api: &Url,
    secret: &str,
    issuer: &str,
    matrix_domain: &Host,
) {
    let api_url = match hs_api.join("/_palpo/mas/is_localpart_available") {
        Ok(u) => u,
        Err(e) => {
            error!("Unable to construct Pasion API URL: {e}");
            return;
        }
    };

    let result = http.get(api_url.as_str()).bearer_auth(secret).send().await;

    match result {
        Ok(resp) if resp.status() == StatusCode::BAD_REQUEST => {
            info!(r#"Palpo Pasion API is reachable with authentication at "{api_url}"."#);
        }
        Ok(resp) => {
            let code = resp.status();
            error!(
                r#"Palpo Pasion API endpoint at "{api_url}" replied with {code}.
Ensure the homeserver is running and the Pasion config has the correct `matrix.secret`.
It should match the `secret` set in the Palpo config.

  matrix_authentication_service:
    enabled: true
    endpoint: {issuer:?}
    # This must exactly match the secret in the Pasion config:
    secret: {secret:?}

And in the Pasion config:

  matrix:
    homeserver: "{matrix_domain}"
    endpoint: "{hs_api}"
    secret: {secret:?}
"#
            );
        }
        Err(e) => error!(
            r#"Unable to reach the Palpo Pasion API at "{api_url}".
Ensure the homeserver is running and the Pasion config has the correct `matrix.secret`.

Error details: {e}
"#
        ),
    }
}
