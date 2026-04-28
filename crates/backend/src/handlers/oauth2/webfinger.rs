use oauth2_types::webfinger::WebFingerResponse;
use coauth_data::UrlBuilder;
use salvo::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Params {
    resource: String,

    // NOTE: WebFinger allows multiple `rel=` query parameters. We only honour
    // the first value here because `OIDC Discovery 1.0 §2` — the only use case
    // we currently serve — is satisfied by a single
    // `http://openid.net/specs/connect/1.0/issuer` hint. Extending to a
    // `Vec<String>` is trivial if we ever need to return multiple links.
    #[serde(default)]
    rel: Option<String>,
}

fn jrd() -> mime::Mime {
    "application/jrd+json".parse().unwrap()
}

#[handler]
#[tracing::instrument(name = "handlers.oauth2.webfinger.get", skip_all)]
pub async fn get(req: &mut Request, depot: &Depot, res: &mut Response) {
    use crate::handlers::common::DepotExt as _;

    let url_builder = match depot.url_builder() {
        Ok(ub) => ub,
        Err(e) => {
            // Server is misconfigured. Return 500 instead of panicking so a
            // single bad request cannot crash the worker.
            tracing::error!(
                error = &e as &dyn std::error::Error,
                "DepotExt::url_builder failed"
            );
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }
    };

    let params: Params = match req.parse_queries() {
        Ok(p) => p,
        Err(e) => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain(format!("Invalid query parameters: {e}")));
            return;
        }
    };

    // The subject is echoed back verbatim per RFC 7033 §4.4.1 — the response
    // "MUST contain a `subject` member"; clients are expected to compare it
    // to the value they sent. We do not reject unusual subjects here because
    // WebFinger URIs may be arbitrary (acct:, mailto:, https:…).
    let subject = params.resource;

    let wants_issuer = params
        .rel
        .iter()
        .any(|i| i == "http://openid.net/specs/connect/1.0/issuer");

    let webfinger_res = if wants_issuer {
        WebFingerResponse::new(subject).with_issuer(url_builder.oidc_issuer())
    } else {
        WebFingerResponse::new(subject)
    };

    res.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/jrd+json"),
    );
    res.render(Json(webfinger_res));
}
