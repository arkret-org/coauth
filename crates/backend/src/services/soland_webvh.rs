//! Submission of client-signed DID operations to an authoritative Principal Server.

use arkret_models_identity::{DidOperationSubmitOutcome, DidOperationSubmitRequestBody};
use thiserror::Error;
use url::Url;

use crate::outbound_http;

/// Errors produced while forwarding a client-signed DID operation.
#[derive(Debug, Error)]
pub enum SolandWebvhError {
    #[error("principal-server endpoint is not a valid URL: {0}")]
    InvalidEndpoint(#[from] url::ParseError),
    #[error("principal-server DID operation submit request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("principal-server DID operation body could not be serialized canonically: {0}")]
    Canonical(String),
    #[error("principal-server returned status {status}: {body}")]
    SubmitRejected { status: u16, body: String },
}

/// Forward the exact typed operation supplied by the client.
pub async fn submit_did_operation(
    http_client: &reqwest::Client,
    principal_endpoint: &Url,
    bearer: Option<&str>,
    body: &DidOperationSubmitRequestBody,
) -> Result<DidOperationSubmitOutcome, SolandWebvhError> {
    let endpoint = principal_endpoint
        .join("/_arkret/root/identity/submit-did-operation")
        .map_err(SolandWebvhError::InvalidEndpoint)?;
    let body_bytes = arkret_canonical::canonical_json_bytes(body)
        .map_err(|error| SolandWebvhError::Canonical(error.to_string()))?;
    let response = outbound_http::send_with_policy(
        outbound_http::soland_policy("identity_submit_did_operation")
            .with_timeout(std::time::Duration::from_secs(15)),
        || {
            let mut request = http_client
                .post(endpoint.clone())
                .header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION_V1,
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes.clone());
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            }
            request
        },
    )
    .await?;
    let status = response.status();
    let response_body = response.text().await.unwrap_or_default();
    if status.is_success() {
        return serde_json::from_str(&response_body).map_err(|error| {
            SolandWebvhError::SubmitRejected {
                status: status.as_u16(),
                body: format!("invalid response body: {error}"),
            }
        });
    }
    Err(SolandWebvhError::SubmitRejected {
        status: status.as_u16(),
        body: response_body.chars().take(512).collect(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_models_identity::{DidMethodName, DidOperationSubmitStatus};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn did_operation_submit_carries_the_registered_operation_selector() {
        let server = MockServer::start().await;
        let did = arkret_wire::Did::new("did:webvh:z6mkfixture:local.host").unwrap();
        Mock::given(method("POST"))
            .and(path("/_arkret/root/identity/submit-did-operation"))
            .and(header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION_V1,
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "accepted",
                "did": did,
                "accepted_at": "2026-08-27T00:00:00.000Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let body = DidOperationSubmitRequestBody {
            did: did.clone(),
            did_method: DidMethodName::Webvh,
            seq: Some(0),
            prev_event_digest: None,
            operation: BTreeMap::new(),
        };

        let outcome = submit_did_operation(
            &reqwest::Client::new(),
            &Url::parse(&format!("{}/", server.uri())).unwrap(),
            None,
            &body,
        )
        .await
        .unwrap();

        assert_eq!(outcome.status, DidOperationSubmitStatus::Accepted);
    }
}
