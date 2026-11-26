//! Service-authenticated Account Authority issuer-ledger reads.
use arkret_identity::DidBindingPurpose;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusResolveRequestBody, AccountStatusResolveResponseBody,
};
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignatureVerificationPolicy, parse_signature_input,
    verify_signed_canonical_json_message,
};
use arkret_wire::DidUrl;
use coauth_data::{Clock as _, LocalAccountId, RepositoryAccess as _};
use salvo::prelude::*;

use super::{ArkretRouteError, required_header};
use crate::arkret_key_bridge::sdk_verifying_key_from_jose_verifying_key;
use crate::handlers::common::DepotExt;
use crate::services::did_binding;
use crate::services::station_trust::owning_station_id_for;

#[handler]
pub async fn resolve_account_status(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AccountStatusResolveResponseBody>, ArkretRouteError> {
    let config = depot.arkret_config()?;
    let source_id = required_header(req, "source-service-id")?;
    let destination_id = required_header(req, "destination-service-id")?;
    if destination_id != owning_station_id_for(&config).as_str()
        || !config.stations.iter().any(|server| {
            crate::services::station_trust::effective_audience_shared(server)
                .is_some_and(|audience| audience.as_str() == source_id)
        })
    {
        return Err(not_found());
    }

    let signature_input = req
        .headers()
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_signature_input(value).ok())
        .ok_or_else(not_found)?;
    let key_id = DidUrl::new(signature_input.key_id.clone()).map_err(|_| not_found())?;
    let source_did = key_id
        .as_str()
        .rsplit_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(not_found)?;
    let projected = arkret_wire::project_did_to_core_id(
        &arkret_wire::Did::new(source_did.to_owned()).map_err(|_| not_found())?,
    )
    .map_err(|_| not_found())?;
    if projected.as_str() != source_id {
        return Err(not_found());
    }

    // Read the size-limited wire bytes before acquiring a database connection.
    // Salvo caches the same buffer for the typed parse after verification.
    let body = req.payload().await.map_err(|_| not_found())?.clone();
    let mut repo = depot.repo().await?;
    let authority = did_binding::authority_document(
        &depot.http_client()?,
        &depot.url_builder()?,
        &config,
        &depot.keyring()?,
        &mut repo,
        depot.did_resolver_service()?.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        source_did,
        DidBindingPurpose::Service,
        did_binding::high_risk_freshness(),
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(|_| not_found())?;
    let resolved_key = arkret_identity::resolve_verification_method_key_from_document(
        authority.accepted.document(),
        key_id.as_str(),
    )
    .map_err(|_| not_found())?;
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(
        &resolved_key
            .public_key
            .ed25519_bytes()
            .map_err(|_| not_found())?,
    )
    .map_err(|_| not_found())?;
    verify_account_status_request(req, depot, &body, &public_key)?;

    let request: AccountStatusResolveRequestBody =
        req.parse_json().await.map_err(|_| not_found())?;
    request.validate().map_err(|_| not_found())?;
    if destination_id != request.account_authority_id.as_str() {
        return Err(not_found());
    }
    let binding = repo
        .principal_did()
        .get_by_principal_id_and_audience(
            request.account_id.principal_id.as_str(),
            request.account_id.station_id.as_str(),
        )
        .await?
        .filter(|binding| binding.account_id == request.account_id)
        .ok_or_else(not_found)?;
    let local_account_id =
        LocalAccountId::new(binding.user_id.to_string()).map_err(|_| not_found())?;

    let current = repo
        .account_status_ledger()
        .current(
            request.account_authority_id.as_str(),
            local_account_id.as_str(),
        )
        .await?;
    if current
        .as_ref()
        .is_none_or(|record| record.account_id.station_id.as_str() != source_id)
    {
        return Err(not_found());
    }
    let fetch_limit = request.limit.saturating_add(1).min(129);
    let mut records = repo
        .account_status_ledger()
        .resolve(
            request.account_authority_id.as_str(),
            local_account_id.as_str(),
            request.from_status_sequence,
            fetch_limit,
        )
        .await?;
    let has_more = records.len() > usize::from(request.limit);
    records.truncate(usize::from(request.limit));
    let next_status_sequence = has_more.then(|| {
        records
            .last()
            .map_or(request.from_status_sequence, |record| {
                record.status_sequence + 1
            })
    });
    let outcome = AccountStatusResolveResponseBody {
        account_authority_id: request.account_authority_id.clone(),
        account_id: request.account_id.clone(),
        records,
        has_more,
        next_status_sequence,
    };
    outcome
        .validate_for_request(&request)
        .map_err(|_| not_found())?;
    Ok(Json(outcome))
}

fn verify_account_status_request(
    req: &Request,
    depot: &Depot,
    body: &[u8],
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ArkretRouteError> {
    let public_base_url = depot.url_builder()?.http_base();
    if !public_base_url.has_host() {
        return Err(not_found());
    }
    let authority = &public_base_url[url::Position::BeforeHost..url::Position::AfterPort];
    // The request URI already includes the deployment prefix. Use the configured
    // origin and the exact request path and query for the signature target.
    let path = req.uri().path();
    let path_and_query = req.uri().path_and_query().map_or(path, |uri| uri.as_str());
    let target_uri = format!("{}://{authority}{path_and_query}", public_base_url.scheme());
    let headers = req
        .headers()
        .iter()
        .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str(), value)));
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::ServiceToServiceV1,
        &[
            "content-digest",
            "source-trust-domain",
            "destination-trust-domain",
        ],
    )
    .map_err(|_| not_found())?;
    let sdk_public_key =
        sdk_verifying_key_from_jose_verifying_key(public_key).map_err(|_| not_found())?;
    verify_signed_canonical_json_message(
        req.method().as_str(),
        &target_uri,
        authority,
        path,
        headers,
        req.headers().contains_key("content-encoding"),
        body,
        &sdk_public_key,
        &policy,
        crate::handlers::make_clock().now().timestamp(),
    )
    .map_err(|_| not_found())?;
    if required_header(req, "arkret-operation")?
        != arkret_wire::ServiceOperationId::PeerAccountStatusReadResolveV1.as_str()
    {
        return Err(not_found());
    }
    Ok(())
}

fn not_found() -> ArkretRouteError {
    ArkretRouteError::NotFound
}

#[cfg(test)]
mod tests {
    use arkret_signatures::http_signature::{
        ContentDigest, ContentDigestAlgorithm, SignedRequestParts, sign_http_message_for_scenario,
    };
    use arkret_wire::ServiceOperationId;
    use coauth_data::UrlBuilder;
    use http::header::HeaderName;
    use salvo::http::Method;

    use super::*;
    use crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes;

    #[test]
    fn verifies_signed_target_at_root_and_under_auth_prefix() {
        let seed = [42; 32];
        let signing_key = sdk_signing_key_from_seed_bytes(&seed);
        let public_key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let authority = "station.example:8443";
        let origin = format!("https://{authority}");
        let body = b"{}";
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256).wire_value;
        let operation = ServiceOperationId::PeerAccountStatusReadResolveV1;

        for prefix in ["", "/auth"] {
            let mut depot = Depot::new();
            depot.insert(
                "url_builder",
                UrlBuilder::new(format!("{origin}{prefix}/").parse().unwrap(), None, None),
            );
            let path = format!("{prefix}/_arkret/peer/account-status/resolve");
            let parts = SignedRequestParts {
                method: "POST".to_owned(),
                target_uri: format!("{origin}{path}"),
                authority: authority.to_owned(),
                path: path.clone(),
                headers: [
                    ("arkret-operation", operation.as_str()),
                    ("source-service-id", "ak:did_core:web:station.example"),
                    ("destination-service-id", "ak:did_core:web:station.example"),
                    ("source-trust-domain", "ak:trust_domain:station.example"),
                    ("destination-trust-domain", "ak:trust_domain:auth.example"),
                    ("content-digest", digest.as_str()),
                ]
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
                body_digest: Some(digest.clone()),
            };
            let signature = sign_http_message_for_scenario(
                &parts,
                HttpSignatureScenario::ServiceToServiceV1,
                &[
                    "content-digest",
                    "source-trust-domain",
                    "destination-trust-domain",
                ],
                "sig1",
                "did:web:station.example#notary",
                crate::handlers::make_clock().now().timestamp(),
                &signing_key,
            )
            .unwrap();
            let mut req = Request::default();
            *req.method_mut() = Method::POST;
            req.set_uri(path.parse().unwrap());
            for (name, value) in parts.headers {
                req.add_header(name.parse::<HeaderName>().unwrap(), value, true)
                    .unwrap();
            }
            req.add_header("host", "proxy.internal:8090", true).unwrap();
            req.add_header("signature-input", signature.signature_input_header, true)
                .unwrap();
            req.add_header("signature", signature.signature_header, true)
                .unwrap();

            verify_account_status_request(&req, &depot, body, &public_key)
                .unwrap_or_else(|err| panic!("verification failed for {path}: {err:?}"));
            assert!(verify_account_status_request(&req, &depot, b"{ }", &public_key).is_err());
            req.set_uri(format!("{path}?changed=1").parse().unwrap());
            assert!(verify_account_status_request(&req, &depot, body, &public_key).is_err());
        }
    }
}
