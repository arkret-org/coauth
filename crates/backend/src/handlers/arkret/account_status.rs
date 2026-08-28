//! Service-authenticated Account Authority issuer-ledger reads.

use arkret_identity::DidBindingPurpose;
use arkret_models_collaboration::account_lifecycle::{
    AccountStatusResolveOutcome, AccountStatusResolveRequestBody,
};
use arkret_signatures::http_signature::{
    Component, SignatureVerificationPolicy, parse_signature_input,
    verify_signed_canonical_json_message,
};
use arkret_wire::DidUrl;
use coauth_data::{Clock as _, RepositoryAccess as _};
use salvo::prelude::*;

use super::{ArkretRouteError, service_id_for};
use crate::handlers::common::DepotExt;
use crate::services::did_binding;

#[handler]
pub async fn resolve_account_status(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<AccountStatusResolveOutcome>, ArkretRouteError> {
    let request: AccountStatusResolveRequestBody =
        req.parse_json().await.map_err(|_| not_found())?;
    request.validate().map_err(|_| not_found())?;
    let canonical_body =
        arkret_canonical::canonical_json_bytes(&request).map_err(|_| not_found())?;

    let config = depot.arkret_config()?;
    if request.account_authority_id != service_id_for(&config) {
        return Err(not_found());
    }
    let source_id = required_header(req, "source-service-id")?;
    let destination_id = required_header(req, "destination-service-id")?;
    if destination_id != request.account_authority_id.as_str()
        || !config.principal_servers.iter().any(|server| {
            crate::services::principal_server_trust::effective_audience_shared(server)
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

    let mut repo = depot.repo().await?;
    let authority = did_binding::authority_document(
        &depot.http_client()?,
        &depot.url_builder()?,
        &config,
        &depot.key_store()?,
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
    verify_request(req, depot, &canonical_body, &public_key)?;

    let current = repo
        .account_status_ledger()
        .current(
            request.account_authority_id.as_str(),
            request.account_id.as_str(),
        )
        .await?;
    if current
        .as_ref()
        .is_none_or(|record| record.principal_authority.principal_server_id.as_str() != source_id)
    {
        return Err(not_found());
    }
    let fetch_limit = request.limit.saturating_add(1).min(129);
    let mut records = repo
        .account_status_ledger()
        .resolve(
            request.account_authority_id.as_str(),
            request.account_id.as_str(),
            request.from_status_seq,
            fetch_limit,
        )
        .await?;
    let has_more = records.len() > usize::from(request.limit);
    records.truncate(usize::from(request.limit));
    let next_status_seq = has_more.then(|| {
        records
            .last()
            .map_or(request.from_status_seq, |record| record.status_seq + 1)
    });
    let outcome = AccountStatusResolveOutcome {
        account_authority_id: request.account_authority_id.clone(),
        account_id: request.account_id.clone(),
        records,
        has_more,
        next_status_seq,
    };
    outcome
        .validate_for_request(&request)
        .map_err(|_| not_found())?;
    Ok(Json(outcome))
}

fn verify_request(
    req: &Request,
    depot: &Depot,
    canonical_body: &[u8],
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ArkretRouteError> {
    let public_base_url = depot.url_builder()?.http_base();
    let authority = public_base_url
        .host_str()
        .map(|host| {
            public_base_url
                .port()
                .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"))
        })
        .ok_or_else(not_found)?;
    let target_uri = public_base_url
        .join(req.uri().path().trim_start_matches('/'))
        .map_err(|_| not_found())?;
    let headers = req.headers().iter().filter_map(|(name, value)| {
        value
            .to_str()
            .ok()
            .map(|value| (name.as_str().to_owned(), value.to_owned()))
    });
    let policy = SignatureVerificationPolicy::new(vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("source-trust-domain".to_owned()),
        Component::Header("destination-trust-domain".to_owned()),
        Component::Header("content-digest".to_owned()),
    ])
    .require_content_digest(true)
    .max_clock_skew_seconds(300)
    .max_validity_window_seconds(300);
    verify_signed_canonical_json_message(
        req.method().as_str(),
        target_uri.as_str(),
        &authority,
        req.uri().path(),
        headers,
        req.headers().contains_key("content-encoding"),
        canonical_body,
        public_key,
        &policy,
        crate::handlers::make_clock().now().timestamp(),
    )
    .map_err(|_| not_found())?;
    Ok(())
}

fn required_header(req: &Request, name: &str) -> Result<String, ArkretRouteError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(not_found)
}

fn not_found() -> ArkretRouteError {
    ArkretRouteError::NotFound
}
