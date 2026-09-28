use arkret_identifiers::Hash;
use arkret_models_collaboration::account_lifecycle::{
    AppletDelegatedSessionInventoryOutcome, AppletDelegatedSessionInventoryRequestBody,
};
use arkret_wire::ScopeRef;
use coauth_data::{AppletSessionSelector, Clock as _, RepositoryAccess as _};
use salvo::prelude::*;

use crate::handlers::arkret::account_status::verify_station_signed_request;
use crate::handlers::arkret::canonical_response::ArkretCanonicalJson;
use crate::handlers::arkret::{ArkretRouteError, owning_station_id_for};
use crate::handlers::common::DepotExt;

#[handler]
pub async fn applet_delegated_session_inventory(
    req: &mut Request,
    depot: &Depot,
) -> Result<ArkretCanonicalJson, ArkretRouteError> {
    let body: AppletDelegatedSessionInventoryRequestBody = req
        .parse_json()
        .await
        .map_err(|_| ArkretRouteError::NotFound)?;
    body.validate_shape()
        .map_err(|_| ArkretRouteError::NotFound)?;
    if !matches!(
        &body.effective_scope,
        ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
    ) {
        return Err(ArkretRouteError::NotFound);
    }
    if super::super::account_status::required_header(req, "arkret-operation")?
        != "ak.gate.account.read.applet_delegated_session_inventory.v1"
    {
        return Err(ArkretRouteError::NotFound);
    }
    let canonical_body = arkret_canonical::canonical_json_bytes(&body)?;
    verify_station_signed_request(req, depot, &canonical_body).await?;
    let config = depot.arkret_config()?;
    let effective_scope = serde_json::to_value(&body.effective_scope)?;
    let issuer_id = owning_station_id_for(&config);
    let clock = crate::handlers::make_clock();
    let mut repo = depot.repo().await?;
    let snapshot = repo
        .oauth_session_grant()
        .applet_inventory(
            AppletSessionSelector {
                issuer_id: &issuer_id,
                applet_id: body.applet_id.as_str(),
                effective_scope: &effective_scope,
                registration_epoch: body.registration_epoch.as_str(),
                service_id: Some(&body.service_id),
                capability_grant_refs: &body.capability_grant_refs,
            },
            clock.now(),
        )
        .await?;
    repo.cancel().await?;
    let mut outcome = AppletDelegatedSessionInventoryOutcome {
        applet_id: body.applet_id.clone(),
        effective_scope: body.effective_scope.clone(),
        registration_epoch: body.registration_epoch.clone(),
        service_id: body.service_id.clone(),
        capability_grant_refs: body.capability_grant_refs.clone(),
        inventory_revision: snapshot.inventory_revision,
        active_session_grant_ids: snapshot.active_session_grant_ids,
        snapshot_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
            .map_err(|_| ArkretRouteError::NotFound)?,
    };
    outcome.snapshot_digest = outcome
        .compute_snapshot_digest()
        .map_err(|_| ArkretRouteError::NotFound)?;
    let bytes = arkret_canonical::canonical_json_bytes(&outcome)?;
    Ok(ArkretCanonicalJson(bytes))
}
