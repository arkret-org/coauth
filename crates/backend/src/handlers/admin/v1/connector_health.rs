//! Admin endpoint for checking connector provider health.
//!
//! Wire shape lives in `coauth-admin-types::connector_health` so sodmin
//! and any other admin client deserialize the same struct rustc has
//! type-checked the backend against.

use coauth_admin_types::{ConnectorHealthOutcome, ConnectorHealthRow, ConnectorHealthStatus};
use coauth_principal::ConnectorRegistry;
use salvo::prelude::*;

use crate::JsonResult;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::common::DepotExt;

/// Try to obtain a [`ConnectorRegistry`] from the depot.
fn get_registry(depot: &Depot) -> Option<ConnectorRegistry> {
    depot
        .get::<ConnectorRegistry>("connector_registry")
        .cloned()
        .ok()
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.connector_health", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> JsonResult<ConnectorHealthOutcome> {
    let call_context = extract_call_context(req, depot).await?;

    let providers = if let Some(registry) = get_registry(depot) {
        // Use the registry: check health for every registered provider.
        let health_results = registry.check_all_health().await;
        health_results
            .into_iter()
            .map(|(name, result)| {
                let provider_ref = registry.get(name);
                let account_id = provider_ref
                    .map(|p| p.account_id().to_owned())
                    .unwrap_or_default();
                let (status, error) = match result {
                    Ok(()) => (ConnectorHealthStatus::Healthy, None),
                    Err(e) => (ConnectorHealthStatus::Unhealthy, Some(e)),
                };
                ConnectorHealthRow {
                    provider: name.to_owned(),
                    account_id,
                    status,
                    error,
                }
            })
            .collect()
    } else {
        let station = depot.station()?;
        let (status, error) = match station.is_handle_available("__health_check__").await {
            Ok(_) => (ConnectorHealthStatus::Healthy, None),
            Err(e) => (ConnectorHealthStatus::Unhealthy, Some(e.to_string())),
        };
        vec![ConnectorHealthRow {
            provider: "principal".to_owned(),
            account_id: station.account_id().to_owned(),
            status,
            error,
        }]
    };

    call_context.repo.cancel().await?; // read-only, no save needed

    Ok(Json(ConnectorHealthOutcome { providers }))
}
