//! Admin endpoint for checking connector provider health.
//!
//! Wire shape lives in `coauth-admin-types::connector_health` so sodmin
//! and any other admin client deserialize the same struct rustc has
//! type-checked the backend against.

use coauth_admin_types::{ConnectorHealthResponse, ConnectorHealthRow};
use coauth_principal::ConnectorRegistry;
use salvo::prelude::*;

use crate::{
    JsonResult,
    handlers::{admin::call_context::extract_call_context, common::DepotExt},
};

/// Try to obtain a [`ConnectorRegistry`] from the depot.
fn get_registry(depot: &Depot) -> Option<ConnectorRegistry> {
    depot
        .get::<ConnectorRegistry>("connector_registry")
        .cloned()
        .ok()
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.connector_health", skip_all)]
pub async fn handler(req: &mut Request, depot: &Depot) -> JsonResult<ConnectorHealthResponse> {
    let call_context = extract_call_context(req, depot).await?;

    let providers = if let Some(registry) = get_registry(depot) {
        // Use the registry: check health for every registered provider.
        let health_results = registry.check_all_health().await;
        health_results
            .into_iter()
            .map(|(name, result)| {
                let provider_ref = registry.get(name);
                let principal_authority = provider_ref
                    .map(|p| p.principal_authority().to_owned())
                    .unwrap_or_default();
                let (status, error) = match result {
                    Ok(()) => ("healthy".to_string(), None),
                    Err(e) => ("unhealthy".to_string(), Some(e)),
                };
                ConnectorHealthRow {
                    provider: name.to_owned(),
                    principal_authority,
                    status,
                    error,
                }
            })
            .collect()
    } else {
        let principal_server = depot.principal_server()?;
        let (status, error) = match principal_server
            .is_username_available("__health_check__")
            .await
        {
            Ok(_) => ("healthy".to_string(), None),
            Err(e) => ("unhealthy".to_string(), Some(e.to_string())),
        };
        vec![ConnectorHealthRow {
            provider: "principal".to_string(),
            principal_authority: principal_server.principal_authority().to_string(),
            status,
            error,
        }]
    };

    call_context.repo.cancel().await?; // read-only, no save needed

    Ok(Json(ConnectorHealthResponse { providers }))
}
