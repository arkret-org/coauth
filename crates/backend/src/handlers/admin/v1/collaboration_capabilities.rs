//! Read-only capability templates from the canonical SDK registry.
//!
//! Accepted grant review is served by the governing Station's operator query
//! and rendered by Codmin. Coauth holds no collaboration-grant mirror or read fallback.

use coauth_admin_types::collaboration_capability_admin::{
    ListCollaborationCapabilityTemplatesOutcome, collaboration_capability_templates,
};
use salvo::prelude::*;

use crate::JsonResult;
use crate::handlers::admin::call_context::extract_call_context;

#[endpoint]
#[tracing::instrument(
    name = "handler.admin.v1.collaboration_capabilities.templates",
    skip_all
)]
pub async fn templates_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ListCollaborationCapabilityTemplatesOutcome> {
    let repo = extract_call_context(req, depot).await?.repo;
    repo.cancel().await?;
    Ok(Json(ListCollaborationCapabilityTemplatesOutcome {
        data: collaboration_capability_templates(),
    }))
}
