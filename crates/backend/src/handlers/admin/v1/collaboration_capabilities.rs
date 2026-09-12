//! Read-only admin views over collaboration capability grants.
//!
//! - `GET /_coauth/admin/collaboration/capabilities/templates`
//! - `GET /_coauth/admin/collaboration/capabilities`
//!
//! Issuing and revoking a collaboration capability used to live here too, via a
//! deployment-private `POST /_soland/root/authz/capability-fanout` edge that
//! handed soland a pre-minted `event_id` and a payload, which soland then
//! projected as if an Event had been accepted. No Event ever existed, and the
//! fanout proof signed a transcript rather than an Event digest.
//!
//! `ak.capability.grant` is capability-gated (`event-kind-registry.json` has no
//! `service_attested` admission for it) and `capabilities.md` section 18
//! resolves the *issuer's own* effective capability under the Control Move's
//! `seal_basis`. The issuer is the Event actor, so the grant has to be authored
//! and signed by the administrator who holds that authority, from a client that
//! custodies their key, submitted through the registered Event surface, and
//! executed in the Realm's confirmed safety sequence. An OAuth admin console
//! holds no such key; bridging that gap here would make coauth a signing oracle
//! for the control plane.
//!
//! The review surfaces stay because they need no key. See the arkret-work task
//! `2026-08-08-collaboration-capability-review-source.md` for repointing them
//! at soland's authoritative capability projection.

use coauth_admin_types::collaboration_capability_admin::{
    CollaborationCapabilityGrant, ListCollaborationCapabilityGrantsOutcome,
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

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.collaboration_capabilities.list", skip_all)]
pub async fn list_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<ListCollaborationCapabilityGrantsOutcome> {
    let mut repo = extract_call_context(req, depot).await?.repo;
    let data = repo
        .collaboration_capability_grant()
        .list_active()
        .await?
        .into_iter()
        .map(CollaborationCapabilityGrant::from)
        .collect();
    repo.cancel().await?;

    Ok(Json(ListCollaborationCapabilityGrantsOutcome { data }))
}
