//! COA-ORG-02 / COA-ORG-05 — admin endpoints for organization principal
//! control + organization delegation management.
//!
//! Routes (all under `/_coauth/admin/organizations`):
//!
//! - `POST   /organizations/bootstrap` — bootstrap an organization PCR (COA-ORG-02). Authorized
//!   only by a DID controller proof or a `principal_control_realm_bootstrap` delegation; the admin
//!   session is only the executor.
//! - `GET    /organizations/{org_did}` — read-only control state + delegations.
//! - `GET    /organizations/{org_did}/delegations` — list delegations.
//! - `POST   /organizations/{org_did}/delegations` — record a delegation.
//! - `POST   /organizations/{org_did}/delegations/{ref}/revoke` — revoke.
//! - `POST   /organizations/{org_did}/delegations/{ref}/renew` — renew validity.
//! - `POST   /organizations/{org_did}/rotate-controller` — rotate the control stream / frontier
//!   ref.
//! - `POST   /organizations/{org_did}/statements` — issue a signed `ck.realm.organization`
//!   statement (COA-ORG-03).
//!
//! Wire shapes come from [`coauth_admin_types::organization_admin`] (which
//! re-exports the shared `coauth-data` domain types) and the SDK
//! [`cokret_core::models::RealmOrganizationPayload`]. No admin-private wire
//! struct is defined here.

use coauth_admin_types::organization_admin::{
    BootstrapAuthorizationInput, BootstrapOrganizationRequest, IssueOrganizationStatementRequest,
    ListOrganizationDelegationsOutcome, OrganizationControlView, OrganizationPrincipalControl,
    RecordOrganizationDelegationRequest, RenewOrganizationDelegationRequest,
    RotateOrganizationControllerRequest,
};
use coauth_data::organization_control::{
    NewOrganizationDelegation, NewOrganizationPrincipalControl, OrganizationDelegation,
};
use coauth_data::{BoxRepository, RepositoryAccess};
use cokret_core::identifiers::new_prefixed_uuid7;
use cokret_core::models::{RealmOrganizationPayload, RealmOrganizationStatus};
use cokret_core::{Did, Hash, RealmId};
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;

use crate::JsonResult;
use crate::error::AppError;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::common::{DepotExt, make_clock, make_rng};
use crate::services::organization_bootstrap::{
    AuthorizedBootstrap, BootstrapAttempt, authorize_bootstrap,
};
use crate::services::organization_statement::{
    OrganizationStatementRequest, RepositoryDelegationResolver, issue_organization_statement,
    offline_resolver,
};

fn parse_did(raw: &str) -> Result<Did, AppError> {
    Did::new(raw.to_owned())
        .map_err(|e| AppError::bad_request(format!("invalid organization DID: {e}")))
}

async fn load_control(
    repo: &mut BoxRepository,
    organization_did: &str,
) -> Result<OrganizationPrincipalControl, AppError> {
    repo.organization_control()
        .get_control_by_did(organization_did)
        .await?
        .ok_or_else(|| AppError::not_found("organization control state not found"))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.bootstrap", skip_all)]
pub async fn bootstrap_handler(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<OrganizationPrincipalControl> {
    let body: BootstrapOrganizationRequest = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid bootstrap body: {e}")))?;
    // Validate the organization DID shape up front.
    parse_did(&body.organization_did)?;

    let call_context = extract_call_context(req, depot).await?;
    // The authenticated admin / service principal is only the executor.
    let executed_by = call_context
        .user
        .as_ref()
        .map(|user| format!("user:{}", user.id));
    let has_admin_session = call_context.session.user_id().is_some()
        || matches!(
            call_context.session,
            crate::handlers::admin::call_context::CallerSession::PersonalSession(_)
        );
    let mut repo = call_context.repo;
    let clock = call_context.clock;
    let now = clock.now();

    if repo
        .organization_control()
        .get_control_by_did(&body.organization_did)
        .await?
        .is_some()
    {
        repo.cancel().await?;
        return Err(AppError::conflict(
            "organization control state already bootstrapped",
        ));
    }

    // Resolve the delegation row (if delegated) so the decision can verify it.
    let delegation = match &body.authorization {
        BootstrapAuthorizationInput::DelegatedGovernance { delegation_ref } => {
            repo.organization_control()
                .get_delegation_by_ref(delegation_ref)
                .await?
        }
        BootstrapAuthorizationInput::DidControllerProof { .. } => None,
    };

    let attempt = match &body.authorization {
        BootstrapAuthorizationInput::DidControllerProof { proof_digest } => {
            BootstrapAttempt::ControllerProof {
                proof_digest: Some(proof_digest.clone()),
            }
        }
        BootstrapAuthorizationInput::DelegatedGovernance { delegation_ref } => {
            BootstrapAttempt::Delegated {
                delegation_ref,
                delegation: delegation.as_ref(),
            }
        }
    };

    let AuthorizedBootstrap {
        bootstrap_authorization,
        bootstrap_delegation_ref,
        bootstrap_proof_digest,
    } = authorize_bootstrap(&body.organization_did, has_admin_session, attempt, now).map_err(
        |e| {
            // Authorization failures are caller errors (forbidden), not 500s.
            AppError::forbidden(format!("organization bootstrap rejected: {e}"))
        },
    )?;

    let mut rng = make_rng();
    let control = repo
        .organization_control()
        .bootstrap(
            &mut *rng,
            &*clock,
            NewOrganizationPrincipalControl {
                organization_did: body.organization_did,
                principal_control_realm_id: body.principal_control_realm_id,
                control_stream_ref: body.control_stream_ref,
                pcr_frontier_digest: body.pcr_frontier_digest,
                bootstrap_authorization,
                bootstrap_delegation_ref,
                executed_by,
                bootstrap_proof_digest,
            },
        )
        .await?;
    repo.save().await?;

    Ok(Json(control))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.get", skip_all)]
pub async fn get_handler(
    req: &mut Request,
    depot: &Depot,
    org_did: PathParam<String>,
) -> JsonResult<OrganizationControlView> {
    let organization_did = org_did.into_inner();
    let mut repo = extract_call_context(req, depot).await?.repo;
    let control = load_control(&mut repo, &organization_did).await?;
    let delegations = repo
        .organization_control()
        .list_delegations_for_org(&organization_did)
        .await?;
    repo.cancel().await?;
    Ok(Json(OrganizationControlView {
        control,
        delegations,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.list_delegations", skip_all)]
pub async fn list_delegations_handler(
    req: &mut Request,
    depot: &Depot,
    org_did: PathParam<String>,
) -> JsonResult<ListOrganizationDelegationsOutcome> {
    let organization_did = org_did.into_inner();
    let mut repo = extract_call_context(req, depot).await?.repo;
    let data = repo
        .organization_control()
        .list_delegations_for_org(&organization_did)
        .await?;
    repo.cancel().await?;
    Ok(Json(ListOrganizationDelegationsOutcome { data }))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.record_delegation", skip_all)]
pub async fn record_delegation_handler(
    req: &mut Request,
    depot: &Depot,
    org_did: PathParam<String>,
) -> JsonResult<OrganizationDelegation> {
    let organization_did = org_did.into_inner();
    parse_did(&organization_did)?;
    let body: RecordOrganizationDelegationRequest = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid delegation body: {e}")))?;

    let call_context = extract_call_context(req, depot).await?;
    let created_by = call_context
        .user
        .as_ref()
        .map_or_else(|| "service".to_owned(), |user| format!("user:{}", user.id));
    let mut repo = call_context.repo;
    let clock = call_context.clock;
    let valid_from = body.valid_from.unwrap_or_else(|| clock.now());

    let mut rng = make_rng();
    let delegation = repo
        .organization_control()
        .add_delegation(
            &mut *rng,
            &*clock,
            NewOrganizationDelegation {
                delegation_ref: body.delegation_ref,
                organization_did,
                delegate_did: body.delegate_did,
                issuer_role: body.issuer_role,
                purposes: body.purposes,
                covered_relationships: body.covered_relationships,
                covered_control_scopes: body.covered_control_scopes,
                valid_from,
                valid_until: body.valid_until,
                created_by,
            },
        )
        .await?;
    repo.save().await?;
    Ok(Json(delegation))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.revoke_delegation", skip_all)]
pub async fn revoke_delegation_handler(
    req: &mut Request,
    depot: &Depot,
    org_did: PathParam<String>,
    delegation_ref: PathParam<String>,
) -> JsonResult<OrganizationDelegation> {
    let _organization_did = org_did.into_inner();
    let delegation_ref = delegation_ref.into_inner();
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let revoked = repo
        .organization_control()
        .revoke_delegation(&*clock, &delegation_ref)
        .await?;
    match revoked {
        Some(delegation) => {
            repo.save().await?;
            Ok(Json(delegation))
        }
        None => {
            repo.cancel().await?;
            Err(AppError::not_found(
                "active organization delegation not found",
            ))
        }
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.renew_delegation", skip_all)]
pub async fn renew_delegation_handler(
    req: &mut Request,
    depot: &Depot,
    org_did: PathParam<String>,
    delegation_ref: PathParam<String>,
) -> JsonResult<OrganizationDelegation> {
    let _organization_did = org_did.into_inner();
    let delegation_ref = delegation_ref.into_inner();
    let body: RenewOrganizationDelegationRequest = req.parse_json().await.unwrap_or_default();
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let renewed = repo
        .organization_control()
        .renew_delegation(&*clock, &delegation_ref, body.valid_until)
        .await?;
    match renewed {
        Some(delegation) => {
            repo.save().await?;
            Ok(Json(delegation))
        }
        None => {
            repo.cancel().await?;
            Err(AppError::not_found(
                "active organization delegation not found",
            ))
        }
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.rotate_controller", skip_all)]
pub async fn rotate_controller_handler(
    req: &mut Request,
    depot: &Depot,
    org_did: PathParam<String>,
) -> JsonResult<OrganizationPrincipalControl> {
    let organization_did = org_did.into_inner();
    let body: RotateOrganizationControllerRequest = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid rotate body: {e}")))?;
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let updated = repo
        .organization_control()
        .update_control(
            &*clock,
            &organization_did,
            body.control_stream_ref,
            body.pcr_frontier_digest,
        )
        .await?;
    match updated {
        Some(control) => {
            repo.save().await?;
            Ok(Json(control))
        }
        None => {
            repo.cancel().await?;
            Err(AppError::not_found("organization control state not found"))
        }
    }
}

// `#[handler]` (not `#[endpoint]`): the response is the SDK
// `RealmOrganizationPayload`, which only derives `salvo::oapi::ToSchema` behind
// the SDK's own `salvo` feature (not enabled in coauth's build). Protocol-typed
// responses use `#[handler]` across coauth for exactly this reason.
#[handler]
#[tracing::instrument(name = "handler.admin.v1.organizations.issue_statement", skip_all)]
pub async fn issue_statement_handler(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<RealmOrganizationPayload>, AppError> {
    let org_did = req
        .param::<String>("org_did")
        .ok_or_else(|| AppError::bad_request("missing org_did"))?;
    let organization_did = org_did;
    let organization_id = parse_did(&organization_did)?;
    let body: IssueOrganizationStatementRequest = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid statement body: {e}")))?;

    let realm_id = RealmId::new(body.realm_id.as_str())
        .map_err(|e| AppError::bad_request(format!("invalid realm_id: {e}")))?;
    if body.control_scopes.is_empty() {
        return Err(AppError::bad_request("control_scopes must be non-empty"));
    }
    if matches!(body.status, RealmOrganizationStatus::Revoked)
        && body.revokes_statement_id.is_none()
    {
        return Err(AppError::bad_request(
            "revoked statement requires revokes_statement_id",
        ));
    }
    let realm_frontier_digest = body
        .realm_frontier_digest
        .as_deref()
        .map(|raw| Hash::new(raw.to_owned()))
        .transpose()
        .map_err(|e| AppError::bad_request(format!("invalid realm_frontier_digest: {e}")))?;

    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let service_did = crate::handlers::arkret::service_did_for(&cokret_config);

    let call_context = extract_call_context(req, depot).await?;
    let executed_by = call_context
        .user
        .as_ref()
        .and_then(|user| Did::new(format!("user:{}", user.id)).ok());
    let mut repo = call_context.repo;
    let clock = call_context.clock;
    let now = clock.now();

    // Issuer of the statement: the organization DID for direct statements, the
    // delegate DID for delegated statements.
    let delegation = match &body.delegation_ref {
        Some(reference) => {
            repo.organization_control()
                .get_delegation_by_ref(reference)
                .await?
        }
        None => None,
    };
    let issuer = match (&body.delegation_ref, &delegation) {
        (Some(_), Some(delegation)) => Did::new(delegation.delegate_did.clone())
            .map_err(|e| AppError::bad_request(format!("invalid delegate DID: {e}")))?,
        _ => organization_id.clone(),
    };

    let statement_id = body
        .statement_id
        .unwrap_or_else(|| new_prefixed_uuid7("ak:orgstmt:"));

    let request = OrganizationStatementRequest {
        statement_id,
        realm_id,
        organization_id,
        relationship: body.relationship,
        status: body.status,
        control_scopes: body.control_scopes,
        issued_at: now,
        not_before: body.not_before,
        expires_at: body.expires_at,
        supersedes_statement_id: body.supersedes_statement_id,
        revokes_statement_id: body.revokes_statement_id,
        realm_frontier_digest,
        organization_policy_ref: body.organization_policy_ref,
        issuer,
        issuer_role: body.issuer_role,
        delegation_ref: body.delegation_ref.clone(),
        executed_by,
    };

    // Sign + self-verify. Delegated statements resolve against the durable
    // delegation row; direct statements use the offline resolver.
    let payload = if body.delegation_ref.is_some() {
        let resolver = RepositoryDelegationResolver::new(delegation, now);
        issue_organization_statement(&key_store, &service_did, request, now, &resolver)
    } else {
        issue_organization_statement(&key_store, &service_did, request, now, &offline_resolver())
    }
    .map_err(|e| AppError::bad_request(format!("organization statement issuance failed: {e}")))?;

    repo.cancel().await?;
    Ok(Json(payload))
}
