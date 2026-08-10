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
//! - `POST   /organizations/{org_did}/statements` — issue a signed `ak.realm.organization`
//!   statement (COA-ORG-03).
//!
//! Wire shapes come from [`coauth_admin_types::organization_admin`] and map
//! explicitly from storage-neutral domain records.

use arkret_canonical::{canonical_json_bytes, sha256_digest};
use arkret_identifiers::{DidFullId, EventId, Hash, RealmId, new_prefixed_uuid7};
use arkret_models_collaboration::{RealmOrganizationPayload, RealmOrganizationStatus};
use coauth_admin_types::organization_admin::{
    BootstrapAuthorizationInput, BootstrapOrganizationRequest, IssueOrganizationStatementRequest,
    ListOrganizationDelegationsOutcome, OrganizationControlView, OrganizationDelegation,
    OrganizationPrincipalControl, RecordOrganizationDelegationRequest,
    RenewOrganizationDelegationRequest, RotateOrganizationControllerRequest,
};
use coauth_data::organization_control::{
    NewOrganizationDelegation, NewOrganizationPrincipalControl,
    OrganizationPrincipalControl as DomainOrganizationPrincipalControl,
};
use coauth_data::{BoxRepository, RepositoryAccess};
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::Serialize;

use crate::JsonResult;
use crate::error::AppError;
use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::common::{DepotExt, make_clock, make_rng};
use crate::services::did_binding_proof::verify_detached_jws_with_sdk;
use crate::services::organization_bootstrap::{
    AuthorizedBootstrap, BootstrapAttempt, authorize_bootstrap,
};
use crate::services::organization_statement::{
    OrganizationStatementRequest, RepositoryDelegationResolver, issue_organization_statement,
    offline_resolver,
};

fn parse_did(raw: &str) -> Result<DidFullId, AppError> {
    DidFullId::new(raw.to_owned())
        .map_err(|e| AppError::bad_request(format!("invalid organization DID: {e}")))
}

#[derive(Serialize)]
struct OrganizationControllerBootstrapTranscript<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    organization_did: &'a str,
    principal_control_realm_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    control_stream_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_frontier_digest: Option<&'a str>,
    purpose: &'static str,
    profile: &'static str,
}

fn organization_controller_bootstrap_transcript_bytes(
    body: &BootstrapOrganizationRequest,
) -> Result<Vec<u8>, AppError> {
    canonical_json_bytes(&OrganizationControllerBootstrapTranscript {
        kind: "org.arkret.coauth.organization_pcr.bootstrap.v1",
        organization_did: &body.organization_did,
        principal_control_realm_id: &body.principal_control_realm_id,
        control_stream_ref: body.control_stream_ref.as_deref(),
        pcr_frontier_digest: body.pcr_frontier_digest.as_deref(),
        purpose: "principal_control",
        profile: "ak.profile.principal_control_realm.v1",
    })
    .map_err(|error| AppError::internal(std::io::Error::other(error.to_string())))
}

async fn verify_organization_controller_proof(
    depot: &Depot,
    repo: &mut BoxRepository,
    body: &BootstrapOrganizationRequest,
    proof_jws: &str,
) -> Result<String, AppError> {
    if proof_jws.trim().is_empty() {
        return Err(AppError::bad_request(
            "organization bootstrap requires a non-empty controller proof JWS",
        ));
    }
    let arkret_config = depot.arkret_config()?;
    let did_resolver = depot.did_resolver_service()?;
    let key_store = depot.key_store()?;
    let url_builder = depot.url_builder()?;
    let http_client = depot.http_client().map_err(AppError::internal)?;
    // §4 row 1 — an organization DID crossing this trust domain's boundary for
    // the first time. Bootstrap is a high-risk write, so it demands
    // `fresh_within(HIGH_RISK_MAX_AGE)` under the closed
    // `OrganizationRegistry` purpose; an acceptance made for any other purpose
    // (account binding, admin action, ...) can never satisfy this lookup.
    let resolution = crate::services::did_binding::authority_document(
        &http_client,
        &url_builder,
        &arkret_config,
        &key_store,
        repo,
        did_resolver.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        &body.organization_did,
        arkret_identity::DidBindingPurpose::OrganizationRegistry,
        crate::services::did_binding::high_risk_freshness(),
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(|error| AppError::bad_request(format!("organization_did_resolve_failed: {error}")))?;
    let payload = organization_controller_bootstrap_transcript_bytes(body)?;
    let verification_method = verify_detached_jws_with_sdk(
        proof_jws,
        &payload,
        &resolution.document.verification_method,
    )
    .map_err(|error| AppError::bad_request(format!("controller_proof_jws_invalid: {error}")))?;
    let method = resolution
        .document
        .verification_method
        .iter()
        .find(|method| method.id == verification_method)
        .ok_or_else(|| AppError::bad_request("controller proof verification method not found"))?;
    if method.controller != body.organization_did {
        return Err(AppError::bad_request(
            "controller proof verification method is not controlled by the organization DID",
        ));
    }
    Ok(sha256_digest(proof_jws.as_bytes()))
}

async fn load_control(
    repo: &mut BoxRepository,
    organization_did: &str,
) -> Result<DomainOrganizationPrincipalControl, AppError> {
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
    let create_event_id = body
        .control_stream_ref
        .as_deref()
        .ok_or_else(|| {
            AppError::bad_request(
                "organization bootstrap requires the accepted PCR create Event reference",
            )
        })
        .and_then(|reference| {
            EventId::new(reference.to_owned()).map_err(|error| {
                AppError::bad_request(format!("invalid PCR create Event ref: {error}"))
            })
        })?;
    let supplied_realm_id = RealmId::new(body.principal_control_realm_id.clone())
        .map_err(|error| AppError::bad_request(format!("invalid PCR Realm id: {error}")))?;
    if supplied_realm_id != RealmId::from_event_id(&create_event_id) {
        return Err(AppError::bad_request(
            "principal_control_realm_id is not derived from the accepted PCR create Event",
        ));
    }

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

    let verified_controller_proof_digest = match &body.authorization {
        BootstrapAuthorizationInput::DidControllerProof { proof_jws } => {
            Some(verify_organization_controller_proof(depot, &mut repo, &body, proof_jws).await?)
        }
        BootstrapAuthorizationInput::DelegatedGovernance { .. } => None,
    };

    let attempt = match &body.authorization {
        BootstrapAuthorizationInput::DidControllerProof { .. } => {
            BootstrapAttempt::ControllerProof {
                proof_digest: verified_controller_proof_digest,
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

    Ok(Json(control.into()))
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
        control: control.into(),
        delegations: delegations.into_iter().map(Into::into).collect(),
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
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
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
    Ok(Json(delegation.into()))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.organizations.revoke_delegation", skip_all)]
pub async fn revoke_delegation_handler(
    req: &mut Request,
    depot: &Depot,
    org_did: PathParam<String>,
    delegation_ref: PathParam<String>,
) -> JsonResult<OrganizationDelegation> {
    let organization_did = org_did.into_inner();
    let delegation_ref = delegation_ref.into_inner();
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let revoked = repo
        .organization_control()
        .revoke_delegation(&*clock, &organization_did, &delegation_ref)
        .await?;
    match revoked {
        Some(delegation) => {
            repo.save().await?;
            Ok(Json(delegation.into()))
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
    let organization_did = org_did.into_inner();
    let delegation_ref = delegation_ref.into_inner();
    let body: RenewOrganizationDelegationRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let renewed = repo
        .organization_control()
        .renew_delegation(
            &*clock,
            &organization_did,
            &delegation_ref,
            body.valid_until,
        )
        .await?;
    match renewed {
        Some(delegation) => {
            repo.save().await?;
            Ok(Json(delegation.into()))
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
            Ok(Json(control.into()))
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

    let arkret_config = depot.arkret_config()?;
    let key_store = depot.key_store()?;
    let service_full_id = crate::handlers::arkret::issuer_did_for(&arkret_config);

    let call_context = extract_call_context(req, depot).await?;
    let executed_by = None;
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
    let organization_id = arkret_identifiers::project_full_id_to_core_id(&organization_id)
        .map_err(|e| AppError::bad_request(format!("invalid organization DID: {e}")))?;
    let issuer = match (&body.delegation_ref, &delegation) {
        (Some(_), Some(delegation)) => {
            let full_id = DidFullId::new(delegation.delegate_did.clone())
                .map_err(|e| AppError::bad_request(format!("invalid delegate DID: {e}")))?;
            arkret_identifiers::project_full_id_to_core_id(&full_id)
                .map_err(|e| AppError::bad_request(format!("invalid delegate DID: {e}")))?
        }
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
        issue_organization_statement(
            &key_store,
            service_full_id.as_str(),
            request,
            now,
            &resolver,
        )
    } else {
        issue_organization_statement(
            &key_store,
            service_full_id.as_str(),
            request,
            now,
            &offline_resolver(),
        )
    }
    .map_err(|e| AppError::bad_request(format!("organization statement issuance failed: {e}")))?;

    repo.cancel().await?;
    Ok(Json(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap_request(organization_did: &str) -> BootstrapOrganizationRequest {
        BootstrapOrganizationRequest {
            organization_did: organization_did.to_owned(),
            principal_control_realm_id: "ak:realm:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG"
                .to_owned(),
            control_stream_ref: Some(
                "ak:event:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG".to_owned(),
            ),
            pcr_frontier_digest: Some(format!("sha256:{}", "ab".repeat(32))),
            authorization: BootstrapAuthorizationInput::DidControllerProof {
                proof_jws: "header..signature".to_owned(),
            },
        }
    }

    #[test]
    fn controller_proof_transcript_binds_organization_and_pcr_inputs() {
        let first = bootstrap_request("did:web:org-a.example");
        let mut second = bootstrap_request("did:web:org-b.example");
        let first_bytes = organization_controller_bootstrap_transcript_bytes(&first).unwrap();
        let second_bytes = organization_controller_bootstrap_transcript_bytes(&second).unwrap();
        assert_ne!(first_bytes, second_bytes);

        second.organization_did = first.organization_did.clone();
        second.pcr_frontier_digest = Some(format!("sha256:{}", "cd".repeat(32)));
        let changed_frontier = organization_controller_bootstrap_transcript_bytes(&second).unwrap();
        assert_ne!(first_bytes, changed_frontier);

        let transcript: serde_json::Value = serde_json::from_slice(&first_bytes).unwrap();
        assert_eq!(transcript["purpose"], "principal_control");
        assert_eq!(
            transcript["profile"],
            "ak.profile.principal_control_realm.v1"
        );
    }
}
