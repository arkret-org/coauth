//! COA-ORG-02 / COA-ORG-05 — admin endpoints for organization principal
//! control + organization delegation management.
//!
//! Routes (all under `/_coauth/admin/organizations`):
//!
//! - `POST   /organizations/bootstrap` — bootstrap an organization PCR (COA-ORG-02). Authorized
//!   only by a DID controller proof or a `principal_control_realm_bootstrap` delegation; the admin
//!   session is only the executor.
//! - `GET    /organizations/{organization_id}` — read-only control state + delegations.
//! - `GET    /organizations/{organization_id}/delegations` — list delegations.
//! - `POST   /organizations/{organization_id}/delegations` — record a delegation.
//! - `POST   /organizations/{organization_id}/delegations/{ref}/revoke` — revoke.
//! - `POST   /organizations/{organization_id}/delegations/{ref}/renew` — renew validity.
//! - `POST   /organizations/{organization_id}/rotate-controller` — rotate the control stream /
//!   authority commit ref.
//! - `POST   /organizations/{organization_id}/statements` — issue a signed `ak.realm.organization`
//!   statement (COA-ORG-03).
//!
//! Wire shapes come from [`coauth_admin_types::organization_admin`] and map
//! explicitly from storage-neutral domain records.

use arkret_canonical::{canonical_json_bytes, sha256_digest};
use arkret_identifiers::{
    DidCoreId, DigestSuiteCode, EventId, RealmCommitId, RealmId, new_prefixed_uuid7,
    project_did_to_core_id,
};
use arkret_models_collaboration::{RealmOrganizationPayload, RealmOrganizationStatus};
use coauth_admin_types::organization_admin::{
    BootstrapAuthorizationInput, BootstrapOrganizationRequest, IssueOrganizationStatementRequest,
    ListOrganizationDelegationsOutcome, OrganizationControlView, OrganizationDelegation,
    OrganizationPrincipalControl, RecordOrganizationDelegationRequest,
    RenewOrganizationDelegationRequest, RotateOrganizationControllerRequest,
};
use coauth_data::organization_control::{
    NewOrganizationDelegation, NewOrganizationPrincipalControl,
    OrganizationPrincipalControl as DomainOrganizationPrincipalControl, RotatedOrganizationControl,
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

fn parse_organization_id(raw: &str) -> Result<DidCoreId, AppError> {
    DidCoreId::new(raw.to_owned())
        .map_err(|e| AppError::bad_request(format!("invalid organization_id: {e}")))
}

fn validate_organization_binding(body: &BootstrapOrganizationRequest) -> Result<(), AppError> {
    let projected = project_did_to_core_id(&body.organization_did)
        .map_err(|e| AppError::bad_request(format!("invalid organization DID: {e}")))?;
    if projected != body.organization_id {
        return Err(AppError::bad_request(
            "organization_id does not match the canonical projection of organization_did",
        ));
    }
    Ok(())
}

/// Parse a reference that has to name an Event on a Principal Control Realm's
/// control stream.
///
/// Being a canonical `ak:event:` token is necessary but not sufficient. v1 PCR
/// identity is fixed to SHA-256, so an Event under any other digest suite
/// cannot belong to one — and `RealmId::from_event_id` *asserts* that suite,
/// which means an unchecked ref would turn request input into a panic instead
/// of a 400.
fn parse_control_stream_ref(raw: &str) -> Result<EventId, AppError> {
    let event_id = EventId::new(raw.to_owned()).map_err(|error| {
        AppError::bad_request(format!("invalid PCR control stream Event ref: {error}"))
    })?;
    if event_id.digest_suite_code() != DigestSuiteCode::Sha256 {
        return Err(AppError::bad_request(
            "PCR control stream Event ref must use the SHA-256 digest suite",
        ));
    }
    Ok(event_id)
}

fn parse_commit_ref(raw: Option<&str>) -> Result<Option<RealmCommitId>, AppError> {
    raw.map(|value| RealmCommitId::new(value.to_owned()))
        .transpose()
        .map_err(|error| AppError::bad_request(format!("invalid pcr_commit_ref: {error}")))
}

#[derive(Serialize)]
struct OrganizationControllerBootstrapTranscript<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    organization_id: &'a str,
    organization_did: &'a str,
    principal_control_realm_id: &'a str,
    control_stream_ref: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_commit_ref: Option<&'a str>,
    purpose: &'static str,
    profile: &'static str,
}

fn organization_controller_bootstrap_transcript_bytes(
    body: &BootstrapOrganizationRequest,
) -> Result<Vec<u8>, AppError> {
    canonical_json_bytes(&OrganizationControllerBootstrapTranscript {
        kind: "org.arkret.coauth.organization_pcr.bootstrap.v1",
        organization_id: body.organization_id.as_str(),
        organization_did: body.organization_did.as_str(),
        principal_control_realm_id: &body.principal_control_realm_id,
        control_stream_ref: &body.control_stream_ref,
        pcr_commit_ref: body.pcr_commit_ref.as_deref(),
        purpose: "principal_control",
        profile: arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1,
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
    let keyring = depot.keyring()?;
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
        &keyring,
        repo,
        did_resolver.as_ref(),
        depot.verified_did_binding_store()?.as_ref(),
        body.organization_did.as_str(),
        arkret_identity::DidBindingPurpose::OrganizationRegistry,
        crate::services::did_binding::high_risk_freshness(),
        crate::handlers::make_clock().now(),
    )
    .await
    .map_err(|error| AppError::bad_request(format!("did_resolution_failed: {error}")))?;
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
    if method.controller != body.organization_did.as_str() {
        return Err(AppError::bad_request(
            "controller proof verification method is not controlled by the organization DID",
        ));
    }
    Ok(sha256_digest(proof_jws.as_bytes()))
}

async fn load_control(
    repo: &mut BoxRepository,
    organization_id: &DidCoreId,
) -> Result<DomainOrganizationPrincipalControl, AppError> {
    repo.organization_control()
        .get_control_by_id(organization_id)
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
    // The stable id / resolvable DID relation is an ingress invariant. Check it
    // before any lookup, authorization decision, or proof resolution.
    validate_organization_binding(&body)?;
    let create_event_id = parse_control_stream_ref(&body.control_stream_ref)?;
    parse_commit_ref(body.pcr_commit_ref.as_deref())?;
    let supplied_realm_id = RealmId::new(body.principal_control_realm_id.clone())
        .map_err(|error| AppError::bad_request(format!("invalid PCR Realm id: {error}")))?;
    if supplied_realm_id != RealmId::from_event_id(&create_event_id) {
        return Err(AppError::bad_request(
            "principal_control_realm_id is not derived from the accepted PCR create Event",
        ));
    }

    let call_context = extract_call_context(req, depot).await?;
    // The authenticated admin / service principal is only the executor.
    let arkret_config = depot.arkret_config()?;
    let has_admin_session = call_context.session.user_id().is_some()
        || matches!(
            call_context.session,
            crate::handlers::admin::call_context::CallerSession::PersonalSession(_)
        );
    let mut repo = call_context.repo;
    let executed_by = match call_context.user.as_ref() {
        Some(user) => Some(
            crate::handlers::arkret::published_principal_id_for_user(
                &mut repo,
                &arkret_config,
                user,
            )
            .await?
            .ok_or_else(|| AppError::conflict("admin account has no published principal_id"))?,
        ),
        None => None,
    };
    let clock = call_context.clock;
    let now = clock.now();

    if repo
        .organization_control()
        .get_control_by_id(&body.organization_id)
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
    } = authorize_bootstrap(&body.organization_id, has_admin_session, attempt, now).map_err(
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
                organization_id: body.organization_id,
                organization_did: body.organization_did,
                principal_control_realm_id: body.principal_control_realm_id,
                control_stream_ref: body.control_stream_ref,
                pcr_commit_ref: body.pcr_commit_ref,
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
    organization_id: PathParam<String>,
) -> JsonResult<OrganizationControlView> {
    let organization_id = parse_organization_id(&organization_id.into_inner())?;
    let mut repo = extract_call_context(req, depot).await?.repo;
    let control = load_control(&mut repo, &organization_id).await?;
    let delegations = repo
        .organization_control()
        .list_delegations_for_org(&organization_id)
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
    organization_id: PathParam<String>,
) -> JsonResult<ListOrganizationDelegationsOutcome> {
    let organization_id = parse_organization_id(&organization_id.into_inner())?;
    let mut repo = extract_call_context(req, depot).await?.repo;
    let data = repo
        .organization_control()
        .list_delegations_for_org(&organization_id)
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
    organization_id: PathParam<String>,
) -> JsonResult<OrganizationDelegation> {
    let organization_id = parse_organization_id(&organization_id.into_inner())?;
    let body: RecordOrganizationDelegationRequest = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid delegation body: {e}")))?;

    let call_context = extract_call_context(req, depot).await?;
    let arkret_config = depot.arkret_config()?;
    let mut repo = call_context.repo;
    let created_by = match call_context.user.as_ref() {
        Some(user) => crate::handlers::arkret::published_principal_id_for_user(
            &mut repo,
            &arkret_config,
            user,
        )
        .await?
        .ok_or_else(|| AppError::conflict("admin account has no published principal_id"))?,
        None => crate::handlers::arkret::owning_station_id_for(&arkret_config),
    };
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
                organization_id,
                delegate_id: body.delegate_id,
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
    organization_id: PathParam<String>,
    delegation_ref: PathParam<String>,
) -> JsonResult<OrganizationDelegation> {
    let organization_id = parse_organization_id(&organization_id.into_inner())?;
    let delegation_ref = delegation_ref.into_inner();
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let revoked = repo
        .organization_control()
        .revoke_delegation(&*clock, &organization_id, &delegation_ref)
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
    organization_id: PathParam<String>,
    delegation_ref: PathParam<String>,
) -> JsonResult<OrganizationDelegation> {
    let organization_id = parse_organization_id(&organization_id.into_inner())?;
    let delegation_ref = delegation_ref.into_inner();
    let body: RenewOrganizationDelegationRequest = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let renewed = repo
        .organization_control()
        .renew_delegation(&*clock, &organization_id, &delegation_ref, body.valid_until)
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
    organization_id: PathParam<String>,
) -> JsonResult<OrganizationPrincipalControl> {
    let organization_id = parse_organization_id(&organization_id.into_inner())?;
    let body: RotateOrganizationControllerRequest = req
        .parse_json()
        .await
        .map_err(|e| AppError::bad_request(format!("invalid rotate body: {e}")))?;
    // The rotated-to state is fully validated before a repository is opened, so
    // a malformed ref can never reach the database layer.
    let rotated = RotatedOrganizationControl {
        control_stream_ref: parse_control_stream_ref(&body.control_stream_ref)?,
        pcr_commit_ref: parse_commit_ref(body.pcr_commit_ref.as_deref())?,
    };
    let mut repo = extract_call_context(req, depot).await?.repo;
    let clock = make_clock();
    let updated = repo
        .organization_control()
        .replace_control_state(&*clock, &organization_id, rotated)
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
    let organization_id = req
        .param::<String>("organization_id")
        .ok_or_else(|| AppError::bad_request("missing organization_id"))?;
    let organization_id = parse_organization_id(&organization_id)?;
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
    let realm_commit_ref = body
        .realm_commit_ref
        .as_deref()
        .map(|raw| RealmCommitId::new(raw.to_owned()))
        .transpose()
        .map_err(|e| AppError::bad_request(format!("invalid realm_commit_ref: {e}")))?;

    let arkret_config = depot.arkret_config()?;
    let keyring = depot.keyring()?;
    let service_did = crate::handlers::arkret::owning_station_did_for(&arkret_config);

    let call_context = extract_call_context(req, depot).await?;
    let executed_by = None;
    let mut repo = call_context.repo;
    let clock = call_context.clock;
    let now = clock.now();

    // Issuer of the statement: the stable organization id for direct
    // statements, the stable delegate id for delegated statements.
    let delegation = match &body.delegation_ref {
        Some(reference) => {
            repo.organization_control()
                .get_delegation_by_ref(reference)
                .await?
        }
        None => None,
    };
    let issuer = match (&body.delegation_ref, &delegation) {
        (Some(_), Some(delegation)) => delegation.delegate_id.clone(),
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
        realm_commit_ref,
        organization_policy_ref: body.organization_policy_ref,
        issuer_id: issuer,
        issuer_role: body.issuer_role,
        delegation_ref: body.delegation_ref.clone(),
        executed_by,
    };

    // Sign + self-verify. Delegated statements resolve against the durable
    // delegation row; direct statements use the offline resolver.
    let payload = if body.delegation_ref.is_some() {
        let resolver = RepositoryDelegationResolver::new(delegation, now);
        issue_organization_statement(&keyring, service_did.as_str(), request, now, &resolver)
    } else {
        issue_organization_statement(
            &keyring,
            service_did.as_str(),
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
    use arkret_identifiers::Did;

    use super::*;

    fn bootstrap_request(did: &str) -> BootstrapOrganizationRequest {
        let did = Did::new(did.to_owned()).unwrap();
        BootstrapOrganizationRequest {
            organization_id: project_did_to_core_id(&did).unwrap(),
            organization_did: did,
            principal_control_realm_id: "ak:realm:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG"
                .to_owned(),
            control_stream_ref: "ak:event:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG".to_owned(),
            pcr_commit_ref: Some(
                "ak:realm_commit:Aaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur".to_owned(),
            ),
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

        second.organization_id = first.organization_id.clone();
        second.organization_did = first.organization_did.clone();
        second.pcr_commit_ref =
            Some("ak:realm_commit:Ac3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3N".to_owned());
        let changed_commit = organization_controller_bootstrap_transcript_bytes(&second).unwrap();
        assert_ne!(first_bytes, changed_commit);

        let transcript: serde_json::Value = serde_json::from_slice(&first_bytes).unwrap();
        assert_eq!(transcript["purpose"], "principal_control");
        assert_eq!(
            transcript["organization_id"],
            first.organization_id.as_str()
        );
        assert_eq!(
            transcript["organization_did"],
            first.organization_did.as_str()
        );
        assert_eq!(
            transcript["profile"],
            "ak.profile.principal_control_realm.v1"
        );
    }

    #[test]
    fn bootstrap_body_without_control_stream_ref_fails_to_decode() {
        let body = serde_json::json!({
            "organization_id": "ak:did_core:web:org-a.example",
            "organization_did": "did:web:org-a.example",
            "principal_control_realm_id":
                "ak:realm:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG",
            "authorization": { "kind": "did_controller_proof", "proof_jws": "header..signature" },
        });
        let error = serde_json::from_value::<BootstrapOrganizationRequest>(body)
            .expect_err("control_stream_ref must be rejected at decode time");
        assert!(
            error.to_string().contains("control_stream_ref"),
            "unexpected decode error: {error}"
        );
    }

    #[test]
    fn bootstrap_rejects_mismatched_organization_id_and_did() {
        let mut body = bootstrap_request("did:web:org-a.example");
        body.organization_id = DidCoreId::new("ak:did_core:web:org-b.example".to_owned()).unwrap();

        let error = validate_organization_binding(&body)
            .expect_err("a stable id from another DID must fail closed");
        assert!(error.to_string().contains("organization_id"));
    }

    #[test]
    fn rotation_body_without_a_control_stream_ref_fails_to_decode() {
        // An absent field is named in serde's error; an explicit null is a type
        // error on the field's own value and carries no field name. Both are
        // decode failures, which is the property under test: an empty or
        // nulled-out body can never reach the handler as a rotation.
        for (body, expected_fragment) in [
            (serde_json::json!({}), "control_stream_ref"),
            (
                serde_json::json!({ "pcr_commit_ref": "ak:realm_commit:Aaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur" }),
                "control_stream_ref",
            ),
            (
                serde_json::json!({ "control_stream_ref": serde_json::Value::Null }),
                "invalid type: null",
            ),
        ] {
            let error = serde_json::from_value::<RotateOrganizationControllerRequest>(body.clone())
                .expect_err("a rotation must state the complete post-rotation control state");
            assert!(
                error.to_string().contains(expected_fragment),
                "unexpected decode error for {body}: {error}"
            );
        }
    }

    #[test]
    fn rotation_body_treats_an_absent_commit_ref_as_the_rotated_to_value() {
        let decoded =
            serde_json::from_value::<RotateOrganizationControllerRequest>(serde_json::json!({
                "control_stream_ref":
                    "ak:event:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG",
            }))
            .expect("a rotation without a commit ref rotates onto a commit-less state");
        assert_eq!(decoded.pcr_commit_ref, None);

        let explicit_null =
            serde_json::from_value::<RotateOrganizationControllerRequest>(serde_json::json!({
                "control_stream_ref":
                    "ak:event:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG",
                "pcr_commit_ref": serde_json::Value::Null,
            }))
            .expect("an explicit null commit ref decodes to the same rotated-to state");
        assert_eq!(explicit_null.pcr_commit_ref, None);
    }

    #[test]
    fn control_stream_ref_must_be_a_sha256_event_reference() {
        parse_control_stream_ref("ak:event:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG")
            .expect("a canonical SHA-256 Event ref is a valid control stream ref");

        for rejected in [
            "",
            "   ",
            "ak:realm:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG",
            "ak:event:not-canonical",
            "ak:event:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG=",
        ] {
            assert!(
                parse_control_stream_ref(rejected).is_err(),
                "{rejected} must not be accepted as a PCR control stream ref"
            );
        }

        // The token is structurally canonical, but its suite byte identifies
        // BLAKE3. A v1 Event identity must be rejected at the parser boundary.
        let blake3_event = "ak:event:AgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG";
        assert!(arkret_identifiers::EventId::new(blake3_event).is_err());
        assert!(parse_control_stream_ref(blake3_event).is_err());
    }

    #[test]
    fn commit_ref_must_be_a_canonical_realm_commit_id() {
        assert_eq!(parse_commit_ref(None).unwrap(), None);
        assert!(
            parse_commit_ref(Some(
                "ak:realm_commit:Aaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur"
            ))
            .unwrap()
            .is_some()
        );
        for rejected in [
            "",
            "sha256:",
            "deadbeef",
            &format!("sha256:{}", "ab".repeat(32)),
            "ak:realm_commit:not-canonical",
            "ak:realm:AQYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG",
        ] {
            assert!(
                parse_commit_ref(Some(rejected)).is_err(),
                "{rejected} must not be accepted as a PCR control authority commit ref"
            );
        }
    }
}
