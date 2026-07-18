// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use coauth_data::RepositoryAccess;
use coauth_data::audit::AdminOperation;
use coauth_data::upstream_oauth::UpstreamOAuthLinkFilter;
use salvo::http::StatusCode;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::handlers::admin::call_context::extract_call_context;
use crate::handlers::admin::model::{Resource, UpstreamOAuthLink, to_upstream_oauth_link};
use crate::handlers::admin::params::{IncludeCount, extract_pagination, extract_ulid_param};
use crate::handlers::admin::response::{
    PaginatedOutcome, SingleOutcome, paginated_response_for_count_only, paginated_response_for_page,
};
use crate::{AppError, AppResult, CreatedJsonResult, JsonResult};

/// JSON body accepted by `POST /_coauth/admin/upstream-oauth-links`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUpstreamOauthLinkRequest")]
pub struct AddRequestBody {
    /// Identifier of the user to associate with this link.
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    user_id: Ulid,

    /// Identifier of the upstream OAuth provider.
    #[schemars(with = "crate::handlers::admin::schema::Ulid")]
    provider_id: Ulid,

    /// The subject (sub) claim identifying the user at the provider.
    subject: String,

    /// Optional human-readable label for this account.
    human_account_name: Option<String>,
}

/// Create a new upstream OAuth link or associate an existing unlinked one.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.post", skip_all)]
pub async fn add_link(
    req: &mut Request,
    depot: &Depot,
) -> CreatedJsonResult<SingleOutcome<UpstreamOAuthLink>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let body: AddRequestBody = req.parse_json().await.map_err(AppError::internal)?;

    // Resolve the target user
    let owner = repo
        .user()
        .lookup(body.user_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {} not found", body.user_id)))?;

    // Resolve the upstream provider
    let provider = repo
        .upstream_oauth_provider()
        .lookup(body.provider_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "Upstream OAuth Provider ID {} not found",
                body.provider_id
            ))
        })?;

    // Check whether a link with this subject already exists for the provider
    let existing_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, &body.subject)
        .await?;

    if let Some(mut entry) = existing_link {
        // If already associated to a user, reject as conflict
        if entry.user_id.is_some() {
            return Err(AppError::conflict(format!(
                "Upstream OAuth 2.0 Provider ID {} with subject {} is already linked to a user",
                entry.provider_id, entry.subject
            )));
        }

        // Otherwise, associate the orphaned link to the requested user
        repo.upstream_oauth_link()
            .associate_to_user(&entry, &owner)
            .await?;
        entry.user_id = Some(owner.id);

        crate::handlers::admin::audit_helper::record_admin_operation(
            &mut repo,
            &mut rng,
            &*clock,
            admin_user.as_ref(),
            AdminOperation::UpstreamLinkCreated,
            "upstream_oauth_link",
            Some(entry.id),
            serde_json::json!({
                "provider_id": provider.id.to_string(),
                "subject": entry.subject,
                "user_id": owner.id.to_string(),
            }),
        )
        .await?;

        repo.save().await?;

        return Ok(crate::handlers::admin::CreatedJson(
            SingleOutcome::new_canonical(to_upstream_oauth_link(entry)),
        ));
    }

    // No existing link -- create a brand-new one
    let mut entry = repo
        .upstream_oauth_link()
        .add(
            &mut rng,
            &clock,
            &provider,
            body.subject,
            body.human_account_name,
        )
        .await?;

    repo.upstream_oauth_link()
        .associate_to_user(&entry, &owner)
        .await?;
    entry.user_id = Some(owner.id);

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamLinkCreated,
        "upstream_oauth_link",
        Some(entry.id),
        serde_json::json!({
            "provider_id": provider.id.to_string(),
            "subject": entry.subject,
            "user_id": owner.id.to_string(),
        }),
    )
    .await?;

    repo.save().await?;

    Ok(crate::handlers::admin::CreatedJson(
        SingleOutcome::new_canonical(to_upstream_oauth_link(entry)),
    ))
}

/// Remove an upstream OAuth link by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.delete", skip_all)]
pub async fn delete_link(req: &mut Request, depot: &Depot) -> AppResult<StatusCode> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let link_id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();

    let entry = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Upstream OAuth Link ID {link_id} not found"))
        })?;

    let provider_id = entry.provider_id;
    let subject = entry.subject.clone();

    repo.upstream_oauth_link().remove(&clock, entry).await?;

    crate::handlers::admin::audit_helper::record_admin_operation(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        AdminOperation::UpstreamLinkDeleted,
        "upstream_oauth_link",
        Some(link_id),
        serde_json::json!({
            "provider_id": provider_id.to_string(),
            "subject": subject,
        }),
    )
    .await?;

    repo.save().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Retrieve a single upstream OAuth link by its identifier.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.get", skip_all)]
pub async fn get_link(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UpstreamOAuthLink>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let link_id = extract_ulid_param(req)?;

    let entry = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found(format!("Upstream OAuth Link ID {link_id} not found"))
        })?;

    Ok(Json(SingleOutcome::new_canonical(to_upstream_oauth_link(
        entry,
    ))))
}

/// Query-string filters for the upstream OAuth link list endpoint.
#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UpstreamOAuthLinkFilter")]
pub struct FilterParams {
    /// Narrow results to links belonging to this user
    #[serde(rename = "filter[user]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    user: Option<Ulid>,

    /// Narrow results to links from this provider
    #[serde(rename = "filter[provider]")]
    #[schemars(with = "Option<crate::handlers::admin::schema::Ulid>")]
    provider: Option<Ulid>,

    /// Narrow results to links matching this subject claim
    #[serde(rename = "filter[subject]")]
    subject: Option<String>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut delimiter = '?';

        if let Some(uid) = self.user {
            write!(f, "{delimiter}filter[user]={uid}")?;
            delimiter = '&';
        }

        if let Some(pid) = self.provider {
            write!(f, "{delimiter}filter[provider]={pid}")?;
            delimiter = '&';
        }

        if let Some(sub) = &self.subject {
            write!(f, "{delimiter}filter[subject]={sub}")?;
            delimiter = '&';
        }

        let _ = delimiter;
        Ok(())
    }
}

/// List upstream OAuth links with optional filtering and pagination.
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.list", skip_all)]
pub async fn list_links(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PaginatedOutcome<UpstreamOAuthLink>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = ctx;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base_url = format!("{path}{params}", path = UpstreamOAuthLink::PATH);
    let base_url = include_count.add_to_base(&base_url);
    let mut filter = UpstreamOAuthLinkFilter::default();

    // Optionally scope to a particular user
    let resolved_user = match params.user {
        Some(uid) => {
            let u = repo
                .user()
                .lookup(uid)
                .await?
                .ok_or_else(|| AppError::not_found(format!("User ID {uid} not found")))?;
            Some(u)
        }
        None => None,
    };

    filter = match &resolved_user {
        Some(u) => filter.for_user(u),
        None => filter,
    };

    // Optionally scope to a particular provider
    let resolved_provider = match params.provider {
        Some(pid) => {
            let p = repo
                .upstream_oauth_provider()
                .lookup(pid)
                .await?
                .ok_or_else(|| AppError::not_found(format!("Provider ID {pid} not found")))?;
            Some(p)
        }
        None => None,
    };

    filter = match &resolved_provider {
        Some(p) => filter.for_provider(p),
        None => filter,
    };

    // Optionally match by subject claim
    filter = match &params.subject {
        Some(sub) => filter.for_subject(sub),
        None => filter,
    };

    let result = match include_count {
        IncludeCount::True => {
            let page = repo
                .upstream_oauth_link()
                .list(filter, pagination)
                .await?
                .map(to_upstream_oauth_link);
            let total = repo.upstream_oauth_link().count(filter).await?;
            paginated_response_for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .upstream_oauth_link()
                .list(filter, pagination)
                .await?
                .map(to_upstream_oauth_link);
            paginated_response_for_page(page, pagination, None, &base_url)
        }
        IncludeCount::Only => {
            let total = repo.upstream_oauth_link().count(filter).await?;
            paginated_response_for_count_only(total, &base_url)
        }
    };

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct UpdateRequestBody {
    user_id: Option<Option<Ulid>>,
    subject: Option<String>,
    human_account_name: Option<Option<String>>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.update", skip_all)]
pub async fn update_link(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleOutcome<UpstreamOAuthLink>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: UpdateRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(error.to_string()))?;

    let link = crate::services::user_admin::patch_upstream_oauth_link(
        &mut repo,
        &mut rng,
        &*clock,
        admin_user.as_ref(),
        id,
        coauth_data::UpstreamOAuthLinkPatch {
            user_id: body.user_id,
            subject: body.subject,
            human_account_name: body.human_account_name,
        },
    )
    .await
    .map_err(map_service_error)?;

    repo.save().await?;

    Ok(Json(SingleOutcome::new_canonical(to_upstream_oauth_link(
        link,
    ))))
}

fn map_service_error(error: crate::services::user_admin::UserAdminServiceError) -> AppError {
    match error {
        crate::services::user_admin::UserAdminServiceError::UpstreamOAuthLinkNotFound(id) => {
            AppError::not_found(format!("Upstream OAuth Link ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::ReferencedUserNotFound(id) => {
            AppError::bad_request(format!("Referenced user ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::ProviderNotFound(id) => {
            AppError::bad_request(format!("Provider ID {id} not found"))
        }
        crate::services::user_admin::UserAdminServiceError::UpstreamSubjectAlreadyLinked {
            provider_id,
            subject,
        } => AppError::conflict(format!(
            "Provider ID {provider_id} already has subject {subject}"
        )),
        crate::services::user_admin::UserAdminServiceError::Repository(error) => {
            AppError::internal(error)
        }
        crate::services::user_admin::UserAdminServiceError::UserNotFound(id) => {
            AppError::bad_request(format!("Unexpected user lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::UserEmailNotFound(id) => {
            AppError::bad_request(format!("Unexpected user email lookup failure for {id}"))
        }
        crate::services::user_admin::UserAdminServiceError::InvalidDisplayName => {
            AppError::bad_request("Invalid display name")
        }
        crate::services::user_admin::UserAdminServiceError::InvalidEmail { email, .. } => {
            AppError::bad_request(format!("Email {email:?} is not valid"))
        }
        crate::services::user_admin::UserAdminServiceError::EmailAlreadyInUse(email) => {
            AppError::conflict(format!("User email {email:?} already in use"))
        }
        crate::services::user_admin::UserAdminServiceError::PrincipalServer(error) => {
            AppError::internal(std::io::Error::other(error.to_string()))
        }
    }
}

#[cfg(test)]
mod test_utils {
    use coauth_data::upstream_oauth::UpstreamOAuthProviderParams;
    use coauth_data::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_oauth_types::scope::{OPENID, Scope};

    pub(crate) fn oidc_provider_params(name: &str) -> UpstreamOAuthProviderParams {
        UpstreamOAuthProviderParams {
            issuer: Some(format!("https://{name}.example.com")),
            human_name: Some(name.to_owned()),
            brand_name: Some(name.to_owned()),
            scope: Scope::from_iter([OPENID]),
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
            token_endpoint_signing_alg: None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            client_id: format!("client_{name}"),
            encrypted_client_secret: Some("secret".to_owned()),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::default(),
            pkce_mode: UpstreamOAuthProviderPkceMode::default(),
            response_mode: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            jwks_uri_override: None,
            additional_authorization_parameters: Vec::new(),
            forward_login_hint: false,
            ui_order: 0,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            source: coauth_data::UpstreamOAuthProviderSource::Config,
        }
    }
}

#[cfg(test)]
mod tests;
