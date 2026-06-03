// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use coauth_data::{
    RepositoryAccess, audit::AdminOperation, upstream_oauth::UpstreamOAuthLinkFilter,
};
use salvo::{http::StatusCode, prelude::*};
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use crate::{
    AppError, AppResult, CreatedJsonResult, JsonResult,
    handlers::admin::{
        call_context::extract_call_context,
        model::{Resource, UpstreamOAuthLink},
        params::{IncludeCount, extract_pagination, extract_ulid_param},
        response::{
            PaginatedResponse, SingleResponse, paginated_response_for_count_only,
            paginated_response_for_page,
        },
    },
};

#[cfg(test)]
mod test_utils {
    use coauth_data::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderTokenAuthMethod, upstream_oauth::UpstreamOAuthProviderParams,
    };
    use coauth_iana::jose::JsonWebSignatureAlg;
    use oauth_types::scope::{OPENID, Scope};

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

/// JSON body accepted by `POST /_cokret/local/admin/upstream-oauth-links`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUpstreamOauthLinkRequest")]
pub struct AddRequest {
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
) -> CreatedJsonResult<SingleResponse<UpstreamOAuthLink>> {
    let ctx = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = ctx;
    let mut rng = crate::handlers::account::make_rng();
    let body: AddRequest = req.parse_json().await.map_err(AppError::internal)?;

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
                "Upstream Oauth 2.0 Provider ID {} with subject {} is already linked to a user",
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
            SingleResponse::new_canonical(entry.into()),
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
        SingleResponse::new_canonical(entry.into()),
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
) -> JsonResult<SingleResponse<UpstreamOAuthLink>> {
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

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthLink::from(entry),
    )))
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
) -> JsonResult<PaginatedResponse<UpstreamOAuthLink>> {
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
                .map(UpstreamOAuthLink::from);
            let total = repo.upstream_oauth_link().count(filter).await?;
            paginated_response_for_page(page, pagination, Some(total), &base_url)
        }
        IncludeCount::False => {
            let page = repo
                .upstream_oauth_link()
                .list(filter, pagination)
                .await?
                .map(UpstreamOAuthLink::from);
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
pub struct UpdateRequest {
    user_id: Option<Option<Ulid>>,
    subject: Option<String>,
    human_account_name: Option<Option<String>>,
}
#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.upstream_oauth_links.update", skip_all)]
pub async fn update_link(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<SingleResponse<UpstreamOAuthLink>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext {
        mut repo,
        clock,
        user: admin_user,
        ..
    } = call_context;
    let id = extract_ulid_param(req)?;
    let mut rng = crate::handlers::account::make_rng();
    let body: UpdateRequest = req
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

    Ok(Json(SingleResponse::new_canonical(
        UpstreamOAuthLink::from(link),
    )))
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
mod tests {
    use chrono::Duration;
    use coauth_data::{
        RepositoryAccess, UpstreamOAuthAuthorizationSessionState,
        upstream_oauth::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
        user::UserRepository,
    };
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use ulid::Ulid;

    use super::test_utils;
    use crate::handlers::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, setup, unique_test_nonce,
    };

    #[tokio::test]
    async fn test_create() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/_cokret/local/admin/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG07HNEZXNQM2KNBNF6",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "subject": "subject1",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_account_name": null
            },
            "links": {
              "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG07HNEZXNQM2KNBNF6"
            }
          },
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG07HNEZXNQM2KNBNF6"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_association() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        // Existing unfinished link
        repo.upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/_cokret/local/admin/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG09NMZYX8MFYH578R9",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "subject": "subject1",
              "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "human_account_name": null
            },
            "links": {
              "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
            }
          },
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_link_already_exists() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&link, &alice)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/_cokret/local/admin/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": bob.id,
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Upstream Oauth 2.0 Provider ID 01FSHN9AG09NMZYX8MFYH578R9 with subject subject1 is already linked to a user"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_user_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/_cokret/local/admin/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": Ulid::nil(),
                "provider_id": provider.id,
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "User ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_provider_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::post("/_cokret/local/admin/upstream-oauth-links")
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": alice.id,
                "provider_id": Ulid::nil(),
                "subject": "subject1"
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "errors": [
            {
              "title": "Upstream OAuth Provider ID 00000000000000000000000000 not found"
            }
          ]
        }
        "###);
    }

    #[tokio::test]
    async fn test_delete() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();

        // Pretend it was linked by an authorization session
        let session = repo
            .upstream_oauth_session()
            .add(&mut rng, &state.clock, &provider, String::new(), None, None)
            .await
            .unwrap();

        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                String::from("subject1"),
                None,
            )
            .await
            .unwrap();

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(&state.clock, session, &link, None, None, None, None)
            .await
            .unwrap();

        repo.upstream_oauth_link()
            .associate_to_user(&link, &alice)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::delete(format!("/_cokret/local/admin/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NO_CONTENT);

        // Verify that the link was deleted
        let request = Request::get(format!("/_cokret/local/admin/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);

        // Verify that the session was marked as unlinked
        let mut repo = state.repository().await.unwrap();
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            session.state,
            UpstreamOAuthAuthorizationSessionState::Unlinked { .. }
        ));
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let link_id = Ulid::nil();
        let request = Request::delete(format!("/_cokret/local/admin/upstream-oauth-links/{link_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision a provider and a link
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("provider1"),
            )
            .await
            .unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject1".to_owned(),
                None,
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let link_id = link.id;
        let request = Request::get(format!("/_cokret/local/admin/upstream-oauth-links/{link_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "data": {
            "type": "upstream-oauth-link",
            "id": "01FSHN9AG09NMZYX8MFYH578R9",
            "attributes": {
              "created_at": "2022-01-16T14:40:00Z",
              "provider_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
              "subject": "subject1",
              "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
              "human_account_name": null
            },
            "links": {
              "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
            }
          },
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG09NMZYX8MFYH578R9"
          }
        }
        "###);
    }

    #[tokio::test]
    async fn test_get_not_found() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;

        let link_id = Ulid::nil();
        let request = Request::get(format!("/_cokret/local/admin/upstream-oauth-links/{link_id}"))
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = state.rng();

        // Provision users and providers
        let mut repo = state.repository().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let bob = repo
            .user()
            .add(&mut rng, &state.clock, "bob".to_owned())
            .await
            .unwrap();
        let provider1 = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("acme"),
            )
            .await
            .unwrap();
        let provider2 = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params("example"),
            )
            .await
            .unwrap();

        // Create some links
        let link1 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider1,
                "subject1".to_owned(),
                Some("alice@acme".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link1, &alice)
            .await
            .unwrap();
        let link2 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider2,
                "subject2".to_owned(),
                Some("alice@example".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link2, &alice)
            .await
            .unwrap();
        let link3 = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider1,
                "subject3".to_owned(),
                Some("bob@acme".to_owned()),
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&link3, &bob)
            .await
            .unwrap();

        repo.save().await.unwrap();

        let request = Request::get("/_cokret/local/admin/upstream-oauth-links")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 3
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?page[first]=10",
            "first": "/_cokret/local/admin/upstream-oauth-links?page[first]=10",
            "last": "/_cokret/local/admin/upstream-oauth-links?page[last]=10"
          }
        }
        "#);

        // Filter by user ID
        let request = Request::get(format!(
            "/_cokret/local/admin/upstream-oauth-links?filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "first": "/_cokret/local/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[first]=10",
            "last": "/_cokret/local/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&page[last]=10"
          }
        }
        "#);

        // Filter by provider
        let request = Request::get(format!(
            "/_cokret/local/admin/upstream-oauth-links?filter[provider]={}",
            provider1.id
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "first": "/_cokret/local/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[first]=10",
            "last": "/_cokret/local/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&page[last]=10"
          }
        }
        "#);

        // Filter by subject
        let request = Request::get(format!(
            "/_cokret/local/admin/upstream-oauth-links?filter[subject]={}",
            "subject1"
        ))
        .bearer(&token)
        .empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 1
          },
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "first": "/_cokret/local/admin/upstream-oauth-links?filter[subject]=subject1&page[first]=10",
            "last": "/_cokret/local/admin/upstream-oauth-links?filter[subject]=subject1&page[last]=10"
          }
        }
        "#);

        // Test count=false
        let request = Request::get("/_cokret/local/admin/upstream-oauth-links?count=false")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0PJZ6DZNTAA1XKPT4",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject3",
                "user_id": "01FSHN9AG0AJ6AC5HQ9X6H4RP4",
                "human_account_name": "bob@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0PJZ6DZNTAA1XKPT4"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0PJZ6DZNTAA1XKPT4"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?count=false&page[first]=10",
            "first": "/_cokret/local/admin/upstream-oauth-links?count=false&page[first]=10",
            "last": "/_cokret/local/admin/upstream-oauth-links?count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only
        let request = Request::get("/_cokret/local/admin/upstream-oauth-links?count=only")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r###"
        {
          "meta": {
            "count": 3
          },
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?count=only"
          }
        }
        "###);

        // Test count=false with filtering
        let request = Request::get(format!(
            "/_cokret/local/admin/upstream-oauth-links?count=false&filter[user]={}",
            alice.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "data": [
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0AQZQP8DX40GD59PW",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG09NMZYX8MFYH578R9",
                "subject": "subject1",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@acme"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0AQZQP8DX40GD59PW"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0AQZQP8DX40GD59PW"
                }
              }
            },
            {
              "type": "upstream-oauth-link",
              "id": "01FSHN9AG0QHEHKX2JNQ2A2D07",
              "attributes": {
                "created_at": "2022-01-16T14:40:00Z",
                "provider_id": "01FSHN9AG0KEPHYQQXW9XPTX6Z",
                "subject": "subject2",
                "user_id": "01FSHN9AG0MZAA6S4AF7CTV32E",
                "human_account_name": "alice@example"
              },
              "links": {
                "self": "/_cokret/local/admin/upstream-oauth-links/01FSHN9AG0QHEHKX2JNQ2A2D07"
              },
              "meta": {
                "page": {
                  "cursor": "01FSHN9AG0QHEHKX2JNQ2A2D07"
                }
              }
            }
          ],
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "first": "/_cokret/local/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[first]=10",
            "last": "/_cokret/local/admin/upstream-oauth-links?filter[user]=01FSHN9AG0MZAA6S4AF7CTV32E&count=false&page[last]=10"
          }
        }
        "#);

        // Test count=only with filtering
        let request = Request::get(format!(
            "/_cokret/local/admin/upstream-oauth-links?count=only&filter[provider]={}",
            provider1.id
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_json_snapshot!(body, @r#"
        {
          "meta": {
            "count": 2
          },
          "links": {
            "self": "/_cokret/local/admin/upstream-oauth-links?filter[provider]=01FSHN9AG09NMZYX8MFYH578R9&count=only"
          }
        }
        "#);
    }

    #[tokio::test]
    async fn test_patch_upstream_oauth_link_updates_subject_user_and_name() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let suffix = Ulid::new().to_string().to_lowercase();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, format!("alice{suffix}"))
            .await
            .unwrap();
        let bob = repo
            .user()
            .add(&mut rng, &state.clock, format!("bob{suffix}"))
            .await
            .unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params(&format!("provider-{suffix}")),
            )
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                format!("subject-{suffix}-1"),
                Some("Alice Provider".to_owned()),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/_cokret/local/admin/upstream-oauth-links/{}", link.id))
            .bearer(&token)
            .json(serde_json::json!({
                "user_id": bob.id,
                "subject": format!("subject-{suffix}-2"),
                "human_account_name": "Bob Provider"
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["subject"],
            format!("subject-{suffix}-2")
        );
        assert_eq!(body["data"]["attributes"]["user_id"], bob.id.to_string());
        assert_eq!(
            body["data"]["attributes"]["human_account_name"],
            "Bob Provider"
        );

        let mut repo = state.repository().await.unwrap();
        let updated = repo
            .upstream_oauth_link()
            .lookup(link.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.user_id, Some(bob.id));
        assert_eq!(updated.subject, format!("subject-{suffix}-2"));
        assert_eq!(updated.human_account_name.as_deref(), Some("Bob Provider"));

        let _ = alice;
    }

    #[tokio::test]
    async fn test_patch_upstream_oauth_link_rejects_duplicate_subject() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let mut state = TestState::from_pool(pool.clone()).await.unwrap();
        let unique = unique_test_nonce();
        state.clock.advance(Duration::seconds(unique as i64));
        let token = state.token_with_scope("urn:coauth:admin").await;
        let mut rng = ChaChaRng::seed_from_u64(unique);
        let mut repo = state.repository().await.unwrap();
        let suffix = Ulid::new().to_string().to_lowercase();

        let alice = repo
            .user()
            .add(&mut rng, &state.clock, format!("alice{suffix}"))
            .await
            .unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                test_utils::oidc_provider_params(&format!("provider-{suffix}")),
            )
            .await
            .unwrap();
        let first = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                format!("subject-{suffix}-1"),
                None,
            )
            .await
            .unwrap();
        let second = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                format!("subject-{suffix}-2"),
                None,
            )
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&first, &alice)
            .await
            .unwrap();
        repo.upstream_oauth_link()
            .associate_to_user(&second, &alice)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::patch(format!("/_cokret/local/admin/upstream-oauth-links/{}", second.id))
            .bearer(&token)
            .json(serde_json::json!({
                "subject": format!("subject-{suffix}-1")
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
    }
}
