// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Read endpoints: `GET /users`, `GET /users/{id}`, `GET
//! /users/by-username/{username}`.

use coauth_data::user::UserFilter;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    AppError, JsonResult,
    handlers::admin::{
        call_context::extract_call_context,
        model::{Resource, User},
        params::{IncludeCount, extract_pagination, extract_ulid_param},
        response::{
            PaginatedResponse, SingleResponse, paginated_response_for_count_only,
            paginated_response_for_page,
        },
    },
};

#[derive(Deserialize, JsonSchema)]
pub struct UsernamePathParam {
    /// The username (username) of the user to get
    #[allow(dead_code)]
    username: String,
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.by_username", skip_all)]
pub async fn get_by_username(req: &mut Request, depot: &Depot) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let username: String = req
        .param::<String>("username")
        .ok_or_else(|| AppError::not_found(r#"User with username "unknown" not found"#))?;

    let self_path = format!("/api/admin/v1/users/by-username/{username}");
    let user = repo
        .user()
        .find_by_handle(&username)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User with username {username:?} not found")))?;

    Ok(Json(SingleResponse::new(User::from(user), self_path)))
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.get", skip_all)]
pub async fn get_user(req: &mut Request, depot: &Depot) -> JsonResult<SingleResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let id = extract_ulid_param(req)?;

    let user = repo
        .user()
        .lookup(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User ID {id} not found")))?;

    Ok(Json(SingleResponse::new_canonical(User::from(user))))
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum UserStatus {
    Active,
    Locked,
    Deactivated,
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Locked => write!(f, "locked"),
            Self::Deactivated => write!(f, "deactivated"),
        }
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(rename = "UserFilter")]
pub struct FilterParams {
    /// Retrieve users with (or without) the `admin` flag set
    #[serde(rename = "filter[admin]")]
    admin: Option<bool>,

    /// Retrieve users with (or without) the `legacy_guest` flag set
    #[serde(rename = "filter[legacy-guest]")]
    legacy_guest: Option<bool>,

    /// Retrieve users where the username matches contains the given string
    ///
    /// Note that this doesn't change the ordering of the result, which are
    /// still ordered by ID.
    #[serde(rename = "filter[search]")]
    search: Option<String>,

    /// Retrieve the items with the given status
    ///
    /// Defaults to retrieve all users, including locked ones.
    ///
    /// * `active`: Only retrieve active users
    ///
    /// * `locked`: Only retrieve locked users (includes deactivated users)
    ///
    /// * `deactivated`: Only retrieve deactivated users
    #[serde(rename = "filter[status]")]
    status: Option<UserStatus>,
}

impl std::fmt::Display for FilterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sep = '?';

        if let Some(admin) = self.admin {
            write!(f, "{sep}filter[admin]={admin}")?;
            sep = '&';
        }
        if let Some(legacy_guest) = self.legacy_guest {
            write!(f, "{sep}filter[legacy-guest]={legacy_guest}")?;
            sep = '&';
        }
        if let Some(search) = &self.search {
            write!(f, "{sep}filter[search]={search}")?;
            sep = '&';
        }
        if let Some(status) = self.status {
            write!(f, "{sep}filter[status]={status}")?;
            sep = '&';
        }

        let _ = sep;
        Ok(())
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.admin.v1.users.list", skip_all)]
pub async fn list_users(req: &mut Request, depot: &Depot) -> JsonResult<PaginatedResponse<User>> {
    let call_context = extract_call_context(req, depot).await?;
    let crate::handlers::admin::call_context::CallContext { mut repo, .. } = call_context;
    let (pagination, include_count) = extract_pagination(req)?;
    let params: FilterParams = req.parse_queries().unwrap_or_default();

    let base = format!("{path}{params}", path = User::PATH);
    let base = include_count.add_to_base(&base);
    let filter = UserFilter::default();

    let filter = match params.admin {
        Some(true) => filter.can_request_admin_only(),
        Some(false) => filter.cannot_request_admin_only(),
        None => filter,
    };

    let filter = match params.legacy_guest {
        Some(true) => filter.guest_only(),
        Some(false) => filter.non_guest_only(),
        None => filter,
    };

    let filter = match params.search.as_deref() {
        Some(search) => filter.matching_search(search),
        None => filter,
    };

    let filter = match params.status {
        Some(UserStatus::Active) => filter.active_only(),
        Some(UserStatus::Locked) => filter.locked_only(),
        Some(UserStatus::Deactivated) => filter.deactivated_only(),
        None => filter,
    };

    let response = match include_count {
        IncludeCount::True => {
            let page = repo.user().list(filter, pagination).await?;
            let count = repo.user().count(filter).await?;
            paginated_response_for_page(page.map(User::from), pagination, Some(count), &base)
        }
        IncludeCount::False => {
            let page = repo.user().list(filter, pagination).await?;
            paginated_response_for_page(page.map(User::from), pagination, None, &base)
        }
        IncludeCount::Only => {
            let count = repo.user().count(filter).await?;
            paginated_response_for_count_only(count, &base)
        }
    };

    Ok(Json(response))
}
