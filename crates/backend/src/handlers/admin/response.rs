// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_name_repetitions)]

//! Server-side helpers around the JSON:API admin response envelopes.
//!
//! The wire-shape structs (`SingleResource`, `SingleResponse`,
//! `PaginatedResponse`, link/meta helpers) and the `Resource` trait now
//! live in `coauth_admin_types::envelope` so `sodmin` can deserialize
//! the same shape without reimplementing it. This module keeps only the
//! cursor-paginated builder (`PaginatedResponse::for_page`) plus the
//! error-response shape — both depend on `coauth_data` and therefore
//! cannot live in admin-types.

use coauth_admin_types::{PaginationLinks, Resource, SingleResource};
use coauth_data::{Pagination, pagination::Edge};
use salvo::oapi::ToSchema;
use schemars::JsonSchema;
use serde::Serialize;

pub use coauth_admin_types::{PaginatedResponse, SingleResponse};

fn url_with_pagination(base: &str, pagination: Pagination) -> String {
    let (path, query) = base.split_once('?').unwrap_or((base, ""));
    let mut query = query.to_owned();

    if let Some(before) = pagination.before {
        query = format!("{query}&page[before]={before}");
    }

    if let Some(after) = pagination.after {
        query = format!("{query}&page[after]={after}");
    }

    let count = pagination.count;
    match pagination.direction {
        coauth_data::pagination::PaginationDirection::Forward => {
            query = format!("{query}&page[first]={count}");
        }
        coauth_data::pagination::PaginationDirection::Backward => {
            query = format!("{query}&page[last]={count}");
        }
    }

    let query = query.trim_start_matches('&');
    format!("{path}?{query}")
}

/// Cursor-paginated builder. Mirrors the previous
/// `PaginatedResponse::for_page` inherent method but as a free function,
/// so the depend-on-`coauth_data` cursor logic stays out of admin-types.
pub fn paginated_response_for_page<T: Resource>(
    page: coauth_data::Page<T>,
    current_pagination: Pagination,
    count: Option<usize>,
    base: &str,
) -> PaginatedResponse<T> {
    let links = PaginationLinks {
        self_: url_with_pagination(base, current_pagination),
        first: Some(url_with_pagination(
            base,
            Pagination::first(current_pagination.count),
        )),
        last: Some(url_with_pagination(
            base,
            Pagination::last(current_pagination.count),
        )),
        next: page.has_next_page.then(|| {
            url_with_pagination(
                base,
                current_pagination
                    .clear_before()
                    .after(page.edges.last().unwrap().cursor),
            )
        }),
        prev: if page.has_previous_page {
            Some(url_with_pagination(
                base,
                current_pagination
                    .clear_after()
                    .before(page.edges.first().unwrap().cursor),
            ))
        } else {
            None
        },
    };

    let items = page
        .edges
        .into_iter()
        .map(|edge: Edge<T, _>| SingleResource::new_with_cursor(edge.node, edge.cursor.to_string()))
        .collect();

    PaginatedResponse::from_parts(items, count, links)
}

/// Count-only paginated response (no `data` array).
pub fn paginated_response_for_count_only<T>(count: usize, base: &str) -> PaginatedResponse<T> {
    PaginatedResponse::for_count_only(count, base.to_owned())
}

/// A single error
#[derive(Serialize, JsonSchema, ToSchema)]
struct Error {
    /// A human-readable title for the error
    title: String,
}

impl Error {
    fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        Self {
            title: error.to_string(),
        }
    }
}

/// A top-level response with a list of errors
#[derive(Serialize, JsonSchema, ToSchema)]
pub struct ErrorResponse {
    /// The list of errors
    errors: Vec<Error>,
}

impl ErrorResponse {
    /// Create a new error response from any Rust error
    pub fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        let mut errors = Vec::new();
        let mut head = Some(error);
        while let Some(error) = head {
            errors.push(Error::from_error(error));
            head = error.source();
        }
        Self { errors }
    }
}
