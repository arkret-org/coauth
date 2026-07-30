// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_name_repetitions)]

//! Server-side helpers around the JSON:API admin response envelopes.
//!
//! The wire-shape structs (`SingleResource`, `SingleOutcome`,
//! `PaginatedOutcome`, link/meta helpers) and the `Resource` trait now
//! live in `coauth_admin_types::envelope` so `sodmin` can deserialize
//! the same shape without reimplementing it. This module keeps only the
//! cursor-paginated builder (`PaginatedOutcome::for_page`) plus the
//! error-response shape — both depend on `coauth_data` and therefore
//! cannot live in admin-types.

pub use coauth_admin_types::{PaginatedOutcome, SingleOutcome};
use coauth_admin_types::{PaginationLinks, Resource, SingleResource};
use coauth_data::Pagination;
use coauth_data::pagination::Edge;
use salvo::oapi::ToSchema;
use schemars::JsonSchema;
use serde::Serialize;

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
/// `PaginatedOutcome::for_page` inherent method but as a free function,
/// so the depend-on-`coauth_data` cursor logic stays out of admin-types.
pub fn paginated_response_for_page<T: Resource>(
    page: coauth_data::Page<T>,
    current_pagination: Pagination,
    count: Option<usize>,
    base: &str,
) -> PaginatedOutcome<T> {
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
        next: if page.has_next_page {
            page.edges.last().map(|edge| {
                url_with_pagination(base, current_pagination.clear_before().after(edge.cursor))
            })
        } else {
            None
        },
        prev: if page.has_previous_page {
            page.edges.first().map(|edge| {
                url_with_pagination(base, current_pagination.clear_after().before(edge.cursor))
            })
        } else {
            None
        },
    };

    let items = page
        .edges
        .into_iter()
        .map(|edge: Edge<T, _>| SingleResource::new_with_cursor(edge.node, edge.cursor.to_string()))
        .collect();

    PaginatedOutcome::from_parts(items, count, links)
}

/// Count-only paginated response (no `data` array).
pub fn paginated_response_for_count_only<T>(count: usize, base: &str) -> PaginatedOutcome<T> {
    PaginatedOutcome::for_count_only(count, base.to_owned())
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
pub struct ErrorOutcome {
    /// The list of errors
    errors: Vec<Error>,
}

impl ErrorOutcome {
    /// Create a client-safe error response from any Rust error.
    ///
    /// Error sources frequently contain database statements, filesystem paths
    /// or upstream response bodies. They belong in structured server logs, not
    /// in the public JSON:API response, so only the top-level message crosses
    /// the HTTP trust boundary.
    pub fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        Self {
            errors: vec![Error::from_error(error)],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::fmt;

    use super::*;

    #[derive(Debug)]
    struct TestResource;

    impl Resource for TestResource {
        const KIND: &'static str = "test";
        const PATH: &'static str = "/test";

        fn id(&self) -> String {
            "test".to_owned()
        }
    }

    #[derive(Debug)]
    struct Inner;

    impl fmt::Display for Inner {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sensitive database detail")
        }
    }

    impl std::error::Error for Inner {}

    #[derive(Debug)]
    struct Outer(Inner);

    impl fmt::Display for Outer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("public rejection")
        }
    }

    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn error_outcome_does_not_serialize_source_chain() {
        let error = Outer(Inner);
        assert!(error.source().is_some());

        let json = serde_json::to_value(ErrorOutcome::from_error(&error)).unwrap();
        let errors = json["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0]["title"], "public rejection");
        assert!(!json.to_string().contains("sensitive database detail"));
    }

    #[test]
    fn empty_page_with_direction_flags_has_no_cursor_links() {
        let page = coauth_data::Page {
            edges: Vec::<Edge<TestResource>>::new(),
            has_previous_page: true,
            has_next_page: true,
        };

        let outcome = paginated_response_for_page(page, Pagination::first(0), None, "/admin/test");

        assert!(outcome.links.next.is_none());
        assert!(outcome.links.prev.is_none());
    }
}
