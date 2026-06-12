// Generated code from schemars violates this rule
#![allow(clippy::str_to_string)]

use std::borrow::Cow;
use std::num::NonZeroUsize;

use coauth_data::pagination::PaginationDirection;
use salvo::http::StatusCode;
use salvo::prelude::*;
use schemars::JsonSchema;
use serde::Deserialize;
use ulid::Ulid;

use super::response::ErrorOutcome;

#[derive(Debug, thiserror::Error)]
#[error("Invalid ULID in path")]
pub struct UlidPathParamRejection(pub String);

impl Scribe for UlidPathParamRejection {
    fn render(self, res: &mut Response) {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ErrorOutcome::from_error(&self)));
    }
}

pub fn extract_ulid_param(req: &Request) -> Result<Ulid, UlidPathParamRejection> {
    let id_str: String = req
        .param::<String>("id")
        .ok_or_else(|| UlidPathParamRejection("Missing id parameter".to_owned()))?;
    id_str
        .parse::<Ulid>()
        .map_err(|e| UlidPathParamRejection(e.to_string()))
}

/// The default page size if not specified
const DEFAULT_PAGE_SIZE: usize = 10;

#[derive(Deserialize, JsonSchema, Clone, Copy, Default, Debug)]
pub enum IncludeCount {
    /// Include the total number of items (default)
    #[default]
    #[serde(rename = "true")]
    True,

    /// Do not include the total number of items
    #[serde(rename = "false")]
    False,

    /// Only include the total number of items, skip the items themselves
    #[serde(rename = "only")]
    Only,
}

impl IncludeCount {
    pub(crate) fn add_to_base(self, base: &str) -> Cow<'_, str> {
        let separator = if base.contains('?') { '&' } else { '?' };
        match self {
            // This is the default, don't add anything
            Self::True => Cow::Borrowed(base),
            Self::False => format!("{base}{separator}count=false").into(),
            Self::Only => format!("{base}{separator}count=only").into(),
        }
    }
}

#[derive(Deserialize, JsonSchema, Clone, Copy)]
struct PaginationParams {
    /// Retrieve the items before the given ID
    #[serde(rename = "page[before]")]
    #[schemars(with = "Option<super::schema::Ulid>")]
    before: Option<Ulid>,

    /// Retrieve the items after the given ID
    #[serde(rename = "page[after]")]
    #[schemars(with = "Option<super::schema::Ulid>")]
    after: Option<Ulid>,

    /// Retrieve the first N items
    #[serde(rename = "page[first]")]
    first: Option<NonZeroUsize>,

    /// Retrieve the last N items
    #[serde(rename = "page[last]")]
    last: Option<NonZeroUsize>,

    /// Include the total number of items. Defaults to `true`.
    #[serde(rename = "count")]
    include_count: Option<IncludeCount>,
}

#[derive(Debug, thiserror::Error)]
pub enum PaginationRejection {
    #[error("Invalid pagination parameters: {0}")]
    Invalid(String),

    #[error("Cannot specify both `page[first]` and `page[last]` parameters")]
    FirstAndLast,
}

impl Scribe for PaginationRejection {
    fn render(self, res: &mut Response) {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ErrorOutcome::from_error(&self)));
    }
}

pub fn extract_pagination(
    req: &mut Request,
) -> Result<(coauth_data::Pagination, IncludeCount), PaginationRejection> {
    let params: PaginationParams = req.parse_queries().unwrap_or(PaginationParams {
        before: None,
        after: None,
        first: None,
        last: None,
        include_count: None,
    });

    // Figure out the direction and the count out of the first and last parameters
    let (direction, count) = match (params.first, params.last) {
        // Make sure we don't specify both first and last
        (Some(_), Some(_)) => return Err(PaginationRejection::FirstAndLast),

        // Default to forward pagination with a default page size
        (None, None) => (PaginationDirection::Forward, DEFAULT_PAGE_SIZE),

        (Some(first), None) => (PaginationDirection::Forward, first.into()),
        (None, Some(last)) => (PaginationDirection::Backward, last.into()),
    };

    Ok((
        coauth_data::Pagination {
            before: params.before,
            after: params.after,
            direction,
            count,
        },
        params.include_count.unwrap_or_default(),
    ))
}
