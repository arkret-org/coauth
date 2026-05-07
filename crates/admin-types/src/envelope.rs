//! JSON:API-shaped envelopes used by every admin endpoint.
//!
//! These types describe the wire shape of `data` / `links` / `meta`
//! that the backend writes and `sodmin` reads. Migrated out of
//! `coauth/crates/backend/src/handlers/admin/response.rs` so a typed
//! Rust struct backs the wire on both sides instead of a hand-mirrored
//! one.
//!
//! Server-side helpers that need `coauth_data::Page` (e.g. cursor-paginated
//! `for_page` builder) stay in `coauth-backend`; what lives here is the
//! pure data shape plus the lightweight `Resource` trait so generic
//! `new_canonical` / `from_parts` builders work without depending on the
//! cursor implementation.

use serde::{Deserialize, Serialize};

/// A resource that can be addressed by stable kind + id and has a canonical
/// URL path.
///
/// Implemented on every type that lives inside the `attributes` slot of a
/// [`SingleResource`]. The default `path()` impl is `"{PATH}/{id}"`; types
/// with non-standard URL shapes override it.
pub trait Resource {
    /// The JSON:API `type` discriminator. Stable per resource kind.
    const KIND: &'static str;

    /// The collection-base path for this resource kind.
    const PATH: &'static str;

    /// Stable id of the resource as a string. Backend types typically
    /// hold this as a `Ulid` and convert via `.to_string()`.
    fn id(&self) -> String;

    /// Canonical URL path for one instance of this resource. Default is
    /// `{PATH}/{id}`. Overridden by resources with nested or non-standard
    /// path shapes.
    fn path(&self) -> String {
        format!("{}/{}", Self::PATH, self.id())
    }
}

/// Self-link block — `{ "self": "..." }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct SelfLinks {
    #[serde(rename = "self", default)]
    pub self_: String,
}

/// Pagination link block — `{ "self", "first", "last", "next", "prev" }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct PaginationLinks {
    #[serde(rename = "self", default)]
    pub self_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
}

/// Pagination meta — `{ "count": ... }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct PaginationMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
}

impl PaginationMeta {
    pub fn is_empty(&self) -> bool {
        self.count.is_none()
    }
}

/// Per-resource cursor metadata — `{ "page": { "cursor": "..." } }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct SingleResourceMetaPage {
    #[serde(default)]
    pub cursor: String,
}

/// Per-resource meta block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema, salvo::oapi::ToSchema)
)]
pub struct SingleResourceMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<SingleResourceMetaPage>,
}

impl SingleResourceMeta {
    pub fn is_empty(&self) -> bool {
        self.page.is_none()
    }
}

/// One JSON:API resource — `{ "type", "id", "attributes", "links", "meta" }`.
///
/// Generic over the inner attributes type. The backend sets `type_` from
/// `T::KIND` when constructing, sodmin trusts what the wire emits.
///
/// Schema derives (JsonSchema / ToSchema) are intentionally NOT on the
/// generic envelope types — auto-deriving them imposes `T: 'static`,
/// `T: Default`, and the equivalent schema bounds on every concrete `T`,
/// which we don't want here. Backend installs minimal hand-written
/// schema impls when the `schema` feature is on (see below).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize",
    deserialize = "T: Default + serde::Deserialize<'de>"
))]
pub struct SingleResource<T> {
    #[serde(rename = "type", default)]
    pub type_: String,

    #[serde(default)]
    pub id: String,

    #[serde(default)]
    pub attributes: T,

    #[serde(default)]
    pub links: SelfLinks,

    #[serde(default, skip_serializing_if = "SingleResourceMeta::is_empty")]
    pub meta: SingleResourceMeta,
}

impl<T> SingleResource<T>
where
    T: Resource,
{
    /// Build a single-resource wrapper with `type` and `links.self` taken
    /// from `T`'s `Resource` impl.
    pub fn new(resource: T) -> Self {
        let path = resource.path();
        Self {
            type_: T::KIND.to_owned(),
            id: resource.id(),
            attributes: resource,
            links: SelfLinks { self_: path },
            meta: SingleResourceMeta { page: None },
        }
    }

    /// Same as [`new`](Self::new) but tags the resource with a paginated
    /// cursor (used by `paginated_for_page` to associate each item with
    /// its page cursor).
    pub fn new_with_cursor(resource: T, cursor: String) -> Self {
        let mut wrapper = Self::new(resource);
        wrapper.meta = SingleResourceMeta {
            page: Some(SingleResourceMetaPage { cursor }),
        };
        wrapper
    }
}

/// Top-level envelope for a single-resource response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize",
    deserialize = "T: Default + serde::Deserialize<'de>"
))]
pub struct SingleResponse<T> {
    pub data: SingleResource<T>,
    pub links: SelfLinks,
}

impl<T> SingleResponse<T>
where
    T: Resource,
{
    /// Wrap a resource with an explicit `links.self` URL.
    pub fn new(resource: T, self_link: String) -> Self {
        Self {
            data: SingleResource::new(resource),
            links: SelfLinks { self_: self_link },
        }
    }

    /// Wrap a resource using its canonical path as `links.self`.
    pub fn new_canonical(resource: T) -> Self {
        let path = resource.path();
        Self::new(resource, path)
    }
}

/// Top-level envelope for a paginated list response.
///
/// `data` is `Option` so a count-only response (`?count=true`) can omit
/// it without changing the type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize",
    deserialize = "T: Default + serde::Deserialize<'de>"
))]
pub struct PaginatedResponse<T> {
    #[serde(default, skip_serializing_if = "PaginationMeta::is_empty")]
    pub meta: PaginationMeta,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<SingleResource<T>>>,

    #[serde(default)]
    pub links: PaginationLinks,
}

impl<T> PaginatedResponse<T> {
    /// Build a count-only response (no `data` array).
    pub fn for_count_only(count: usize, self_link: String) -> Self {
        Self {
            meta: PaginationMeta { count: Some(count) },
            data: None,
            links: PaginationLinks {
                self_: self_link,
                ..PaginationLinks::default()
            },
        }
    }

    /// Build a paginated response from already-wrapped resources and
    /// pre-computed link strings. Backend's cursor-paginated `for_page`
    /// helper extracts the cursors and links and calls this.
    pub fn from_parts(
        items: Vec<SingleResource<T>>,
        count: Option<usize>,
        links: PaginationLinks,
    ) -> Self {
        Self {
            meta: PaginationMeta { count },
            data: Some(items),
            links,
        }
    }
}

// Hand-written schema impls for the generic envelope types so backend's
// `#[salvo::endpoint]` can populate the OpenAPI document without forcing
// `T: ToSchema + JsonSchema + 'static + Default` on every concrete `T`.
// These intentionally describe the wrapper shape only and leave the
// inner `attributes` slot as a generic object — same trade-off the
// backend made before this crate existed.
#[cfg(feature = "schema")]
mod schema_impls {
    use std::borrow::Cow;

    use super::{PaginatedResponse, SingleResponse};

    impl<T> schemars::JsonSchema for PaginatedResponse<T> {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("PaginatedResponse")
        }

        fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
            // Wrapper-only schema; the `attributes` slot is left untyped
            // because we don't want to force `T: JsonSchema` on every
            // concrete inner type.
            schemars::json_schema!({
                "type": "object",
                "properties": {
                    "meta": {
                        "type": "object",
                        "properties": { "count": { "type": "integer" } }
                    },
                    "data": {
                        "type": "object",
                        "properties": {
                            "type": { "type": "string" },
                            "id": { "type": "string" },
                            "attributes": { "type": "object" }
                        }
                    },
                    "links": {
                        "type": "object",
                        "properties": {
                            "self": { "type": "string" },
                            "first": { "type": "string" },
                            "last": { "type": "string" },
                            "next": { "type": "string" },
                            "prev": { "type": "string" }
                        }
                    }
                },
                "required": ["links"]
            })
        }
    }

    impl<T> schemars::JsonSchema for SingleResponse<T> {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("SingleResponse")
        }

        fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
            schemars::json_schema!({
                "type": "object",
                "properties": {
                    "data": {
                        "type": "object",
                        "properties": {
                            "type": { "type": "string" },
                            "id": { "type": "string" },
                            "attributes": { "type": "object" }
                        }
                    },
                    "links": {
                        "type": "object",
                        "properties": { "self": { "type": "string" } }
                    }
                },
                "required": ["data", "links"]
            })
        }
    }

    impl<T: 'static> salvo::oapi::ToSchema for PaginatedResponse<T> {
        fn to_schema(
            _components: &mut salvo::oapi::Components,
        ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
            use salvo::oapi::*;
            Object::new()
                .property(
                    "meta",
                    Object::new()
                        .property("count", Object::new().schema_type(BasicType::Integer)),
                )
                .property(
                    "data",
                    Object::new()
                        .property("type", Object::new().schema_type(BasicType::String))
                        .property("id", Object::new().schema_type(BasicType::String))
                        .property("attributes", Object::new()),
                )
                .property(
                    "links",
                    Object::new()
                        .property("self", Object::new().schema_type(BasicType::String))
                        .property("first", Object::new().schema_type(BasicType::String))
                        .property("last", Object::new().schema_type(BasicType::String))
                        .property("next", Object::new().schema_type(BasicType::String))
                        .property("prev", Object::new().schema_type(BasicType::String)),
                )
                .required("links")
                .into()
        }
    }

    impl<T: 'static> salvo::oapi::ToSchema for SingleResponse<T> {
        fn to_schema(
            _components: &mut salvo::oapi::Components,
        ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
            use salvo::oapi::*;
            Object::new()
                .property(
                    "data",
                    Object::new()
                        .property("type", Object::new().schema_type(BasicType::String))
                        .property("id", Object::new().schema_type(BasicType::String))
                        .property("attributes", Object::new()),
                )
                .property(
                    "links",
                    Object::new()
                        .property("self", Object::new().schema_type(BasicType::String)),
                )
                .required("data")
                .required("links")
                .into()
        }
    }
}
