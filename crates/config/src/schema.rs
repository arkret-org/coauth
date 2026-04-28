//! Reusable JSON Schema type helpers for configuration fields.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

/// Represents a valid network hostname in configuration schemas.
pub struct Hostname;

impl JsonSchema for Hostname {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Hostname")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "hostname",
        })
    }
}
