// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

//! Common schema definitions

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

/// A type to use for schema definitions of ULIDs
///
/// Use with `#[schemars(with = "crate::handlers::admin::schema::Ulid")]`
pub struct Ulid;

impl JsonSchema for Ulid {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ULID")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "title": "ULID",
            "description": "A ULID as per https://github.com/ulid/spec",
            "examples": [
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "01J41912SC8VGAQDD50F6APK91",
            ],
            "pattern": "^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$",
        })
    }
}
