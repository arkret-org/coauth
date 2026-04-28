// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Rust source code generation from IANA registry entries.
//!
//! Each public function emits one piece of the generated enum:
//! the type definition, trait implementations, or schema helpers.

use crate::traits::{EnumMember, Section};

/// Emit the `pub enum` definition with doc-comments and optional `#[non_exhaustive]`.
pub fn struct_def(
    out: &mut std::fmt::Formatter<'_>,
    section: &Section,
    members: &[EnumMember],
    exhaustive: bool,
) -> std::fmt::Result {
    // Doc header
    writeln!(out)?;
    writeln!(out, "/// {}", section.doc)?;
    if let Some(url) = section.url {
        writeln!(out, "///")?;
        writeln!(out, "/// Source: <{url}>")?;
    }
    writeln!(out, "#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]")?;
    if !exhaustive {
        writeln!(out, "#[non_exhaustive]")?;
    }
    writeln!(out, "pub enum {} {{", section.key)?;

    for m in members {
        let doc = m.description.as_deref().unwrap_or(&m.value);
        writeln!(out, "    /// {doc}")?;
        writeln!(out, "    {},", m.enum_name)?;
    }

    if !exhaustive {
        writeln!(out)?;
        writeln!(out, "    /// An unknown value.")?;
        writeln!(out, "    Unknown(String),")?;
    }

    writeln!(out, "}}")
}

/// Emit `impl Display`.
pub fn display_impl(
    out: &mut std::fmt::Formatter<'_>,
    section: &Section,
    members: &[EnumMember],
    exhaustive: bool,
) -> std::fmt::Result {
    writeln!(out, "impl core::fmt::Display for {} {{", section.key)?;
    writeln!(out, "    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {{")?;
    writeln!(out, "        match self {{")?;

    for m in members {
        writeln!(out, r#"            Self::{} => f.write_str("{}"),"#, m.enum_name, m.value)?;
    }
    if !exhaustive {
        writeln!(out, "            Self::Unknown(v) => f.write_str(v),")?;
    }

    writeln!(out, "        }}")?;
    writeln!(out, "    }}")?;
    writeln!(out, "}}")
}

/// Emit `impl FromStr`.
pub fn from_str_impl(
    out: &mut std::fmt::Formatter<'_>,
    section: &Section,
    members: &[EnumMember],
    exhaustive: bool,
) -> std::fmt::Result {
    let err_type = if exhaustive {
        "crate::ParseError"
    } else {
        "core::convert::Infallible"
    };

    writeln!(out, "impl core::str::FromStr for {} {{", section.key)?;
    writeln!(out, "    type Err = {err_type};")?;
    writeln!(out)?;
    writeln!(out, "    fn from_str(s: &str) -> Result<Self, Self::Err> {{")?;
    writeln!(out, "        match s {{")?;

    for m in members {
        writeln!(out, r#"            "{}" => Ok(Self::{}),"#, m.value, m.enum_name)?;
    }

    if exhaustive {
        writeln!(out, "            _ => Err(crate::ParseError::new()),")?;
    } else {
        writeln!(out, "            other => Ok(Self::Unknown(other.to_owned())),")?;
    }

    writeln!(out, "        }}")?;
    writeln!(out, "    }}")?;
    writeln!(out, "}}")
}

/// Emit `impl Serialize` and `impl Deserialize` via the string representation.
pub fn serde_impl(
    out: &mut std::fmt::Formatter<'_>,
    section: &Section,
) -> std::fmt::Result {
    let name = section.key;

    // Deserialize: parse from string
    writeln!(out, "impl<'de> serde::Deserialize<'de> for {name} {{")?;
    writeln!(out, "    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>")?;
    writeln!(out, "    where")?;
    writeln!(out, "        D: serde::de::Deserializer<'de>,")?;
    writeln!(out, "    {{")?;
    writeln!(out, "        let s = String::deserialize(deserializer)?;")?;
    writeln!(out, "        core::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)")?;
    writeln!(out, "    }}")?;
    writeln!(out, "}}")?;
    writeln!(out)?;

    // Serialize: write as string
    writeln!(out, "impl serde::Serialize for {name} {{")?;
    writeln!(out, "    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>")?;
    writeln!(out, "    where")?;
    writeln!(out, "        S: serde::ser::Serializer,")?;
    writeln!(out, "    {{")?;
    writeln!(out, "        serializer.serialize_str(&self.to_string())")?;
    writeln!(out, "    }}")?;
    writeln!(out, "}}")
}

/// Helper: produce a Rust raw-string literal for a value that may contain quotes.
fn raw_str_literal(s: &str) -> String {
    if s.contains('"') {
        format!(r##"r#"{s}"#"##)
    } else {
        format!(r#"r"{s}""#)
    }
}

/// Emit `impl JsonSchema` using `schemars`.
pub fn json_schema_impl(
    out: &mut std::fmt::Formatter<'_>,
    section: &Section,
    members: &[EnumMember],
) -> std::fmt::Result {
    let name = section.key;

    writeln!(out, "impl schemars::JsonSchema for {name} {{")?;
    writeln!(out, "    fn schema_name() -> std::borrow::Cow<'static, str> {{")?;
    writeln!(out, "        std::borrow::Cow::Borrowed(\"{name}\")")?;
    writeln!(out, "    }}")?;
    writeln!(out)?;
    writeln!(out, "    #[allow(clippy::too_many_lines)]")?;
    writeln!(out, "    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {{")?;
    writeln!(out, "        let variants = vec![")?;

    for m in members {
        writeln!(out, "            schemars::json_schema!({{")?;
        if let Some(desc) = &m.description {
            writeln!(out, "                \"description\": {},", raw_str_literal(desc))?;
        }
        writeln!(out, "                \"const\": \"{}\",", m.value)?;
        writeln!(out, "            }}),")?;
    }

    writeln!(out, "        ];")?;
    writeln!(out)?;
    writeln!(out, "        schemars::json_schema!({{")?;
    writeln!(out, "            \"description\": {},", raw_str_literal(section.doc))?;
    writeln!(out, "            \"anyOf\": variants,")?;
    writeln!(out, "        }})")?;
    writeln!(out, "    }}")?;
    writeln!(out, "}}")
}
