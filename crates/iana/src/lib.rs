//! IANA registry values for JOSE and OAuth 2.0, defined via declarative macros.

#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

pub mod jose;
mod macros;
pub mod oauth;

/// An error that occurred while parsing a value from a string.
pub struct ParseError {
    _private: (),
}

impl ParseError {
    fn new() -> Self {
        Self { _private: () }
    }
}

impl core::fmt::Debug for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ParseError")
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Parse error")
    }
}

impl std::error::Error for ParseError {}
