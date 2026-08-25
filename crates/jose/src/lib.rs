//! General-purpose JOSE implementation for coauth's OIDC boundary.
//!
//! This crate intentionally remains separate from Arkret protocol JWK and
//! detached-proof helpers: OIDC requires RSA/ECDSA signing, verification,
//! public JWKS hosting, and the complete JWT compact serialization surface.
//! Shared encoding primitives still come from `arkret-canonical` where their
//! contracts overlap.

#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::module_name_repetitions)]

mod base64;
pub mod claims;
pub mod constraints;
pub mod jwa;
pub mod jwk;
pub mod jwt;

pub use self::base64::Base64;
