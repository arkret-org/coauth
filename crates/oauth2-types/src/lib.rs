//! [OAuth 2.0] and [OpenID Connect] types.
//!
//! This is part of the [Pasion] project.
//!
//! [OAuth 2.0]: https://oauth.net/2/
//! [OpenID Connect]: https://openid.net/connect/
//! [Pasion]: https://github.com/taidge/coauth

#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

pub mod errors;
pub mod oidc;
pub mod pkce;
pub mod registration;
pub mod requests;
pub mod response_type;
pub mod scope;
pub mod webfinger;

/// Traits intended for blanket imports.
pub mod prelude {
    pub use crate::pkce::CodeChallengeMethodExt;
}

#[cfg(test)]
mod test_utils;
