//! [OAuth] and [OpenID Connect] types.
//!
//! This is part of the coauth project.
//!
//! [OAuth]: https://oauth.net/2/
//! [OpenID Connect]: https://openid.net/connect/
//! [coauth]: https://github.com/contrix-dev/coauth

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
