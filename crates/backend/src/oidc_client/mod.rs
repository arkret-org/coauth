//! OpenID Connect client helpers used by coauth.
//!
//! # Scope
//!
//! The scope of this crate is to support the OIDC and OAuth 2.0 features
//! needed by the Contrix/Soland auth flows.
//!
//! # OpenID Connect and OAuth 2.0 Features
//!
//! - Grant Types:
//!   - [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
//!   - [Client Credentials](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
//!   - [Device Code](https://www.rfc-editor.org/rfc/rfc8628) (TBD)
//!   - [Refresh Token](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens)
//! - [User Info](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
//! - [PKCE](https://www.rfc-editor.org/rfc/rfc7636)
//!
//! [OpenID Connect]: https://openid.net/connect/
//! [OAuth 2.0]: https://oauth.net/2/

pub mod error;
pub mod requests;
pub mod types;

use std::fmt;

#[doc(inline)]
pub use coauth_jose as jose;

// Wrapper around `String` that cannot be used in a meaningful way outside of
// this crate. Used for string enums that only allow certain characters because
// their variant can't be private.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivString(String);

impl fmt::Debug for PrivString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
