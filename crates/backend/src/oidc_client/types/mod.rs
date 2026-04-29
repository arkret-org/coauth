//! OAuth 2.0 and OpenID Connect types.

pub mod client_credentials;

use std::collections::HashMap;

#[doc(inline)]
pub use coauth_iana as iana;
use coauth_jose::jwt::Jwt;
pub use oauth2_types::*;
use serde_json::Value;

/// An OpenID Connect [ID Token].
///
/// [ID Token]: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
pub type IdToken<'a> = Jwt<'a, HashMap<String, Value>>;
