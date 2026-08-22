//! OAuth and OpenID Connect types.

pub mod client_credentials;

use std::collections::HashMap;

use coauth_jose::jwt::Jwt;
pub use coauth_oauth_types::*;
use serde_json::Value;

/// An OpenID Connect [ID Token].
///
/// [ID Token]: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
pub type IdToken<'a> = Jwt<'a, HashMap<String, Value>>;
