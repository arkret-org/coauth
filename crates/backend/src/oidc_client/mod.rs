//! OpenID Connect client helpers used by coauth.
//!
//! # Scope
//!
//! The scope of this crate is to support the OIDC and OAuth features
//! needed by the Arkret/Soland auth flows.
//!
//! # OpenID Connect and OAuth Features
//!
//! - Grant Types:
//!   - [Authorization Code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
//! - [User Info](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
//! - [PKCE](https://www.rfc-editor.org/rfc/rfc7636)
//!
//! [OpenID Connect]: https://openid.net/connect/
//! [OAuth]: https://oauth.net/2/

pub mod error;
pub mod requests;
pub mod types;
