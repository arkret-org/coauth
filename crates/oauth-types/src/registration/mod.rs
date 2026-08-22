//! Types for [Dynamic Client Registration].
//!
//! [Dynamic Client Registration]: https://openid.net/specs/openid-connect-registration-1_0.html

use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_iana::oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod};

use crate::oidc::ApplicationType;
use crate::requests::GrantType;

mod client_metadata_serde;
mod localized;
mod metadata;
mod response;
mod validation;

#[cfg(test)]
mod tests;

pub use self::localized::Localized;
pub use self::metadata::ClientMetadata;
pub use self::response::ClientRegistrationResponse;
pub use self::validation::{ClientMetadataVerificationError, VerifiedClientMetadata};

/// The default value of `response_types` if it is not set.
pub const DEFAULT_RESPONSE_TYPES: [OAuthAuthorizationEndpointResponseType; 1] =
    [OAuthAuthorizationEndpointResponseType::Code];

/// The default value of `grant_types` if it is not set.
pub const DEFAULT_GRANT_TYPES: &[GrantType] = &[GrantType::AuthorizationCode];

/// The default value of `application_type` if it is not set.
pub const DEFAULT_APPLICATION_TYPE: ApplicationType = ApplicationType::Web;

/// The default value of `token_endpoint_auth_method` if it is not set.
pub const DEFAULT_TOKEN_AUTH_METHOD: &OAuthClientAuthenticationMethod =
    &OAuthClientAuthenticationMethod::ClientSecretBasic;

/// The default value of `id_token_signed_response_alg` if it is not set.
pub const DEFAULT_SIGNING_ALGORITHM: &JsonWebSignatureAlg = &JsonWebSignatureAlg::Rs256;
