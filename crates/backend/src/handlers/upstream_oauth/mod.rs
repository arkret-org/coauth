//! # Provider adapter boundary
//!
//! Upstream OAuth integration spans two layers:
//!
//! - **Connector layer** (`crates/oidc-client/`): Protocol-level operations
//!   (discovery, authorization URL, token exchange, userinfo). These are
//!   provider-agnostic for standard OIDC, and provider-specific for Chinese
//!   platforms (QQ, WeChat, WeCom, Feishu, DingTalk). The provider-specific
//!   userinfo-only adapters do not return signed ID tokens, so callbacks for
//!   those adapters fail closed unless
//!   `COAUTH_ALLOW_NON_STANDARD_UPSTREAM_OAUTH=true` is set.
//!
//! - **Handler layer** (this module): User-facing flow orchestration (session
//!   management, link/unlink, attribute mapping, conflict resolution). This
//!   logic is delegated to `upstream_link_workflow.rs`.
//!
//! The `ConnectorRegistry` provides runtime provider lookup. Each upstream
//! OAuth provider is NOT a `ConnectorProvider` (that's for PrincipalServers).
//! Instead, upstream providers are managed through
//! `UpstreamOAuthProviderRepository`.

use std::string::FromUtf8Error;

use coauth_data::{UpstreamOAuthProvider, UpstreamOAuthProviderTokenAuthMethod};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_keystore::{DecryptError, Encrypter, Keystore};
use pkcs8::DecodePrivateKey;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::oidc_client::types::client_credentials::ClientCredentials;

pub mod authorize;
pub mod backchannel_logout;
pub mod cache;
pub mod callback;
pub(crate) mod cookie;
pub mod jwks_cache;
pub(crate) mod template;

pub(crate) use self::cookie::UpstreamSessions as UpstreamSessionsCookie;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum ProviderCredentialsError {
    #[error("Provider doesn't have a client secret")]
    MissingClientSecret,

    #[error("Could not decrypt client secret")]
    DecryptClientSecret {
        #[from]
        inner: DecryptError,
    },

    #[error("Client secret is invalid")]
    InvalidClientSecret {
        #[from]
        inner: FromUtf8Error,
    },

    #[error("Invalid JSON in client secret")]
    InvalidClientSecretJson {
        #[from]
        inner: serde_json::Error,
    },

    #[error("Could not parse PEM encoded private key")]
    InvalidPrivateKey {
        #[from]
        inner: pkcs8::Error,
    },
}

#[derive(Debug, Deserialize)]
pub struct SignInWithApple {
    pub private_key: String,
    pub team_id: String,
    pub key_id: String,
}

pub(crate) fn client_credentials_for_provider(
    provider: &UpstreamOAuthProvider,
    token_endpoint: &Url,
    keystore: &Keystore,
    encrypter: &Encrypter,
) -> Result<ClientCredentials, ProviderCredentialsError> {
    let client_id = provider.client_id.clone();

    // Decrypt the client secret
    let client_secret = provider
        .encrypted_client_secret
        .as_deref()
        .map(|encrypted_client_secret| {
            let decrypted = encrypter.decrypt_string(encrypted_client_secret)?;
            let decrypted = String::from_utf8(decrypted)?;
            Ok::<_, ProviderCredentialsError>(decrypted)
        })
        .transpose()?;

    let client_credentials = match provider.token_endpoint_auth_method {
        UpstreamOAuthProviderTokenAuthMethod::None => ClientCredentials::None { client_id },

        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost => {
            ClientCredentials::ClientSecretPost {
                client_id,
                client_secret: client_secret
                    .ok_or(ProviderCredentialsError::MissingClientSecret)?,
            }
        }

        UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic => {
            ClientCredentials::ClientSecretBasic {
                client_id,
                client_secret: client_secret
                    .ok_or(ProviderCredentialsError::MissingClientSecret)?,
            }
        }

        UpstreamOAuthProviderTokenAuthMethod::ClientSecretJwt => {
            ClientCredentials::ClientSecretJwt {
                client_id,
                client_secret: client_secret
                    .ok_or(ProviderCredentialsError::MissingClientSecret)?,
                signing_algorithm: provider
                    .token_endpoint_signing_alg
                    .clone()
                    .unwrap_or(JsonWebSignatureAlg::Rs256),
                token_endpoint: token_endpoint.clone(),
            }
        }

        UpstreamOAuthProviderTokenAuthMethod::PrivateKeyJwt => ClientCredentials::PrivateKeyJwt {
            client_id,
            keystore: keystore.clone(),
            signing_algorithm: provider
                .token_endpoint_signing_alg
                .clone()
                .unwrap_or(JsonWebSignatureAlg::Rs256),
            token_endpoint: token_endpoint.clone(),
        },

        UpstreamOAuthProviderTokenAuthMethod::SignInWithApple => {
            let params = client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?;
            let params: SignInWithApple = serde_json::from_str(&params)?;

            let key = elliptic_curve::SecretKey::from_pkcs8_pem(&params.private_key)?;

            ClientCredentials::SignInWithApple {
                client_id,
                key,
                key_id: params.key_id,
                team_id: params.team_id,
            }
        }

        UpstreamOAuthProviderTokenAuthMethod::QQConnect => ClientCredentials::QQConnect {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
        },

        UpstreamOAuthProviderTokenAuthMethod::Feishu => ClientCredentials::Feishu {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
        },

        UpstreamOAuthProviderTokenAuthMethod::Lark => ClientCredentials::Lark {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
        },

        UpstreamOAuthProviderTokenAuthMethod::DingTalk => ClientCredentials::DingTalk {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
        },

        UpstreamOAuthProviderTokenAuthMethod::WeChat => ClientCredentials::WeChat {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
        },

        UpstreamOAuthProviderTokenAuthMethod::WeCom => ClientCredentials::WeCom {
            client_id,
            client_secret: client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?,
        },
    };

    Ok(client_credentials)
}

pub(crate) mod link_workflow;
