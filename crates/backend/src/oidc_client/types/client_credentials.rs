// Copyright 2022-2024 Kevin Commaille.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Types and methods for client credentials.

use std::collections::HashMap;
use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::claims::{self, ClaimError};
use coauth_jose::constraints::Constrainable;
use coauth_jose::jwa::{AsymmetricSigningKey, SymmetricKey};
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keyring::Keyring;
use rand_core::RngCore as Rng;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use super::super::error::CredentialsError;

/// The credentials obtained during registration, to authenticate a client on
/// endpoints that require it.
#[derive(Clone)]
pub enum ClientCredentials {
    /// No client authentication is used.
    ///
    /// This is used if the client is public.
    None {
        /// The unique ID for the client.
        client_id: String,
    },

    /// The client authentication is sent via the Authorization HTTP header.
    ClientSecretBasic {
        /// The unique ID for the client.
        client_id: String,

        /// The secret of the client.
        client_secret: String,
    },

    /// The client authentication is sent with the body of the request.
    ClientSecretPost {
        /// The unique ID for the client.
        client_id: String,

        /// The secret of the client.
        client_secret: String,
    },

    /// The client authentication uses a JWT signed with a key derived from the
    /// client secret.
    ClientSecretJwt {
        /// The unique ID for the client.
        client_id: String,

        /// The secret of the client.
        client_secret: String,

        /// The algorithm used to sign the JWT.
        signing_algorithm: JsonWebSignatureAlg,

        /// The URL of the issuer's Token endpoint.
        token_endpoint: Url,
    },

    /// The client authentication uses a JWT signed with a private key.
    PrivateKeyJwt {
        /// The unique ID for the client.
        client_id: String,

        /// The keyring used to sign the JWT.
        keyring: Keyring,

        /// The algorithm used to sign the JWT.
        signing_algorithm: JsonWebSignatureAlg,

        /// The URL of the issuer's Token endpoint.
        token_endpoint: Url,
    },

    // -- coauth-specific credential types for social login providers --
    /// The client authenticates using Sign in with Apple.
    ///
    /// Apple requires a specially constructed JWT as the `client_secret`.
    SignInWithApple {
        /// The unique ID for the client.
        client_id: String,

        /// The ECDSA key used to sign the JWT.
        key: elliptic_curve::SecretKey<p256::NistP256>,

        /// The key ID.
        key_id: String,

        /// The Apple Team ID.
        team_id: String,
    },

    /// QQ Connect: `client_id` and `client_secret` sent in the request body.
    /// The actual token exchange uses a QQ-specific strand handled separately.
    QQConnect {
        /// The unique ID for the client (QQ `AppID`).
        client_id: String,

        /// The secret of the client (QQ `AppKey`).
        client_secret: String,
    },

    /// Feishu (Lark): uses `app_access_token` as Bearer auth for token
    /// exchange. The actual token exchange uses a Feishu-specific strand
    /// handled separately.
    Feishu {
        /// The unique ID for the client (Feishu `app_id`).
        client_id: String,

        /// The secret of the client (Feishu `app_secret`).
        client_secret: String,
    },

    /// Lark (international Feishu): same strand as Feishu with different
    /// endpoints.
    Lark {
        /// The unique ID for the client (Lark `app_id`).
        client_id: String,

        /// The secret of the client (Lark `app_secret`).
        client_secret: String,
    },

    /// `DingTalk`: uses JSON body with clientId/clientSecret for token
    /// exchange.
    DingTalk {
        /// The unique ID for the client.
        client_id: String,

        /// The secret of the client.
        client_secret: String,
    },

    /// `WeChat` Open Platform: uses appid/secret as query params.
    WeChat {
        /// The unique ID for the client (`WeChat` `AppID`).
        client_id: String,

        /// The secret of the client (`WeChat` `AppSecret`).
        client_secret: String,
    },

    /// `WeCom`: uses corpid/corpsecret for corp access token.
    WeCom {
        /// The unique ID for the client (`WeCom` `CorpID`).
        client_id: String,

        /// The secret of the client (`WeCom` `CorpSecret`).
        client_secret: String,
    },
}

impl ClientCredentials {
    /// Get the client ID of these `ClientCredentials`.
    #[must_use]
    pub fn client_id(&self) -> &str {
        match self {
            ClientCredentials::None { client_id }
            | ClientCredentials::ClientSecretBasic { client_id, .. }
            | ClientCredentials::ClientSecretPost { client_id, .. }
            | ClientCredentials::ClientSecretJwt { client_id, .. }
            | ClientCredentials::PrivateKeyJwt { client_id, .. }
            | ClientCredentials::SignInWithApple { client_id, .. }
            | ClientCredentials::QQConnect { client_id, .. }
            | ClientCredentials::Feishu { client_id, .. }
            | ClientCredentials::Lark { client_id, .. }
            | ClientCredentials::DingTalk { client_id, .. }
            | ClientCredentials::WeChat { client_id, .. }
            | ClientCredentials::WeCom { client_id, .. } => client_id,
        }
    }

    /// Apply these [`ClientCredentials`] to the given
    /// [`reqwest::RequestBuilder`] together with the given form body.
    ///
    /// Depending on the credential type the authentication may be placed in an
    /// HTTP header (for `ClientSecretBasic`) or serialised as part of the form
    /// body.
    pub(crate) fn authenticated_form<T: Serialize>(
        &self,
        request: reqwest::RequestBuilder,
        form: &T,
        now: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> Result<reqwest::RequestBuilder, CredentialsError> {
        let request = match self {
            ClientCredentials::None { client_id } => request.form(&AuthenticatedForm {
                body: form,
                client_id: Some(client_id),
                client_secret: None,
                client_assertion: None,
                client_assertion_type: None,
            }),

            ClientCredentials::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                // Encode the values with `application/x-www-form-urlencoded`
                // before setting them as HTTP Basic credentials.
                let encoded_id =
                    form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>();
                let encoded_secret =
                    form_urlencoded::byte_serialize(client_secret.as_bytes()).collect::<String>();
                request
                    .basic_auth(encoded_id, Some(encoded_secret))
                    .form(&AuthenticatedForm {
                        body: form,
                        client_id: None,
                        client_secret: None,
                        client_assertion: None,
                        client_assertion_type: None,
                    })
            }

            ClientCredentials::ClientSecretPost {
                client_id,
                client_secret,
            } => request.form(&AuthenticatedForm {
                body: form,
                client_id: Some(client_id),
                client_secret: Some(client_secret),
                client_assertion: None,
                client_assertion_type: None,
            }),

            ClientCredentials::ClientSecretJwt {
                client_id,
                client_secret,
                signing_algorithm,
                token_endpoint,
            } => {
                let claims = prepare_jwt_bearer_claims(
                    client_id.clone(),
                    token_endpoint.to_string(),
                    now,
                    rng,
                )?;
                let key = SymmetricKey::new_for_alg(
                    client_secret.as_bytes().to_vec(),
                    signing_algorithm,
                )?;
                let header = JsonWebSignatureHeader::new(signing_algorithm.clone());
                let jwt = Jwt::sign(header, claims, &key)?;

                request.form(&AuthenticatedForm {
                    body: form,
                    client_id: None,
                    client_secret: None,
                    client_assertion: Some(jwt.as_str()),
                    client_assertion_type: Some(JwtBearerClientAssertionType),
                })
            }

            ClientCredentials::PrivateKeyJwt {
                client_id,
                keyring,
                signing_algorithm,
                token_endpoint,
            } => {
                let claims = prepare_jwt_bearer_claims(
                    client_id.clone(),
                    token_endpoint.to_string(),
                    now,
                    rng,
                )?;

                let key = keyring
                    .signing_key_for_algorithm(signing_algorithm)
                    .ok_or(CredentialsError::NoPrivateKeyFound)?;
                let signer = keyring
                    .signer_for_algorithm(signing_algorithm)
                    .map_err(|_| CredentialsError::JwtWrongAlgorithm)?;
                let mut header = JsonWebSignatureHeader::new(signing_algorithm.clone());

                if let Some(kid) = key.kid() {
                    header = header.with_kid(kid);
                }

                let client_assertion = Jwt::sign(header, claims, &*signer)?;

                request.form(&AuthenticatedForm {
                    body: form,
                    client_id: None,
                    client_secret: None,
                    client_assertion: Some(client_assertion.as_str()),
                    client_assertion_type: Some(JwtBearerClientAssertionType),
                })
            }

            // -- coauth-specific social provider handling --
            ClientCredentials::QQConnect {
                client_id,
                client_secret,
            }
            | ClientCredentials::Feishu {
                client_id,
                client_secret,
            }
            | ClientCredentials::Lark {
                client_id,
                client_secret,
            }
            | ClientCredentials::DingTalk {
                client_id,
                client_secret,
            }
            | ClientCredentials::WeChat {
                client_id,
                client_secret,
            }
            | ClientCredentials::WeCom {
                client_id,
                client_secret,
            } => request.form(&AuthenticatedForm {
                body: form,
                client_id: Some(client_id),
                client_secret: Some(client_secret),
                client_assertion: None,
                client_assertion_type: None,
            }),

            ClientCredentials::SignInWithApple {
                client_id,
                key,
                key_id,
                team_id,
            } => {
                // Apple expects a specially signed JWT as the client_secret.
                // See: https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
                let signer = AsymmetricSigningKey::es256(key.clone());

                let mut apple_claims = HashMap::new();
                claims::ISS.insert(&mut apple_claims, team_id)?;
                claims::SUB.insert(&mut apple_claims, client_id)?;
                claims::AUD.insert(&mut apple_claims, "https://appleid.apple.com".to_owned())?;
                claims::IAT.insert(&mut apple_claims, now)?;
                claims::EXP.insert(
                    &mut apple_claims,
                    now + Duration::microseconds(60 * 1000 * 1000),
                )?;

                let header =
                    JsonWebSignatureHeader::new(JsonWebSignatureAlg::Es256).with_kid(key_id);
                let client_secret_jwt = Jwt::sign(header, apple_claims, &signer)?;

                request.form(&AuthenticatedForm {
                    body: form,
                    client_id: Some(client_id),
                    client_secret: Some(client_secret_jwt.as_str()),
                    client_assertion: None,
                    client_assertion_type: None,
                })
            }
        };

        Ok(request)
    }
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None { client_id } => f
                .debug_struct("None")
                .field("client_id", client_id)
                .finish(),
            Self::ClientSecretBasic { client_id, .. } => f
                .debug_struct("ClientSecretBasic")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::ClientSecretPost { client_id, .. } => f
                .debug_struct("ClientSecretPost")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::ClientSecretJwt {
                client_id,
                signing_algorithm,
                token_endpoint,
                ..
            } => f
                .debug_struct("ClientSecretJwt")
                .field("client_id", client_id)
                .field("signing_algorithm", signing_algorithm)
                .field("token_endpoint", token_endpoint)
                .finish_non_exhaustive(),
            Self::PrivateKeyJwt {
                client_id,
                signing_algorithm,
                token_endpoint,
                ..
            } => f
                .debug_struct("PrivateKeyJwt")
                .field("client_id", client_id)
                .field("signing_algorithm", signing_algorithm)
                .field("token_endpoint", token_endpoint)
                .finish_non_exhaustive(),
            Self::SignInWithApple {
                client_id,
                key_id,
                team_id,
                ..
            } => f
                .debug_struct("SignInWithApple")
                .field("client_id", client_id)
                .field("key_id", key_id)
                .field("team_id", team_id)
                .finish_non_exhaustive(),
            Self::QQConnect { client_id, .. } => f
                .debug_struct("QQConnect")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::Feishu { client_id, .. } => f
                .debug_struct("Feishu")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::Lark { client_id, .. } => f
                .debug_struct("Lark")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::DingTalk { client_id, .. } => f
                .debug_struct("DingTalk")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::WeChat { client_id, .. } => f
                .debug_struct("WeChat")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::WeCom { client_id, .. } => f
                .debug_struct("WeCom")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")]
struct JwtBearerClientAssertionType;

/// Prepare the standard JWT bearer claims used for `client_secret_jwt` and
/// `private_key_jwt` authentication methods.
fn prepare_jwt_bearer_claims(
    iss: String,
    aud: String,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<HashMap<String, Value>, ClaimError> {
    let mut claims = HashMap::new();

    claims::ISS.insert(&mut claims, iss.clone())?;
    claims::SUB.insert(&mut claims, iss)?;
    claims::AUD.insert(&mut claims, aud)?;
    claims::IAT.insert(&mut claims, now)?;
    claims::EXP.insert(
        &mut claims,
        now + Duration::microseconds(5 * 60 * 1000 * 1000),
    )?;

    let mut jti = [0u8; 16];
    rng.fill_bytes(&mut jti);
    let jti = Base64UrlUnpadded::encode_string(&jti);
    claims::JTI.insert(&mut claims, jti)?;

    Ok(claims)
}

/// A request body combined with client credentials for serialisation.
#[derive(Clone, Serialize)]
struct AuthenticatedForm<'a, T> {
    #[serde(flatten)]
    body: T,

    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion_type: Option<JwtBearerClientAssertionType>,
}
