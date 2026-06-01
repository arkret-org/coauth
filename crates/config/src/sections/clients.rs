// Copyright (c) 2026 Contrix Authors. Licensed under the Apache License,
// Version 2.0; see LICENSE-APACHE for details.

// ── OAuth Client Configuration ──
//
// Defines configuration for statically-registered OAuth clients,
// including authentication methods, secrets, and redirect URIs.

use std::ops::Deref;

use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_jose::jwk::PublicJsonWebKeySet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};
use serde_with::serde_as;
use ulid::Ulid;
use url::Url;

use super::{ClientSecret, ClientSecretRaw, ConfigurationSection};

// ── JWKS Variant ──

/// Represents either an inline JWKS or a remote JWKS URI reference
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    Jwks(PublicJsonWebKeySet),
    JwksUri(Url),
}

impl From<PublicJsonWebKeySet> for JwksOrJwksUri {
    fn from(jwks: PublicJsonWebKeySet) -> Self {
        Self::Jwks(jwks)
    }
}

// ── Client Auth Method ──

/// Supported token endpoint authentication methods for configured clients
#[derive(JsonSchema, Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethodConfig {
    /// `none`: No authentication
    None,

    /// `client_secret_basic`: `client_id` and `client_secret` used as basic
    /// authorization credentials
    ClientSecretBasic,

    /// `client_secret_post`: `client_id` and `client_secret` sent in the
    /// request body
    ClientSecretPost,

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed using the `client_secret`
    ClientSecretJwt,

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed by an asymmetric key
    PrivateKeyJwt,
}

impl std::fmt::Display for ClientAuthMethodConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
            Self::PrivateKeyJwt => "private_key_jwt",
        };
        f.write_str(label)
    }
}

// ── Single Client Configuration ──

/// Represents the configuration of a single statically-registered OAuth
/// client
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientConfig {
    /// Unique identifier for this client (ULID format)
    #[schemars(
        with = "String",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$"),
        description = "A ULID as per https://github.com/ulid/spec"
    )]
    pub client_id: Ulid,

    /// Token endpoint authentication method for this client
    client_auth_method: ClientAuthMethodConfig,

    /// Name of the `OAuth` client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// Shared secret used for `client_secret_basic`, `client_secret_post`,
    /// and `client_secret_jwt` authentication methods
    #[schemars(with = "ClientSecretRaw")]
    #[serde_as(as = "serde_with::TryFromInto<ClientSecretRaw>")]
    #[serde(flatten)]
    pub client_secret: Option<ClientSecret>,

    /// The JSON Web Key Set (JWKS) used by the `private_key_jwt` authentication
    /// method. Mutually exclusive with `jwks_uri`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<PublicJsonWebKeySet>,

    /// The URL of the JSON Web Key Set (JWKS) used by the `private_key_jwt`
    /// authentication method. Mutually exclusive with `jwks`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,

    /// Allowed redirect URIs for authorization responses
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<Url>,
}

impl ClientConfig {
    // ── Validation helpers ──

    /// Checks that the fields present are consistent with the chosen auth
    /// method
    fn validate(&self) -> Result<(), Box<figment::error::Error>> {
        let method = self.client_auth_method;

        match method {
            ClientAuthMethodConfig::None => {
                self.reject_secret_for_method("none authentication method")?;
                self.reject_jwks_for_method("none authentication method")?;
            }

            ClientAuthMethodConfig::ClientSecretBasic
            | ClientAuthMethodConfig::ClientSecretPost
            | ClientAuthMethodConfig::ClientSecretJwt => {
                self.require_secret_for_method(method)?;
                self.reject_jwks_for_method(method)?;
            }

            ClientAuthMethodConfig::PrivateKeyJwt => {
                self.validate_private_key_jwt()?;
            }
        }

        Ok(())
    }

    /// Ensures a `client_secret` is present, returning an error otherwise
    fn require_secret_for_method(
        &self,
        method: impl std::fmt::Display,
    ) -> Result<(), Box<figment::error::Error>> {
        if self.client_secret.is_none() {
            let msg = format!("client_secret is required for {method}");
            let err = figment::error::Error::custom(msg);
            return Err(Box::new(err.with_path("client_auth_method")));
        }
        Ok(())
    }

    /// Ensures `client_secret` is absent for the given method
    fn reject_secret_for_method(
        &self,
        method: impl std::fmt::Display,
    ) -> Result<(), Box<figment::error::Error>> {
        if self.client_secret.is_some() {
            let msg = format!("client_secret is not allowed with {method}");
            let err = figment::error::Error::custom(msg);
            return Err(Box::new(err.with_path("client_secret")));
        }
        Ok(())
    }

    /// Ensures jwks and `jwks_uri` are both absent for the given method
    fn reject_jwks_for_method(
        &self,
        method: impl std::fmt::Display,
    ) -> Result<(), Box<figment::error::Error>> {
        if self.jwks.is_some() {
            let msg = format!("jwks is not allowed with {method}");
            let err = figment::error::Error::custom(msg);
            return Err(Box::new(err));
        }
        if self.jwks_uri.is_some() {
            let msg = format!("jwks_uri is not allowed with {method}");
            let err = figment::error::Error::custom(msg);
            return Err(Box::new(err));
        }
        Ok(())
    }

    /// Validates field constraints specific to the `private_key_jwt` method
    fn validate_private_key_jwt(&self) -> Result<(), Box<figment::error::Error>> {
        let has_jwks = self.jwks.is_some();
        let has_jwks_uri = self.jwks_uri.is_some();

        if !has_jwks && !has_jwks_uri {
            let err =
                figment::error::Error::custom("jwks or jwks_uri is required for private_key_jwt");
            return Err(Box::new(err.with_path("client_auth_method")));
        }

        if has_jwks && has_jwks_uri {
            let err = figment::error::Error::custom("jwks and jwks_uri are mutually exclusive");
            return Err(Box::new(err.with_path("jwks")));
        }

        if self.client_secret.is_some() {
            let err =
                figment::error::Error::custom("client_secret is not allowed with private_key_jwt");
            return Err(Box::new(err.with_path("client_secret")));
        }

        Ok(())
    }

    // ── Public accessors ──

    /// Authentication method used for this client
    #[must_use]
    pub fn client_auth_method(&self) -> OAuthClientAuthenticationMethod {
        match self.client_auth_method {
            ClientAuthMethodConfig::None => OAuthClientAuthenticationMethod::None,
            ClientAuthMethodConfig::ClientSecretBasic => {
                OAuthClientAuthenticationMethod::ClientSecretBasic
            }
            ClientAuthMethodConfig::ClientSecretPost => {
                OAuthClientAuthenticationMethod::ClientSecretPost
            }
            ClientAuthMethodConfig::ClientSecretJwt => {
                OAuthClientAuthenticationMethod::ClientSecretJwt
            }
            ClientAuthMethodConfig::PrivateKeyJwt => OAuthClientAuthenticationMethod::PrivateKeyJwt,
        }
    }

    /// Returns the client secret.
    ///
    /// If `client_secret_file` was given, the secret is read from that file.
    ///
    /// # Errors
    ///
    /// Returns an error when the client secret could not be read from file.
    pub async fn client_secret(&self) -> anyhow::Result<Option<String>> {
        match &self.client_secret {
            Some(secret) => Ok(Some(secret.value().await?)),
            None => Ok(None),
        }
    }
}

// ── Clients Collection ──

/// Wrapper around a list of statically-configured OAuth clients
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ClientsConfig(#[schemars(with = "Vec::<ClientConfig>")] Vec<ClientConfig>);

impl ClientsConfig {
    /// Returns true if all fields are at their default values
    pub(crate) fn is_default(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for ClientsConfig {
    type Target = Vec<ClientConfig>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for ClientsConfig {
    type Item = ClientConfig;
    type IntoIter = std::vec::IntoIter<ClientConfig>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// ── ConfigurationSection impl ──

impl ConfigurationSection for ClientsConfig {
    const PATH: &'static str = "clients";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        for (index, client) in self.0.iter().enumerate() {
            client.validate().map_err(|mut err| {
                // Annotate the error with location metadata from figment
                err.metadata = figment.find_metadata(Self::PATH).cloned();
                err.profile = Some(figment::Profile::Default);
                err.path.insert(0, Self::PATH.to_owned());
                err.path.insert(1, format!("{index}"));
                err
            })?;
        }

        Ok(())
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    #![allow(clippy::result_large_err)]
    use std::str::FromStr;

    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };
    use tokio::{runtime::Handle, task};

    use super::*;

    #[tokio::test]
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    r#"
                      clients:
                        - client_id: 01GFWR28C4KNE04WG3HKXB7C9R
                          client_auth_method: none
                          redirect_uris:
                            - https://exemple.fr/callback

                        - client_id: 01GFWR32NCQ12B8Z0J8CPXRRB6
                          client_auth_method: client_secret_basic
                          client_secret_file: secret

                        - client_id: 01GFWR3WHR93Y5HK389H28VHZ9
                          client_auth_method: client_secret_post
                          client_secret: c1!3n753c237

                        - client_id: 01GFWR43R2ZZ8HX9CVBNW9TJWG
                          client_auth_method: client_secret_jwt
                          client_secret_file: secret

                        - client_id: 01GFWR4BNFDCC4QDG6AMSP1VRR
                          client_auth_method: private_key_jwt
                          jwks:
                            keys:
                            - kid: "03e84aed4ef4431014e8617567864c4efaaaede9"
                              kty: "RSA"
                              alg: "RS256"
                              use: "sig"
                              e: "AQAB"
                              n: "ma2uRyBeSEOatGuDpCiV9oIxlDWix_KypDYuhQfEzqi_BiF4fV266OWfyjcABbam59aJMNvOnKW3u_eZM-PhMCBij5MZ-vcBJ4GfxDJeKSn-GP_dJ09rpDcILh8HaWAnPmMoi4DC0nrfE241wPISvZaaZnGHkOrfN_EnA5DligLgVUbrA5rJhQ1aSEQO_gf1raEOW3DZ_ACU3qhtgO0ZBG3a5h7BPiRs2sXqb2UCmBBgwyvYLDebnpE7AotF6_xBIlR-Cykdap3GHVMXhrIpvU195HF30ZoBU4dMd-AeG6HgRt4Cqy1moGoDgMQfbmQ48Hlunv9_Vi2e2CLvYECcBw"

                            - kid: "d01c1abe249269f72ef7ca2613a86c9f05e59567"
                              kty: "RSA"
                              alg: "RS256"
                              use: "sig"
                              e: "AQAB"
                              n: "0hukqytPwrj1RbMYhYoepCi3CN5k7DwYkTe_Cmb7cP9_qv4ok78KdvFXt5AnQxCRwBD7-qTNkkfMWO2RxUMBdQD0ED6tsSb1n5dp0XY8dSWiBDCX8f6Hr-KolOpvMLZKRy01HdAWcM6RoL9ikbjYHUEW1C8IJnw3MzVHkpKFDL354aptdNLaAdTCBvKzU9WpXo10g-5ctzSlWWjQuecLMQ4G1mNdsR1LHhUENEnOvgT8cDkX0fJzLbEbyBYkdMgKggyVPEB1bg6evG4fTKawgnf0IDSPxIU-wdS9wdSP9ZCJJPLi5CEp-6t6rE_sb2dGcnzjCGlembC57VwpkUvyMw"
                    "#,
                )?;
                jail.create_file("secret", r"c1!3n753c237")?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<ClientsConfig>("clients")?;

                assert_eq!(config.0.len(), 5);

                assert_eq!(
                    config.0[0].client_id,
                    Ulid::from_str("01GFWR28C4KNE04WG3HKXB7C9R").unwrap()
                );
                assert_eq!(
                    config.0[0].redirect_uris,
                    vec!["https://exemple.fr/callback".parse().unwrap()]
                );

                assert_eq!(
                    config.0[1].client_id,
                    Ulid::from_str("01GFWR32NCQ12B8Z0J8CPXRRB6").unwrap()
                );
                assert_eq!(config.0[1].redirect_uris, Vec::new());

                assert!(config.0[0].client_secret.is_none());
                assert!(matches!(config.0[1].client_secret, Some(ClientSecret::File(ref p)) if p == "secret"));
                assert!(matches!(config.0[2].client_secret, Some(ClientSecret::Value(ref v)) if v == "c1!3n753c237"));
                assert!(matches!(config.0[3].client_secret, Some(ClientSecret::File(ref p)) if p == "secret"));
                assert!(config.0[4].client_secret.is_none());

                Handle::current().block_on(async move {
                    assert_eq!(config.0[1].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                    assert_eq!(config.0[2].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                    assert_eq!(config.0[3].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                });

                Ok(())
            });
        }).await.unwrap();
    }
}
