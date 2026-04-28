// ── Upstream OAuth 2.0 / OIDC Provider Configuration ──
//
// Defines how the application connects to external identity providers
// using OAuth 2.0 and OpenID Connect protocols.

mod claims;
mod discovery;
mod provider;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error as _};

// Re-export sub-module types so they remain accessible from the parent
pub use self::claims::{ClaimsImports, EmailImportPreference, ImportAction, OnConflict};
pub use self::{
    discovery::{DiscoveryMode, OnBackchannelLogout, PkceMethod},
    provider::{Provider, ResponseMode, TokenAuthMethod},
};
use crate::ConfigurationSection;

// ── Top-level Section ──

/// Holds the list of upstream OAuth 2.0 identity providers
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct UpstreamOAuth2Config {
    /// List of OAuth 2.0 providers
    pub providers: Vec<Provider>,
}

impl UpstreamOAuth2Config {
    /// Returns `true` when no providers have been configured
    pub(crate) fn is_default(&self) -> bool {
        self.providers.is_empty()
    }
}

impl ConfigurationSection for UpstreamOAuth2Config {
    const PATH: &'static str = "upstream_oauth2";

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        for (index, provider) in self.providers.iter().enumerate() {
            let annotate = |mut error: figment::Error| {
                error.metadata = figment
                    .find_metadata(&format!("{root}.providers", root = Self::PATH))
                    .cloned();
                error.profile = Some(figment::Profile::Default);
                error.path = vec![
                    Self::PATH.to_owned(),
                    "providers".to_owned(),
                    index.to_string(),
                ];
                error
            };

            // Discovery requires an issuer
            if !matches!(provider.discovery_mode, DiscoveryMode::Disabled)
                && provider.issuer.is_none()
            {
                return Err(annotate(figment::Error::custom(
                    "The `issuer` field is required when discovery is enabled",
                ))
                .into());
            }

            // Validate client_secret presence based on auth method
            check_client_secret_requirement(provider, &annotate)?;

            // Validate signing algorithm requirement
            check_signing_alg_requirement(provider, &annotate)?;

            // Validate Apple-specific fields
            check_apple_specific_fields(provider, &annotate)?;

            // Validate claims import consistency
            check_claims_import_consistency(provider, &annotate)?;
        }

        Ok(())
    }
}

// ── Validation Helpers ──

/// Ensures client_secret is present when required and absent when forbidden
/// by the chosen token endpoint auth method.
fn check_client_secret_requirement(
    provider: &Provider,
    annotate: &dyn Fn(figment::Error) -> figment::Error,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    match provider.token_endpoint_auth_method {
        TokenAuthMethod::None
        | TokenAuthMethod::PrivateKeyJwt
        | TokenAuthMethod::SignInWithApple => {
            if provider.client_secret.is_some() {
                return Err(annotate(figment::Error::custom(
                    "Unexpected field `client_secret` for the selected authentication method",
                ))
                .into());
            }
        }
        TokenAuthMethod::ClientSecretBasic
        | TokenAuthMethod::ClientSecretPost
        | TokenAuthMethod::ClientSecretJwt
        | TokenAuthMethod::QQConnect
        | TokenAuthMethod::Feishu
        | TokenAuthMethod::Lark
        | TokenAuthMethod::DingTalk
        | TokenAuthMethod::WeChat
        | TokenAuthMethod::WeCom => {
            if provider.client_secret.is_none() {
                return Err(annotate(figment::Error::missing_field("client_secret")).into());
            }
        }
    }
    Ok(())
}

/// Ensures token_endpoint_auth_signing_alg is present when required and
/// absent when not applicable.
fn check_signing_alg_requirement(
    provider: &Provider,
    annotate: &dyn Fn(figment::Error) -> figment::Error,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    match provider.token_endpoint_auth_method {
        TokenAuthMethod::ClientSecretJwt | TokenAuthMethod::PrivateKeyJwt => {
            if provider.token_endpoint_auth_signing_alg.is_none() {
                return Err(annotate(figment::Error::missing_field(
                    "token_endpoint_auth_signing_alg",
                ))
                .into());
            }
        }
        TokenAuthMethod::None
        | TokenAuthMethod::ClientSecretBasic
        | TokenAuthMethod::ClientSecretPost
        | TokenAuthMethod::SignInWithApple
        | TokenAuthMethod::QQConnect
        | TokenAuthMethod::Feishu
        | TokenAuthMethod::Lark
        | TokenAuthMethod::DingTalk
        | TokenAuthMethod::WeChat
        | TokenAuthMethod::WeCom => {
            if provider.token_endpoint_auth_signing_alg.is_some() {
                return Err(annotate(figment::Error::custom(
                    "Unexpected field `token_endpoint_auth_signing_alg` for the selected authentication method",
                ))
                .into());
            }
        }
    }
    Ok(())
}

/// Ensures sign_in_with_apple fields are only present when the auth method
/// is `SignInWithApple`.
fn check_apple_specific_fields(
    provider: &Provider,
    annotate: &dyn Fn(figment::Error) -> figment::Error,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    match provider.token_endpoint_auth_method {
        TokenAuthMethod::SignInWithApple => {
            if provider.sign_in_with_apple.is_none() {
                return Err(annotate(figment::Error::missing_field("sign_in_with_apple")).into());
            }
        }
        TokenAuthMethod::None
        | TokenAuthMethod::ClientSecretBasic
        | TokenAuthMethod::ClientSecretPost
        | TokenAuthMethod::ClientSecretJwt
        | TokenAuthMethod::PrivateKeyJwt
        | TokenAuthMethod::QQConnect
        | TokenAuthMethod::Feishu
        | TokenAuthMethod::Lark
        | TokenAuthMethod::DingTalk
        | TokenAuthMethod::WeChat
        | TokenAuthMethod::WeCom => {
            if provider.sign_in_with_apple.is_some() {
                return Err(annotate(figment::Error::custom(
                    "Unexpected field `sign_in_with_apple` for the selected authentication method",
                ))
                .into());
            }
        }
    }
    Ok(())
}

/// Validates the claims_imports section for internal consistency, checking
/// that skip_confirmation and on_conflict settings are compatible.
fn check_claims_import_consistency(
    provider: &Provider,
    annotate: &dyn Fn(figment::Error) -> figment::Error,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let imports = &provider.claims_imports;

    if imports.skip_confirmation {
        if imports.localpart.action != ImportAction::Require {
            return Err(annotate(figment::Error::custom(
                "The field `action` must be `require` when `skip_confirmation` is set to `true`",
            ))
            .with_path("claims_imports.localpart")
            .into());
        }

        if imports.email.action == ImportAction::Suggest {
            return Err(annotate(figment::Error::custom(
                "The field `action` must not be `suggest` when `skip_confirmation` is set to `true`",
            ))
            .with_path("claims_imports.email")
            .into());
        }

        if imports.displayname.action == ImportAction::Suggest {
            return Err(annotate(figment::Error::custom(
                "The field `action` must not be `suggest` when `skip_confirmation` is set to `true`",
            ))
            .with_path("claims_imports.displayname")
            .into());
        }
    }

    // Localpart on_conflict requires force/require action
    let conflict_requires_force = matches!(
        imports.localpart.on_conflict,
        OnConflict::Add | OnConflict::Replace | OnConflict::Set
    );
    let action_is_force_or_require = matches!(
        imports.localpart.action,
        ImportAction::Force | ImportAction::Require
    );

    if conflict_requires_force && !action_is_force_or_require {
        return Err(annotate(figment::Error::custom(
            "The field `action` must be either `force` or `require` when `on_conflict` is set to `add`, `replace` or `set`",
        ))
        .with_path("claims_imports.localpart")
        .into());
    }

    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };
    use tokio::{runtime::Handle, task};
    use ulid::Ulid;

    use super::*;
    use crate::ClientSecret;

    #[tokio::test]
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    r#"
                      upstream_oauth2:
                        providers:
                          - id: 01GFWR28C4KNE04WG3HKXB7C9R
                            client_id: upstream-oauth2
                            token_endpoint_auth_method: none

                          - id: 01GFWR32NCQ12B8Z0J8CPXRRB6
                            client_id: upstream-oauth2
                            client_secret_file: secret
                            token_endpoint_auth_method: client_secret_basic

                          - id: 01GFWR3WHR93Y5HK389H28VHZ9
                            client_id: upstream-oauth2
                            client_secret: c1!3n753c237
                            token_endpoint_auth_method: client_secret_post

                          - id: 01GFWR43R2ZZ8HX9CVBNW9TJWG
                            client_id: upstream-oauth2
                            client_secret_file: secret
                            token_endpoint_auth_method: client_secret_jwt

                          - id: 01GFWR4BNFDCC4QDG6AMSP1VRR
                            client_id: upstream-oauth2
                            token_endpoint_auth_method: private_key_jwt
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
                    .extract_inner::<UpstreamOAuth2Config>("upstream_oauth2")?;

                assert_eq!(config.providers.len(), 5);

                assert_eq!(
                    config.providers[1].id,
                    Ulid::from_str("01GFWR32NCQ12B8Z0J8CPXRRB6").unwrap()
                );

                assert!(config.providers[0].client_secret.is_none());
                assert!(matches!(config.providers[1].client_secret, Some(ClientSecret::File(ref p)) if p == "secret"));
                assert!(matches!(config.providers[2].client_secret, Some(ClientSecret::Value(ref v)) if v == "c1!3n753c237"));
                assert!(matches!(config.providers[3].client_secret, Some(ClientSecret::File(ref p)) if p == "secret"));
                assert!(config.providers[4].client_secret.is_none());

                Handle::current().block_on(async move {
                    assert_eq!(config.providers[1].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                    assert_eq!(config.providers[2].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                    assert_eq!(config.providers[3].client_secret().await.unwrap().unwrap(), "c1!3n753c237");
                });

                Ok(())
            });
        }).await.unwrap();
    }
}
