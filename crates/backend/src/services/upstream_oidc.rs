use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_config::ArkretConfig;
use coauth_data::{UpstreamOAuthProvider, UrlBuilder};
use coauth_jose::claims::{self, TokenHash};
use coauth_keystore::{Encrypter, Keystore};
use coauth_oauth_types::oidc::VerifiedProviderMetadata;
use coauth_oauth_types::requests::{
    AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant,
};
use serde::Deserialize;
use url::Url;

use crate::handlers::arkret;
use crate::oidc_client::requests::jose::{
    JwtVerificationData, fetch_jwks, verify_id_token, verify_signed_jwt,
};
use crate::oidc_client::requests::token::request_access_token;
use crate::outbound_http::RequestBuilderExt as _;
use crate::services::resolved_principal_audiences::{
    ResolvedPrincipalAudiences, effective_audience,
};

pub type UpstreamOidcServiceHandle = Arc<dyn UpstreamOidcService>;

#[derive(Clone, Debug, Deserialize)]
pub struct OidcUserinfoClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(rename = "org.arkret.principal_id")]
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(rename = "org.arkret.session_id")]
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UpstreamOidcSessionGrantTarget {
    pub audience: String,
    pub principal_server_name: Option<String>,
    pub principal_server_endpoint: Option<String>,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum UpstreamOidcExchangeMode {
    LocalCoauth,
    Federated { provider: UpstreamOAuthProvider },
}

impl UpstreamOidcExchangeMode {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::LocalCoauth => "local_coauth",
            Self::Federated { .. } => "federated",
        }
    }
}

#[derive(Clone, Debug)]
pub struct FederatedOidcExchange {
    pub token_response: AccessTokenResponse,
    pub userinfo: OidcUserinfoClaims,
    pub userinfo_response_signed: bool,
    pub id_token_subject: Option<String>,
}

#[async_trait]
pub trait UpstreamOidcService: Send + Sync {
    fn exchange_mode_for_issuer(
        &self,
        url_builder: &UrlBuilder,
        providers: &[UpstreamOAuthProvider],
        issuer: &Url,
        client_id: &str,
    ) -> Result<UpstreamOidcExchangeMode, String>;

    fn validate_exchange_endpoints(
        &self,
        url_builder: &UrlBuilder,
        mode: &UpstreamOidcExchangeMode,
        discovered_metadata: &VerifiedProviderMetadata,
        token_endpoint: &Url,
        userinfo_endpoint: &Url,
    ) -> Result<(), String>;

    async fn session_grant_target_for_requested_audience(
        &self,
        http_client: &reqwest::Client,
        url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        resolved: &ResolvedPrincipalAudiences,
        requested_audience: Option<&str>,
    ) -> Result<UpstreamOidcSessionGrantTarget, String>;

    #[allow(clippy::too_many_arguments, clippy::ptr_arg)]
    async fn fetch_local_oidc_userinfo(
        &self,
        http_client: &reqwest::Client,
        key_store: &coauth_keystore::Keystore,
        userinfo_endpoint: &url::Url,
        issuer: &url::Url,
        access_token: &str,
        expected_client_id: &String,
        expected_signed_alg: Option<&coauth_iana::jose::JsonWebSignatureAlg>,
    ) -> Result<(OidcUserinfoClaims, bool), String>;

    #[allow(clippy::too_many_arguments)]
    async fn exchange_federated_authorization_code(
        &self,
        http_client: &reqwest::Client,
        key_store: &Keystore,
        encrypter: &Encrypter,
        provider: &UpstreamOAuthProvider,
        issuer: &Url,
        token_endpoint: &Url,
        userinfo_endpoint: &Url,
        jwks_uri: &Url,
        authorization_code: &str,
        redirect_uri: Url,
        code_verifier: &str,
        // The `nonce` the client bound to the upstream authorization request.
        // When present it MUST equal the `nonce` claim of the upstream id_token,
        // mirroring the local-issuer nonce binding. `None`/empty disables the
        // check (the upstream provider did not issue a nonce-bound id_token).
        expected_nonce: Option<&str>,
        now: DateTime<Utc>,
        rng: &mut coauth_data::BoxRng,
    ) -> Result<FederatedOidcExchange, String>;
}

#[derive(Default)]
pub struct DefaultUpstreamOidcService;

#[async_trait]
impl UpstreamOidcService for DefaultUpstreamOidcService {
    fn exchange_mode_for_issuer(
        &self,
        url_builder: &UrlBuilder,
        providers: &[UpstreamOAuthProvider],
        issuer: &Url,
        client_id: &str,
    ) -> Result<UpstreamOidcExchangeMode, String> {
        if issuer == &url_builder.oidc_issuer() {
            return Ok(UpstreamOidcExchangeMode::LocalCoauth);
        }

        let provider = providers
            .iter()
            .filter(|provider| provider.enabled())
            .filter(|provider| provider.client_id == client_id)
            .find(|provider| {
                provider
                    .issuer
                    .as_deref()
                    .and_then(|issuer| issuer.parse::<Url>().ok())
                    .is_some_and(|provider_issuer| &provider_issuer == issuer)
            })
            .cloned()
            .ok_or_else(|| {
                format!(
                    "issuer={issuer} is neither this coauth issuer nor a configured enabled upstream OIDC provider for client_id={client_id}"
                )
            })?;

        Ok(UpstreamOidcExchangeMode::Federated { provider })
    }

    fn validate_exchange_endpoints(
        &self,
        url_builder: &UrlBuilder,
        mode: &UpstreamOidcExchangeMode,
        discovered_metadata: &VerifiedProviderMetadata,
        token_endpoint: &Url,
        userinfo_endpoint: &Url,
    ) -> Result<(), String> {
        match mode {
            UpstreamOidcExchangeMode::LocalCoauth => {
                let expected_issuer = url_builder.oidc_issuer();
                let expected_token_endpoint = url_builder.oauth_token_endpoint();
                let expected_userinfo_endpoint = url_builder.oidc_userinfo_endpoint();

                if discovered_metadata.issuer() != expected_issuer.as_str()
                    || discovered_metadata.token_endpoint() != &expected_token_endpoint
                    || discovered_metadata.userinfo_endpoint() != &expected_userinfo_endpoint
                {
                    return Err(format!(
                        "local OIDC discovery drift: discovered issuer={} token_endpoint={} userinfo_endpoint={} but expected issuer={} token_endpoint={} userinfo_endpoint={}",
                        discovered_metadata.issuer(),
                        discovered_metadata.token_endpoint(),
                        discovered_metadata.userinfo_endpoint(),
                        expected_issuer,
                        expected_token_endpoint,
                        expected_userinfo_endpoint
                    ));
                }

                if token_endpoint != &expected_token_endpoint
                    || userinfo_endpoint != &expected_userinfo_endpoint
                {
                    return Err(format!(
                        "OIDC exchange metadata does not match this coauth issuer/token/userinfo surface: expected token_endpoint={expected_token_endpoint} userinfo_endpoint={expected_userinfo_endpoint} but received token_endpoint={token_endpoint} userinfo_endpoint={userinfo_endpoint}"
                    ));
                }
            }
            UpstreamOidcExchangeMode::Federated { provider } => {
                let provider_issuer = provider
                    .issuer
                    .as_deref()
                    .ok_or_else(|| "federated upstream provider is missing issuer".to_owned())?;
                if discovered_metadata.issuer() != provider_issuer {
                    return Err(format!(
                        "federated OIDC discovery issuer mismatch: discovered issuer={} but configured issuer={}",
                        discovered_metadata.issuer(),
                        provider_issuer
                    ));
                }

                let expected_token_endpoint = provider
                    .token_endpoint_override
                    .as_ref()
                    .unwrap_or_else(|| discovered_metadata.token_endpoint());
                let expected_userinfo_endpoint = provider
                    .userinfo_endpoint_override
                    .as_ref()
                    .unwrap_or_else(|| discovered_metadata.userinfo_endpoint());

                if token_endpoint != expected_token_endpoint
                    || userinfo_endpoint != expected_userinfo_endpoint
                {
                    return Err(format!(
                        "federated OIDC endpoint binding mismatch for provider={}: expected token_endpoint={} userinfo_endpoint={} but received token_endpoint={} userinfo_endpoint={}",
                        provider
                            .human_name
                            .as_deref()
                            .unwrap_or(provider.client_id.as_str()),
                        expected_token_endpoint,
                        expected_userinfo_endpoint,
                        token_endpoint,
                        userinfo_endpoint
                    ));
                }
            }
        }

        Ok(())
    }

    async fn session_grant_target_for_requested_audience(
        &self,
        http_client: &reqwest::Client,
        url_builder: &UrlBuilder,
        arkret_config: &ArkretConfig,
        resolved: &ResolvedPrincipalAudiences,
        requested_audience: Option<&str>,
    ) -> Result<UpstreamOidcSessionGrantTarget, String> {
        // The startup warm-up may run before a configured Principal Server is
        // ready. Retry only missing/expired entries on demand so a valid OIDC
        // callback does not wait for the background refresh interval.
        resolved
            .refresh_unresolved(http_client, arkret_config)
            .await;

        if let Some(requested_audience) = requested_audience
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            for server in &arkret_config.principal_servers {
                let Some(effective) = effective_audience(server, resolved) else {
                    continue;
                };
                if effective.as_str() == requested_audience {
                    return Ok(UpstreamOidcSessionGrantTarget {
                        audience: effective.to_string(),
                        principal_server_name: Some(server.name.clone()),
                        principal_server_endpoint: Some(server.endpoint.to_string()),
                    });
                }
            }

            if arkret::is_allowed_session_grant_audience(
                url_builder,
                arkret_config,
                resolved,
                requested_audience,
            ) {
                let local_audience = arkret::required_audience_for(url_builder, arkret_config);
                return Ok(UpstreamOidcSessionGrantTarget {
                    audience: local_audience,
                    principal_server_name: None,
                    principal_server_endpoint: None,
                });
            }

            return Err(format!(
                "requested principal_audience={requested_audience} is not configured for this coauth service"
            ));
        }

        let grant_target = arkret::password_login_session_grant_target(
            url_builder,
            arkret_config,
            resolved,
            None,
        )
        .map_err(|error| {
            format!(
                "no principal_audience supplied and the deployment cannot pick a default: {error}"
            )
        })?;
        Ok(UpstreamOidcSessionGrantTarget {
            audience: grant_target.audience,
            principal_server_name: grant_target.principal_server_name,
            principal_server_endpoint: grant_target.principal_server_endpoint,
        })
    }

    async fn fetch_local_oidc_userinfo(
        &self,
        http_client: &reqwest::Client,
        key_store: &coauth_keystore::Keystore,
        userinfo_endpoint: &url::Url,
        issuer: &url::Url,
        access_token: &str,
        expected_client_id: &String,
        expected_signed_alg: Option<&coauth_iana::jose::JsonWebSignatureAlg>,
    ) -> Result<(OidcUserinfoClaims, bool), String> {
        let jwks = key_store.public_jwks();
        fetch_oidc_userinfo(
            http_client,
            userinfo_endpoint,
            issuer,
            access_token,
            expected_client_id,
            expected_signed_alg,
            Some(&jwks),
        )
        .await
    }

    async fn exchange_federated_authorization_code(
        &self,
        http_client: &reqwest::Client,
        key_store: &Keystore,
        encrypter: &Encrypter,
        provider: &UpstreamOAuthProvider,
        issuer: &Url,
        token_endpoint: &Url,
        userinfo_endpoint: &Url,
        jwks_uri: &Url,
        authorization_code: &str,
        redirect_uri: Url,
        code_verifier: &str,
        expected_nonce: Option<&str>,
        now: DateTime<Utc>,
        rng: &mut coauth_data::BoxRng,
    ) -> Result<FederatedOidcExchange, String> {
        let client_credentials = crate::handlers::upstream_oauth::client_credentials_for_provider(
            provider,
            token_endpoint,
            key_store,
            encrypter,
        )
        .map_err(|error| format!("failed to load upstream provider credentials: {error}"))?;

        let token_response = request_access_token(
            http_client,
            client_credentials,
            token_endpoint,
            AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
                code: authorization_code.to_owned(),
                redirect_uri: Some(redirect_uri),
                code_verifier: Some(code_verifier.to_owned()),
            }),
            now,
            rng,
        )
        .await
        .map_err(|error| format!("upstream token endpoint exchange failed: {error}"))?;

        let needs_jwks =
            token_response.id_token.is_some() || provider.userinfo_signed_response_alg.is_some();
        let jwks = if needs_jwks {
            Some(
                fetch_jwks(http_client, jwks_uri)
                    .await
                    .map_err(|error| format!("upstream JWKS fetch failed: {error}"))?,
            )
        } else {
            None
        };

        let mut id_token_subject = None;
        if let Some(id_token) = token_response.id_token.as_deref() {
            let jwks = jwks
                .as_ref()
                .ok_or_else(|| "upstream ID token verification requires JWKS".to_owned())?;
            let verification_data = JwtVerificationData {
                issuer: Some(issuer.as_str()),
                jwks,
                client_id: &provider.client_id,
                signing_algorithm: &provider.id_token_signed_response_alg,
            };
            let id_token = verify_id_token(id_token, verification_data, None, now)
                .map_err(|error| format!("upstream ID token verification failed: {error}"))?;
            let (_headers, mut claims) = id_token.into_parts();
            id_token_subject = claims
                .get("sub")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);

            claims::AT_HASH
                .extract_optional_with_options(
                    &mut claims,
                    TokenHash::new(
                        verification_data.signing_algorithm,
                        &token_response.access_token,
                    ),
                )
                .map_err(|error| {
                    format!("upstream ID token access-token hash validation failed: {error}")
                })?;
            claims::C_HASH
                .extract_optional_with_options(
                    &mut claims,
                    TokenHash::new(verification_data.signing_algorithm, authorization_code),
                )
                .map_err(|error| {
                    format!("upstream ID token authorization-code hash validation failed: {error}")
                })?;

            // Nonce binding: when the client bound a non-empty nonce to the
            // upstream authorization request, the upstream id_token MUST echo it
            // back. This is the federated equivalent of the local-issuer nonce
            // check and defends against id_token replay / cross-session
            // injection.
            if let Some(expected_nonce) = expected_nonce.filter(|value| !value.is_empty()) {
                claims::NONCE
                    .extract_required_with_options(&mut claims, expected_nonce)
                    .map_err(|error| format!("upstream ID token nonce binding failed: {error}"))?;
            }
        }

        let (userinfo, userinfo_response_signed) = fetch_oidc_userinfo(
            http_client,
            userinfo_endpoint,
            issuer,
            &token_response.access_token,
            &provider.client_id,
            provider.userinfo_signed_response_alg.as_ref(),
            jwks.as_ref(),
        )
        .await?;

        if userinfo.sub.trim().is_empty() {
            return Err("upstream userinfo did not contain a non-empty sub claim".to_owned());
        }

        if let Some(id_token_subject) = id_token_subject.as_deref()
            && id_token_subject != userinfo.sub
        {
            return Err(format!(
                "upstream ID token subject mismatch: id_token sub={} userinfo sub={}",
                id_token_subject, userinfo.sub
            ));
        }

        Ok(FederatedOidcExchange {
            token_response,
            userinfo,
            userinfo_response_signed,
            id_token_subject,
        })
    }
}

async fn fetch_oidc_userinfo(
    http_client: &reqwest::Client,
    userinfo_endpoint: &Url,
    issuer: &Url,
    access_token: &str,
    expected_client_id: &String,
    expected_signed_alg: Option<&coauth_iana::jose::JsonWebSignatureAlg>,
    jwks: Option<&coauth_jose::jwk::PublicJsonWebKeySet>,
) -> Result<(OidcUserinfoClaims, bool), String> {
    let response = http_client
        .get(userinfo_endpoint.clone())
        .bearer_auth(access_token)
        .send_traced()
        .await
        .map_err(|error| format!("userinfo endpoint request failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("userinfo endpoint returned error status: {error}"))?;

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();

    if content_type.starts_with("application/jwt") {
        let expected_alg = expected_signed_alg.ok_or_else(|| {
                "userinfo endpoint returned a signed JWT but the selected client does not advertise a signed userinfo response".to_owned()
            })?;
        let jwks = jwks.ok_or_else(|| {
            "userinfo endpoint returned a signed JWT but no JWKS was available".to_owned()
        })?;
        let jwt_body = response
            .text()
            .await
            .map_err(|error| format!("failed to read signed userinfo response: {error}"))?;
        let jwt = verify_signed_jwt(
            jwt_body.as_str(),
            JwtVerificationData {
                issuer: Some(issuer.as_str()),
                jwks,
                client_id: expected_client_id,
                signing_algorithm: expected_alg,
            },
        )
        .map_err(|error| format!("userinfo JWT verification failed: {error}"))?;
        let claims =
            serde_json::from_value::<OidcUserinfoClaims>(serde_json::json!(jwt.payload().clone()))
                .map_err(|error| format!("failed to decode signed userinfo claims: {error}"))?;
        return Ok((claims, true));
    }

    if expected_signed_alg.is_some() {
        return Err(
            "userinfo endpoint returned JSON but the selected client expects a signed JWT response"
                .to_owned(),
        );
    }

    let claims = response
        .json::<OidcUserinfoClaims>()
        .await
        .map_err(|error| format!("failed to decode JSON userinfo response: {error}"))?;
    Ok((claims, false))
}

#[must_use]
pub fn default_upstream_oidc_service() -> UpstreamOidcServiceHandle {
    Arc::new(DefaultUpstreamOidcService)
}

#[cfg(test)]
mod tests {
    use coauth_config::PrincipalServerConfig;
    use wiremock::MockServer;

    use super::*;

    fn principal_server_config_for(endpoint: Url) -> ArkretConfig {
        ArkretConfig {
            principal_servers: vec![PrincipalServerConfig {
                name: "soland".to_owned(),
                endpoint: endpoint.clone(),
                service_id: Some(
                    arkret_identifiers::ServiceId::new("ak:did_core:webvh:current").unwrap(),
                ),
                session_grant_introspection_bearer: None,
                embedded_webvh_registration_bearer: None,
            }],
            ..ArkretConfig::default()
        }
    }

    #[tokio::test]
    async fn oidc_target_uses_configured_principal_audience_without_describe_discovery() {
        let server = MockServer::start().await;
        let endpoint = Url::parse(&server.uri()).unwrap();
        let config = principal_server_config_for(endpoint);
        let service_id = arkret_identifiers::ServiceId::new("ak:did_core:webvh:current").unwrap();

        let resolved = ResolvedPrincipalAudiences::new();
        let url_builder = UrlBuilder::new("https://auth.example/".parse().unwrap(), None, None);
        let http_client = reqwest::Client::new();
        let target = DefaultUpstreamOidcService
            .session_grant_target_for_requested_audience(
                &http_client,
                &url_builder,
                &config,
                &resolved,
                Some(service_id.as_str()),
            )
            .await
            .unwrap();

        assert_eq!(target.audience, service_id.as_str());
    }
}
