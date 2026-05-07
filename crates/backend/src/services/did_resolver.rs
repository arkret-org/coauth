use std::sync::Arc;

use async_trait::async_trait;
use coauth_config::ContrixConfig;
use coauth_data::{BoxRepository, RepositoryAccess, UrlBuilder, User};
use coauth_keystore::Keystore;
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

use crate::handlers::contrix::{
    DidDocument, DidService, SessionGrantError, VerificationMethod, issuer_did_for,
    service_did_for, user_did_for,
};

pub type DidResolverServiceHandle = Arc<dyn DidResolverService>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidResolutionSource {
    LocalService,
    LocalUser,
    DidWeb,
    DidPlc,
    DidKey,
    DelegatedResolver,
}

impl DidResolutionSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalService => "local_service",
            Self::LocalUser => "local_user",
            Self::DidWeb => "did_web",
            Self::DidPlc => "did_plc",
            Self::DidKey => "did_key",
            Self::DelegatedResolver => "delegated_resolver",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DidResolution {
    pub document: DidDocument,
    pub source: DidResolutionSource,
    pub verified_local_binding: bool,
    pub method_evidence: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DidBindingVerification {
    Verified,
    Mismatch,
}

#[derive(Debug, Error)]
pub enum DidResolveError {
    #[error("DID not found")]
    NotFound,

    #[error("unsupported DID method")]
    UnsupportedMethod,

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("DID document id mismatch: expected {expected}, got {actual}")]
    DocumentIdMismatch { expected: String, actual: String },

    #[error("DID document request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("DID resolver URL error: {0}")]
    Url(#[from] url::ParseError),

    #[error("DID document JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("repository error: {0}")]
    Repository(#[from] coauth_data::RepositoryError),

    #[error("local DID document error: {0}")]
    LocalDocument(#[from] SessionGrantError),
}

#[async_trait]
pub trait DidResolverService: Send + Sync {
    fn service_did(&self, url_builder: &UrlBuilder, contrix_config: &ContrixConfig) -> String;
    fn issuer_did(&self, url_builder: &UrlBuilder, contrix_config: &ContrixConfig) -> String;
    fn user_did(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        user: &User,
    ) -> String;
    fn parse_local_user_did(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        did: &str,
    ) -> Option<Ulid>;
    fn primary_did_for_user(&self, user: &User) -> String;
    fn delegated_resolver(&self, contrix_config: &ContrixConfig) -> Option<String>;
    fn proof_required_for_pairwise(&self, contrix_config: &ContrixConfig) -> bool;
    fn service_did_document(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        key_store: &Keystore,
    ) -> Result<DidDocument, SessionGrantError>;
    fn user_did_document(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        user: &User,
    ) -> DidDocument;
    fn verify_user_binding(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        user: &User,
        did: &str,
    ) -> DidBindingVerification;

    async fn resolve_did_document(
        &self,
        http_client: &reqwest::Client,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        key_store: &Keystore,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError>;
}

#[derive(Default)]
pub struct DefaultDidResolverService;

#[async_trait]
impl DidResolverService for DefaultDidResolverService {
    fn service_did(&self, url_builder: &UrlBuilder, contrix_config: &ContrixConfig) -> String {
        service_did_for(url_builder, contrix_config)
    }

    fn issuer_did(&self, url_builder: &UrlBuilder, contrix_config: &ContrixConfig) -> String {
        issuer_did_for(url_builder, contrix_config)
    }

    fn user_did(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        user: &User,
    ) -> String {
        user_did_for(url_builder, contrix_config, user)
    }

    fn parse_local_user_did(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        did: &str,
    ) -> Option<Ulid> {
        let prefix = format!("{}:users:", self.service_did(url_builder, contrix_config));
        did.strip_prefix(&prefix)?.parse::<Ulid>().ok()
    }

    fn primary_did_for_user(&self, user: &User) -> String {
        format!(
            "did:web:coauth.invalid:accounts:{}",
            binding_slug(&user.id.to_string())
        )
    }

    fn delegated_resolver(&self, contrix_config: &ContrixConfig) -> Option<String> {
        contrix_config
            .identity_registry
            .as_ref()
            .map(|registry| registry.resolver.to_string())
    }

    fn proof_required_for_pairwise(&self, contrix_config: &ContrixConfig) -> bool {
        contrix_config
            .identity_registry
            .as_ref()
            .is_some_and(|registry| registry.proof_required_for_pairwise)
    }

    fn service_did_document(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        key_store: &Keystore,
    ) -> Result<DidDocument, SessionGrantError> {
        let did = self.service_did(url_builder, contrix_config);
        let mut verification_method = Vec::new();
        let mut authentication = Vec::new();
        let mut assertion_method = Vec::new();

        if let Some(public_key) = crate::handlers::contrix::preferred_public_signing_key(key_store)
        {
            let key_id = format!("{did}#key-1");
            verification_method.push(VerificationMethod {
                id: key_id.clone(),
                kind: "JsonWebKey2020".to_owned(),
                controller: did.clone(),
                public_key_jwk: public_key,
            });
            authentication.push(key_id.clone());
            assertion_method.push(key_id);
        }

        Ok(DidDocument {
            id: did.clone(),
            also_known_as: Vec::new(),
            verification_method,
            authentication,
            assertion_method,
            service: vec![
                DidService {
                    id: format!("{did}#auth-server"),
                    kind: "ContrixAuthServer".to_owned(),
                    service_endpoint: url_builder
                        .absolute_url("/api/v1/server/describe")
                        .to_string(),
                },
                DidService {
                    id: format!("{did}#openid-configuration"),
                    kind: "OpenIdConnectConfiguration".to_owned(),
                    service_endpoint: url_builder.oidc_discovery().to_string(),
                },
            ],
        })
    }

    fn user_did_document(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        user: &User,
    ) -> DidDocument {
        let did = self.user_did(url_builder, contrix_config, user);

        DidDocument {
            id: did.clone(),
            also_known_as: vec![format!(
                "contrix://{}",
                crate::handlers::contrix::user_handle(url_builder, user)
            )],
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            service: vec![DidService {
                id: format!("{did}#auth-server"),
                kind: "ContrixAuthServer".to_owned(),
                service_endpoint: url_builder
                    .absolute_url("/api/v1/server/describe")
                    .to_string(),
            }],
        }
    }

    fn verify_user_binding(
        &self,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        user: &User,
        did: &str,
    ) -> DidBindingVerification {
        if self.user_did(url_builder, contrix_config, user) == did {
            DidBindingVerification::Verified
        } else {
            DidBindingVerification::Mismatch
        }
    }

    async fn resolve_did_document(
        &self,
        http_client: &reqwest::Client,
        url_builder: &UrlBuilder,
        contrix_config: &ContrixConfig,
        key_store: &Keystore,
        repo: &mut BoxRepository,
        did: &str,
    ) -> Result<DidResolution, DidResolveError> {
        if did == self.service_did(url_builder, contrix_config) {
            return Ok(local_resolution(
                self.service_did_document(url_builder, contrix_config, key_store)?,
                DidResolutionSource::LocalService,
                true,
            ));
        }

        if let Some(user_id) = self.parse_local_user_did(url_builder, contrix_config, did) {
            let Some(user) = repo.user().lookup(user_id).await? else {
                return Err(DidResolveError::NotFound);
            };
            return Ok(local_resolution(
                self.user_did_document(url_builder, contrix_config, &user),
                DidResolutionSource::LocalUser,
                true,
            ));
        }

        match did_method(did).as_deref() {
            Some("web") => {
                resolve_http_did(
                    http_client,
                    did,
                    did_web_document_url(did)?,
                    DidResolutionSource::DidWeb,
                )
                .await
            }
            Some("plc") => {
                resolve_http_did(
                    http_client,
                    did,
                    did_plc_document_url(did)?,
                    DidResolutionSource::DidPlc,
                )
                .await
            }
            Some("key") => Ok(local_resolution(
                DidDocument {
                    id: did.to_owned(),
                    also_known_as: Vec::new(),
                    verification_method: Vec::new(),
                    authentication: Vec::new(),
                    assertion_method: Vec::new(),
                    service: Vec::new(),
                },
                DidResolutionSource::DidKey,
                false,
            )),
            Some(_) => match self.delegated_resolver(contrix_config) {
                Some(resolver) => {
                    let url = delegated_resolver_url(&resolver, did)?;
                    resolve_http_did(
                        http_client,
                        did,
                        url,
                        DidResolutionSource::DelegatedResolver,
                    )
                    .await
                }
                None => Err(DidResolveError::UnsupportedMethod),
            },
            None => Err(DidResolveError::InvalidDid(did.to_owned())),
        }
    }
}

pub fn default_did_resolver_service() -> DidResolverServiceHandle {
    Arc::new(DefaultDidResolverService)
}

fn local_resolution(
    document: DidDocument,
    source: DidResolutionSource,
    verified_local_binding: bool,
) -> DidResolution {
    DidResolution {
        document,
        source,
        verified_local_binding,
        method_evidence: serde_json::json!({
            "resolver": source.as_str(),
            "verified_local_binding": verified_local_binding,
        }),
    }
}

async fn resolve_http_did(
    http_client: &reqwest::Client,
    did: &str,
    url: Url,
    source: DidResolutionSource,
) -> Result<DidResolution, DidResolveError> {
    let body = http_client
        .get(url.clone())
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    let document_value = body
        .get("didDocument")
        .cloned()
        .unwrap_or_else(|| body.clone());
    let document = serde_json::from_value::<DidDocument>(document_value)?;
    if document.id != did {
        return Err(DidResolveError::DocumentIdMismatch {
            expected: did.to_owned(),
            actual: document.id,
        });
    }

    Ok(DidResolution {
        document,
        source,
        verified_local_binding: false,
        method_evidence: serde_json::json!({
            "resolver": source.as_str(),
            "document_url": url,
        }),
    })
}

fn delegated_resolver_url(resolver: &str, did: &str) -> Result<Url, DidResolveError> {
    let mut url = Url::parse(resolver)?;
    url.query_pairs_mut().append_pair("did", did);
    Ok(url)
}

fn did_method(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:")?;
    let (method, _method_id) = rest.split_once(':')?;
    (!method.is_empty()).then(|| method.to_ascii_lowercase())
}

fn did_web_document_url(did: &str) -> Result<Url, DidResolveError> {
    let method_id = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidResolveError::InvalidDid(did.to_owned()))?;
    let mut parts = method_id.split(':');
    let host = parts
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| DidResolveError::InvalidDid(did.to_owned()))?
        .replace("%3A", ":")
        .replace("%3a", ":");
    let path: Vec<&str> = parts.filter(|part| !part.is_empty()).collect();
    let url = if path.is_empty() {
        format!("https://{host}/.well-known/did.json")
    } else {
        format!("https://{}/{}/did.json", host, path.join("/"))
    };
    Ok(Url::parse(&url)?)
}

fn did_plc_document_url(did: &str) -> Result<Url, DidResolveError> {
    let method_id = did
        .strip_prefix("did:plc:")
        .ok_or_else(|| DidResolveError::InvalidDid(did.to_owned()))?;
    if method_id.is_empty() || method_id.contains(':') {
        return Err(DidResolveError::InvalidDid(did.to_owned()));
    }
    Ok(Url::parse(&format!("https://plc.directory/{did}"))?)
}

fn binding_slug(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}
