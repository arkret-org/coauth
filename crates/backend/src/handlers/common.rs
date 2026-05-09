//! Shared infrastructure types used across all handler modules.
//!
//! This module provides the core building blocks that every API surface
//! (account, admin, OAuth 2.0, views, etc.) depends on:
//!
//! - [`DepotExt`] — typed access to shared application state
//! - [`RouteError`] — common HTTP error type
//! - [`Requester`] / [`RequestingEntity`] — authenticated caller context
//! - [`make_rng`] / [`make_clock`] — factory helpers for randomness and clocks

use std::{net::IpAddr, ops::Deref, sync::Arc};

use coauth_config::ContrixConfig;
use coauth_data::{
    BoxClock, BoxRepository, BoxRepositoryFactory, BoxRng, BrowserSession, RepositoryError,
    Session, SiteConfig, SystemClock, UrlBuilder, User,
};
use coauth_matrix::HomeserverAdmin;
use coauth_policy::PolicyFactory;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use salvo::prelude::*;
use serde::Serialize;
use ulid::Ulid;

use crate::{
    handlers::{BoundActivityTracker, Limiter, RequesterFingerprint, passwords::PasswordManager},
    salvo_utils::{SessionInfo, SessionInfoExt, cookies::CookieJar},
};

// ── Requester / Auth ───────────────────────────────────────────

/// The authenticated entity making an API request, together with
/// connection metadata (IP address, user-agent).
pub struct Requester {
    /// Who is making the request (anonymous, browser session, or OAuth 2.0
    /// session).
    pub entity: RequestingEntity,
    /// Client IP address (after trusted-proxy unwrapping).
    pub ip_address: Option<IpAddr>,
    /// Raw `User-Agent` header value.
    pub user_agent: Option<String>,
}

impl Requester {
    pub fn fingerprint(&self) -> RequesterFingerprint {
        if let Some(ip) = self.ip_address {
            RequesterFingerprint::new(ip)
        } else {
            RequesterFingerprint::EMPTY
        }
    }
}

impl Deref for Requester {
    type Target = RequestingEntity;

    fn deref(&self) -> &Self::Target {
        &self.entity
    }
}

/// Describes who is making a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RequestingEntity {
    /// No authenticated session (public/anonymous access).
    #[default]
    Anonymous,
    /// A logged-in user via a browser session cookie.
    BrowserSession(Box<BrowserSession>),
    /// An OAuth 2.0 client acting on behalf of (optionally) a user.
    OAuth2Session(Box<(Session, Option<User>)>),
}

impl RequestingEntity {
    pub fn browser_session(&self) -> Option<&BrowserSession> {
        match self {
            Self::BrowserSession(session) => Some(session),
            _ => None,
        }
    }

    pub fn user(&self) -> Option<&User> {
        match self {
            Self::BrowserSession(session) => Some(&session.user),
            Self::OAuth2Session(tuple) => tuple.1.as_ref(),
            Self::Anonymous => None,
        }
    }

    pub fn oauth2_session(&self) -> Option<&Session> {
        match self {
            Self::OAuth2Session(tuple) => Some(&tuple.0),
            _ => None,
        }
    }

    pub fn is_owner_or_admin(&self, owner_id: Option<Ulid>) -> bool {
        if self.is_admin() {
            return true;
        }
        let Some(owner_id) = owner_id else {
            return false;
        };
        let Some(user) = self.user() else {
            return false;
        };
        user.id == owner_id
    }

    pub fn is_admin(&self) -> bool {
        match self {
            Self::OAuth2Session(tuple) => crate::handlers::admin::has_admin_scope(&tuple.0.scope),
            _ => false,
        }
    }

    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, Self::Anonymous)
    }
}

impl From<BrowserSession> for RequestingEntity {
    fn from(session: BrowserSession) -> Self {
        Self::BrowserSession(Box::new(session))
    }
}

impl<T> From<Option<T>> for RequestingEntity
where
    T: Into<RequestingEntity>,
{
    fn from(session: Option<T>) -> Self {
        session.map(Into::into).unwrap_or_default()
    }
}

// ── Error type ─────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Loading of some database objects failed")]
    LoadFailed,

    #[error("Invalid access token")]
    InvalidToken,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not found")]
    NotFound,

    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl_from_error_for_route!(self::RouteError: RepositoryError);

impl Scribe for RouteError {
    fn render(self, res: &mut Response) {
        match self {
            Self::Internal(_) | Self::LoadFailed => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({"error": "internal_error"})));
            }
            Self::InvalidToken => {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(serde_json::json!({"error": "invalid_token"})));
            }
            Self::Unauthorized => {
                res.status_code(StatusCode::FORBIDDEN);
                res.render(Json(serde_json::json!({"error": "unauthorized"})));
            }
            Self::NotFound => {
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Json(serde_json::json!({"error": "not_found"})));
            }
            Self::BadRequest(msg) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({"error": msg})));
            }
        }
    }
}

impl salvo::oapi::EndpointOutRegister for RouteError {
    fn register(
        _components: &mut salvo::oapi::Components,
        _operation: &mut salvo::oapi::Operation,
    ) {
        use salvo::oapi::*;

        let error_schema = Object::new()
            .property("error", Object::new().schema_type(BasicType::String))
            .required("error");

        for (status, desc) in [
            ("400", "Bad request"),
            ("401", "Invalid or missing access token"),
            ("403", "Unauthorized"),
            ("404", "Resource not found"),
            ("500", "Internal server error"),
        ] {
            let response = Response::new(desc)
                .add_content("application/json", Content::new(error_schema.clone()));
            _operation
                .responses
                .insert(status, salvo::oapi::RefOr::Type(response));
        }
    }
}

// ── Depot helpers ──────────────────────────────────────────────

/// Extension trait for [`Depot`] that provides typed access to shared state
/// injected by the server setup.
pub trait DepotExt {
    fn repo_factory(&self) -> Result<&BoxRepositoryFactory, RouteError>;
    /// Convenience shortcut for `self.repo_factory()?.create().await?` which is
    /// repeated in 40+ handler files.
    fn repo(&self) -> impl std::future::Future<Output = Result<BoxRepository, RouteError>> + Send;
    fn site_config(&self) -> Result<SiteConfig, RouteError>;
    fn homeserver(&self) -> Result<Arc<dyn HomeserverAdmin>, RouteError>;
    fn policy_factory(&self) -> Result<Arc<PolicyFactory>, RouteError>;
    fn password_manager(&self) -> Result<PasswordManager, RouteError>;
    fn url_builder(&self) -> Result<UrlBuilder, RouteError>;
    fn limiter(&self) -> Result<Limiter, RouteError>;
    fn templates(&self) -> Result<coauth_templates::Templates, RouteError>;
    fn frontend_script_src(&self) -> Result<String, RouteError>;
    fn translator(&self) -> Result<Arc<coauth_i18n::Translator>, RouteError>;
    fn contrix_config(&self) -> Result<ContrixConfig, RouteError>;
    fn cookie_manager(&self) -> Result<crate::handlers::CookieManager, RouteError>;
    fn metadata_cache(&self) -> Result<crate::handlers::MetadataCache, RouteError>;
    fn http_client(&self) -> Result<reqwest::Client, RouteError>;
    fn encrypter(&self) -> Result<coauth_keystore::Encrypter, RouteError>;
    fn key_store(&self) -> Result<coauth_keystore::Keystore, RouteError>;
    fn app_version(&self) -> Result<coauth_data::AppVersion, RouteError>;
    fn risk_action_state_service(
        &self,
    ) -> Result<crate::services::risk_action_state::RiskActionStateServiceHandle, RouteError>;
    fn risk_action_proposals_service(
        &self,
    ) -> Result<
        crate::services::risk_action_proposals::RiskActionProposalsServiceHandle,
        RouteError,
    >;
    fn principal_cache_service(
        &self,
    ) -> Result<crate::services::principal_cache::PrincipalCacheServiceHandle, RouteError>;
    fn account_claims_service(
        &self,
    ) -> Result<crate::services::account_claims::AccountClaimsServiceHandle, RouteError>;
    fn invite_quarantine_service(
        &self,
    ) -> Result<crate::services::invite_quarantine::InviteQuarantineServiceHandle, RouteError>;
    fn upstream_oidc_service(
        &self,
    ) -> Result<crate::services::upstream_oidc::UpstreamOidcServiceHandle, RouteError>;
    fn did_resolver_service(
        &self,
    ) -> Result<crate::services::did_resolver::DidResolverServiceHandle, RouteError>;
    fn webauthn_service(
        &self,
    ) -> Result<crate::services::webauthn::WebauthnServiceHandle, RouteError>;
    fn cookie_jar(&self, req: &Request) -> Result<CookieJar, RouteError>;
}

fn depot_get<T: Send + Sync + Clone + 'static>(depot: &Depot, key: &str) -> Result<T, RouteError> {
    depot.get::<T>(key).cloned().map_err(|_| {
        RouteError::Internal(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{key} not found in depot"),
        )))
    })
}

impl DepotExt for Depot {
    fn repo_factory(&self) -> Result<&BoxRepositoryFactory, RouteError> {
        self.get::<BoxRepositoryFactory>("box_repository_factory")
            .map_err(|_| {
                RouteError::Internal(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "box_repository_factory not found in depot",
                )))
            })
    }

    async fn repo(&self) -> Result<BoxRepository, RouteError> {
        let factory = self.repo_factory()?;
        factory
            .create()
            .await
            .map_err(|e| RouteError::Internal(Box::new(e)))
    }

    fn site_config(&self) -> Result<SiteConfig, RouteError> {
        depot_get(self, "site_config")
    }

    fn homeserver(&self) -> Result<Arc<dyn HomeserverAdmin>, RouteError> {
        depot_get(self, "homeserver_admin")
    }

    fn policy_factory(&self) -> Result<Arc<PolicyFactory>, RouteError> {
        depot_get(self, "policy_factory")
    }

    fn password_manager(&self) -> Result<PasswordManager, RouteError> {
        depot_get(self, "password_manager")
    }

    fn url_builder(&self) -> Result<UrlBuilder, RouteError> {
        depot_get(self, "url_builder")
    }

    fn limiter(&self) -> Result<Limiter, RouteError> {
        depot_get(self, "limiter")
    }

    fn templates(&self) -> Result<coauth_templates::Templates, RouteError> {
        depot_get(self, "templates")
    }

    fn frontend_script_src(&self) -> Result<String, RouteError> {
        depot_get(self, "frontend_script_src")
    }

    fn translator(&self) -> Result<Arc<coauth_i18n::Translator>, RouteError> {
        depot_get(self, "translator")
    }

    fn contrix_config(&self) -> Result<ContrixConfig, RouteError> {
        depot_get(self, "contrix_config")
    }

    fn cookie_manager(&self) -> Result<crate::handlers::CookieManager, RouteError> {
        depot_get(self, "cookie_manager")
    }

    fn metadata_cache(&self) -> Result<crate::handlers::MetadataCache, RouteError> {
        depot_get(self, "metadata_cache")
    }

    fn http_client(&self) -> Result<reqwest::Client, RouteError> {
        depot_get(self, "http_client")
    }

    fn encrypter(&self) -> Result<coauth_keystore::Encrypter, RouteError> {
        depot_get(self, "encrypter")
    }

    fn key_store(&self) -> Result<coauth_keystore::Keystore, RouteError> {
        depot_get(self, "keystore")
    }

    fn app_version(&self) -> Result<coauth_data::AppVersion, RouteError> {
        depot_get(self, "app_version")
    }

    fn risk_action_state_service(
        &self,
    ) -> Result<crate::services::risk_action_state::RiskActionStateServiceHandle, RouteError> {
        depot_get(self, "risk_action_state_service")
    }

    fn risk_action_proposals_service(
        &self,
    ) -> Result<
        crate::services::risk_action_proposals::RiskActionProposalsServiceHandle,
        RouteError,
    > {
        depot_get(self, "risk_action_proposals_service")
    }

    fn principal_cache_service(
        &self,
    ) -> Result<crate::services::principal_cache::PrincipalCacheServiceHandle, RouteError> {
        depot_get(self, "principal_cache_service")
    }

    fn account_claims_service(
        &self,
    ) -> Result<crate::services::account_claims::AccountClaimsServiceHandle, RouteError> {
        depot_get(self, "account_claims_service")
    }

    fn invite_quarantine_service(
        &self,
    ) -> Result<crate::services::invite_quarantine::InviteQuarantineServiceHandle, RouteError> {
        depot_get(self, "invite_quarantine_service")
    }

    fn upstream_oidc_service(
        &self,
    ) -> Result<crate::services::upstream_oidc::UpstreamOidcServiceHandle, RouteError> {
        depot_get(self, "upstream_oidc_service")
    }

    fn did_resolver_service(
        &self,
    ) -> Result<crate::services::did_resolver::DidResolverServiceHandle, RouteError> {
        depot_get(self, "did_resolver_service")
    }

    fn webauthn_service(
        &self,
    ) -> Result<crate::services::webauthn::WebauthnServiceHandle, RouteError> {
        depot_get(self, "webauthn_service")
    }

    fn cookie_jar(&self, req: &Request) -> Result<CookieJar, RouteError> {
        let cm = self.cookie_manager()?;
        Ok(cm.cookie_jar_from_request(req.cookies()))
    }
}

pub fn make_clock() -> BoxClock {
    Box::new(SystemClock::default())
}

pub fn make_rng() -> BoxRng {
    let rng = ChaChaRng::from_rng(rand_core::OsRng).expect("Failed to seed rng");
    Box::new(rng)
}

// ── User-agent parsing helper ──────────────────────────────────

#[derive(Serialize, Clone, salvo::oapi::ToSchema)]
pub struct UserAgentInfo {
    pub name: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub device_type: &'static str,
}

pub fn parse_user_agent(ua: &str) -> UserAgentInfo {
    let parsed = woothee::parser::Parser::new().parse(ua);
    let (name, os, category) = match parsed {
        Some(result) => (
            if result.name != "UNKNOWN" {
                Some(result.name.to_owned())
            } else {
                None
            },
            if result.os != "UNKNOWN" {
                Some(result.os.to_owned())
            } else {
                None
            },
            result.category,
        ),
        None => (None, None, "UNKNOWN"),
    };

    let device_type = match category {
        "pc" => "PC",
        "smartphone" | "mobilephone" => "MOBILE",
        _ => "UNKNOWN",
    };

    UserAgentInfo {
        name,
        model: None,
        os,
        device_type,
    }
}

// ── Activity tracker extraction ────────────────────────────────

pub fn extract_bound_activity_tracker(req: &Request, depot: &Depot) -> BoundActivityTracker {
    let activity_tracker = depot
        .get::<crate::handlers::ActivityTracker>("activity_tracker")
        .expect("ActivityTracker not found in depot")
        .clone();

    let trusted_proxies = depot
        .get::<Vec<ipnetwork::IpNetwork>>("trusted_proxies")
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    let ip = infer_client_ip(req, trusted_proxies);
    activity_tracker.bind(ip)
}

fn infer_client_ip(req: &Request, trusted_proxies: &[ipnetwork::IpNetwork]) -> Option<IpAddr> {
    let peers_from_header = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').filter_map(|v| v.trim().parse().ok()))
        .into_iter()
        .flatten();

    let peer_list: Vec<IpAddr> = peers_from_header
        .map(|ip: IpAddr| ip.to_canonical())
        .collect();

    let fallback = peer_list.first().copied();

    let client_ip = peer_list
        .iter()
        .rfind(|ip| !trusted_proxies.iter().any(|network| network.contains(**ip)))
        .copied();

    client_ip.or(fallback)
}

// ── Cookie jar extraction helper ───────────────────────────────

pub fn extract_session_info(req: &Request, depot: &Depot) -> SessionInfo {
    let Ok(cookie_jar) = CookieJar::extract_from_request(req, depot) else {
        return SessionInfo::default();
    };
    let (session_info, _) = cookie_jar.session_info();
    session_info
}
