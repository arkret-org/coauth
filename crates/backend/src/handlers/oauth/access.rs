use std::{net::IpAddr, time::Duration};

use coauth_config::CokretConfig;
use coauth_data::{
    AuthorizationGrant, AuthorizationGrantStage, BoxClock, BoxRepository, BoxRng, BrowserSession,
    Client, Clock, PrincipalUser, RepositoryAccess, RepositoryError, Session, UrlBuilder,
    oauth::{
        OAuthAuthorizationGrantRepository, OAuthClientRepository, OAuthDeviceCodeGrantRepository,
        OAuthSessionRepository,
    },
    user::BrowserSessionRepository,
};
use coauth_keystore::Keystore;
use coauth_policy::{Policy, PolicyFactory};
use coauth_principal::PrincipalServerAdmin;
use oauth_types::requests::AuthorizationResponse;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::{
    oauth::{authorization::callback::CallbackDestination, generate_id_token},
    session::count_user_sessions_for_limiting,
};

/// Rich consent information carrying the full domain objects.
///
/// This is returned by [`load_authorization_consent`] and contains everything
/// both the HTML (server-rendered) and REST (JSON) handlers need to present the
/// consent screen.
pub struct AuthorizationConsentInfo {
    pub grant: AuthorizationGrant,
    pub client: Client,
    pub principal_user: PrincipalUser,
    pub policy_violation: bool,
}

/// Simplified projection used by the REST API consent endpoints.
pub struct ConsentScreen {
    pub grant_id: Ulid,
    pub client: Client,
    pub scope: String,
    pub user_principal_id: String,
    pub user_display_name: Option<String>,
    pub policy_violation: bool,
}

impl From<AuthorizationConsentInfo> for ConsentScreen {
    fn from(info: AuthorizationConsentInfo) -> Self {
        Self {
            grant_id: info.grant.id,
            scope: info.grant.scope.to_string(),
            client: info.client,
            user_principal_id: info.principal_user.principal_id,
            user_display_name: info.principal_user.display_name,
            policy_violation: info.policy_violation,
        }
    }
}

/// Result of accepting an authorization consent.
///
/// Carries the fulfilled session along with the data needed by the caller to
/// build a callback response (HTML redirect / form-post or JSON URL).
pub struct AuthorizationConsentDecision {
    pub session: Session,
    pub callback_destination: CallbackDestination,
    pub params: AuthorizationResponse,
}

impl AuthorizationConsentDecision {
    /// Build the redirect URL string for JSON API responses.
    pub fn redirect_url(&self) -> Result<String, OAuthAccessError> {
        self.callback_destination
            .redirect_url(&self.params)
            .map(|info| info.url)
            .map_err(|error| OAuthAccessError::Internal(Box::new(error)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceConsentAction {
    Consent,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceConsentStatus {
    Fulfilled,
    Rejected,
}

#[derive(Debug, Error)]
pub enum OAuthAccessError {
    #[error("not found")]
    NotFound,

    #[error("authorization grant is not pending")]
    GrantNotPending,

    #[error("device grant is expired")]
    GrantExpired,

    #[error("policy violation")]
    PolicyViolation,

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

pub async fn load_authorization_consent(
    mut repo: BoxRepository,
    policy_factory: &PolicyFactory,
    principal_server: &dyn PrincipalServerAdmin,
    _clock: &dyn Clock,
    browser_session: &BrowserSession,
    grant_id: Ulid,
    requester_ip: Option<IpAddr>,
    user_agent: Option<String>,
) -> Result<AuthorizationConsentInfo, OAuthAccessError> {
    let grant = repo
        .oauth_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(OAuthAccessError::GrantNotPending);
    }

    let client = repo
        .oauth_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    let policy_violation = has_policy_violation(
        &mut repo,
        policy_factory,
        browser_session,
        &client,
        &grant.scope,
        coauth_policy::GrantType::AuthorizationCode,
        requester_ip,
        user_agent,
    )
    .await?;

    repo.cancel().await?;

    let username = &browser_session.user.handle;
    let user_display_name = fetch_display_name(principal_server, username).await;

    Ok(AuthorizationConsentInfo {
        grant,
        client,
        principal_user: PrincipalUser {
            principal_id: principal_server.principal_id(username),
            display_name: user_display_name,
        },
        policy_violation,
    })
}

pub async fn accept_authorization_consent(
    mut repo: BoxRepository,
    rng: &mut BoxRng,
    clock: &BoxClock,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    policy_factory: &PolicyFactory,
    browser_session: &BrowserSession,
    grant_id: Ulid,
    requester_ip: Option<IpAddr>,
    user_agent: Option<String>,
) -> Result<AuthorizationConsentDecision, OAuthAccessError> {
    let grant = repo
        .oauth_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    let callback_destination = CallbackDestination::try_from(&grant)
        .map_err(|error| OAuthAccessError::Internal(Box::new(error)))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(OAuthAccessError::GrantNotPending);
    }

    let client = repo
        .oauth_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    if has_policy_violation(
        &mut repo,
        policy_factory,
        browser_session,
        &client,
        &grant.scope,
        coauth_policy::GrantType::AuthorizationCode,
        requester_ip,
        user_agent,
    )
    .await?
    {
        return Err(OAuthAccessError::PolicyViolation);
    }

    let session = repo
        .oauth_session()
        .add_from_browser_session(rng, clock, &client, browser_session, grant.scope.clone())
        .await?;

    let grant = repo
        .oauth_authorization_grant()
        .fulfill(clock, &session, grant)
        .await?;

    let mut params = AuthorizationResponse::default();

    if grant.response_type_id_token {
        let last_authentication = repo
            .browser_session()
            .get_last_authentication(browser_session)
            .await?;

        params.id_token = Some(
            generate_id_token(
                rng,
                clock,
                url_builder,
                cokret_config,
                key_store,
                &client,
                Some(&grant),
                Some(&session),
                browser_session,
                None,
                last_authentication.as_ref(),
            )
            .map_err(|error| OAuthAccessError::Internal(Box::new(error)))?,
        );
    }

    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    repo.save().await?;

    Ok(AuthorizationConsentDecision {
        session,
        callback_destination,
        params,
    })
}

pub async fn lookup_device_link(
    mut repo: BoxRepository,
    clock: &dyn Clock,
    code: &str,
) -> Result<Option<Ulid>, OAuthAccessError> {
    let grant = repo
        .oauth_device_code_grant()
        .find_by_user_code(code)
        .await?
        .filter(|grant| grant.is_pending())
        .filter(|grant| grant.expires_at > clock.now());

    repo.cancel().await?;

    Ok(grant.map(|grant| grant.id))
}

pub async fn load_device_consent(
    mut repo: BoxRepository,
    policy_factory: &PolicyFactory,
    principal_server: &dyn PrincipalServerAdmin,
    clock: &dyn Clock,
    browser_session: &BrowserSession,
    grant_id: Ulid,
    requester_ip: Option<IpAddr>,
    user_agent: Option<String>,
) -> Result<ConsentScreen, OAuthAccessError> {
    let grant = repo
        .oauth_device_code_grant()
        .lookup(grant_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    if grant.expires_at < clock.now() {
        return Err(OAuthAccessError::GrantExpired);
    }

    let client = repo
        .oauth_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    let policy_violation = has_policy_violation(
        &mut repo,
        policy_factory,
        browser_session,
        &client,
        &grant.scope,
        coauth_policy::GrantType::DeviceCode,
        requester_ip,
        user_agent,
    )
    .await?;

    repo.cancel().await?;

    let username = &browser_session.user.handle;
    let user_display_name = fetch_display_name(principal_server, username).await;

    Ok(ConsentScreen {
        grant_id: grant.id,
        client,
        scope: grant.scope.to_string(),
        user_principal_id: principal_server.principal_id(username),
        user_display_name,
        policy_violation,
    })
}

pub async fn submit_device_consent(
    mut repo: BoxRepository,
    policy_factory: &PolicyFactory,
    clock: &dyn Clock,
    browser_session: &BrowserSession,
    grant_id: Ulid,
    action: DeviceConsentAction,
    requester_ip: Option<IpAddr>,
    user_agent: Option<String>,
) -> Result<DeviceConsentStatus, OAuthAccessError> {
    let grant = repo
        .oauth_device_code_grant()
        .lookup(grant_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    if grant.expires_at < clock.now() {
        return Err(OAuthAccessError::GrantExpired);
    }

    let client = repo
        .oauth_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(OAuthAccessError::NotFound)?;

    if has_policy_violation(
        &mut repo,
        policy_factory,
        browser_session,
        &client,
        &grant.scope,
        coauth_policy::GrantType::DeviceCode,
        requester_ip,
        user_agent,
    )
    .await?
    {
        return Err(OAuthAccessError::PolicyViolation);
    }

    let status = if grant.is_pending() {
        match action {
            DeviceConsentAction::Consent => {
                repo.oauth_device_code_grant()
                    .fulfill(clock, grant, browser_session)
                    .await?;
                DeviceConsentStatus::Fulfilled
            }
            DeviceConsentAction::Reject => {
                repo.oauth_device_code_grant()
                    .reject(clock, grant, browser_session)
                    .await?;
                DeviceConsentStatus::Rejected
            }
        }
    } else if grant.is_rejected() {
        DeviceConsentStatus::Rejected
    } else {
        DeviceConsentStatus::Fulfilled
    };

    repo.save().await?;

    Ok(status)
}

async fn has_policy_violation(
    repo: &mut BoxRepository,
    policy_factory: &PolicyFactory,
    browser_session: &BrowserSession,
    client: &Client,
    scope: &oauth_types::scope::Scope,
    grant_type: coauth_policy::GrantType,
    requester_ip: Option<IpAddr>,
    user_agent: Option<String>,
) -> Result<bool, OAuthAccessError> {
    let mut policy: Policy = policy_factory
        .instantiate()
        .await
        .map_err(|error| OAuthAccessError::Internal(Box::new(error)))?;

    let session_counts = count_user_sessions_for_limiting(repo, &browser_session.user).await?;

    let eval_result = policy
        .evaluate_authorization_grant(coauth_policy::AuthorizationGrantInput {
            user: Some(&browser_session.user),
            client,
            session_counts: Some(session_counts),
            scope,
            grant_type,
            requester: coauth_policy::Requester {
                ip_address: requester_ip,
                user_agent,
                ..Default::default()
            },
        })
        .await
        .map_err(|error| OAuthAccessError::Internal(Box::new(error)))?;

    Ok(!eval_result.valid())
}

async fn fetch_display_name(
    principal_server: &dyn PrincipalServerAdmin,
    username: &str,
) -> Option<String> {
    match tokio::time::timeout(
        Duration::from_secs(1),
        principal_server.query_user(username),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                username,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(username, "Timed out while querying user");
            None
        }
    }
}
