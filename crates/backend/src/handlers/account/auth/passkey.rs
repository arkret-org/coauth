//! Self-serve passkey registration, authentication, and lifecycle endpoints.
//!
//! Registration and lifecycle operations derive the account from the active
//! browser session. Authentication completion derives the account from the
//! single-use, server-side ceremony; caller-supplied account hints are never
//! trusted at finish time.

use chrono::Duration;
use coauth_account_types::passkey::{
    PasskeyAccountHint, PasskeyAuthFinishOutcome, PasskeyAuthFinishRequestBody,
    PasskeyAuthStartOutcome, PasskeyListOutcome, PasskeyMutationOutcome,
    PasskeyRegisterFinishOutcome, PasskeyRegisterFinishRequestBody, PasskeyRegisterStartOutcome,
    PasskeyRegisterStartRequestBody, PasskeyRenameRequestBody, PasskeySummary,
};
use coauth_data::audit::{NewAccountSecurityEvent, SecurityEventType};
use coauth_data::user::BrowserSessionRepository;
use coauth_data::{
    Authentication, AuthenticationMethod, BoxRepository, Clock, RepositoryAccess, User,
};
use salvo::prelude::*;
use ulid::Ulid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::handlers::RequesterFingerprint;
use crate::handlers::account::{
    extract_bound_activity_tracker, extract_session_info, make_clock, make_rng,
};
use crate::handlers::common::DepotExt;
use crate::salvo_utils::cookies::CookieExpiration;
use crate::salvo_utils::session::SessionInfoExt;
use crate::services::webauthn::WebauthnError;
use crate::{AppError, JsonResult};

const BROWSER_BINDING_COOKIE: &str = "coauth-passkey-browser-binding";
const RECENT_AUTH_MAX_AGE: Duration = Duration::minutes(10);

fn map_webauthn_error(err: WebauthnError) -> AppError {
    match err {
        WebauthnError::NoChallenge(_) | WebauthnError::NoCredentials(_) => {
            AppError::bad_request("passkey_ceremony_invalid")
        }
        WebauthnError::CredentialNotFound(id) => {
            AppError::not_found(format!("Passkey {id} not found"))
        }
        WebauthnError::InvalidLabel => AppError::bad_request("passkey_label_too_long"),
        WebauthnError::LastCredential => AppError::conflict("cannot revoke the last passkey"),
        WebauthnError::InvalidOrigin(_) => AppError::bad_request("webauthn_rp_misconfigured"),
        WebauthnError::Core(_) => AppError::bad_request("passkey_verification_failed"),
        WebauthnError::UserVerificationRequired => {
            AppError::bad_request("passkey_user_verification_required")
        }
        WebauthnError::CounterConflict => AppError::bad_request("passkey_counter_conflict"),
        WebauthnError::Serde(_) | WebauthnError::Storage(_) => AppError::internal(err),
    }
}

fn trimmed(value: Option<&String>) -> Option<&str> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_account_id(value: &str) -> Option<Ulid> {
    if let Ok(id) = value.parse::<Ulid>() {
        return Some(id);
    }
    if let Some((prefix, id)) = value.split_once(':')
        && matches!(prefix, "user" | "account")
    {
        return id.parse::<Ulid>().ok();
    }
    None
}

async fn resolve_user(
    depot: &Depot,
    hint: &PasskeyAccountHint,
) -> Result<(BoxRepository, User), AppError> {
    let mut repo = depot.repo().await.map_err(AppError::from)?;
    if let Some(account_id) = trimmed(hint.account_id.as_ref()) {
        let id = parse_account_id(account_id)
            .ok_or_else(|| AppError::bad_request("invalid account_id"))?;
        let user = repo
            .user()
            .lookup(id)
            .await?
            .ok_or_else(|| AppError::bad_request("passkey_unavailable"))?;
        return Ok((repo, user));
    }

    let raw_hint = trimmed(hint.handle.as_ref())
        .or_else(|| trimmed(hint.login_hint.as_ref()))
        .ok_or_else(|| AppError::bad_request("account_hint_required"))?;
    let handle = raw_hint
        .strip_prefix("acct:")
        .unwrap_or(raw_hint)
        .split('@')
        .next()
        .unwrap_or(raw_hint)
        .trim();
    let user = repo
        .user()
        .find_by_handle(handle)
        .await?
        .ok_or_else(|| AppError::bad_request("passkey_unavailable"))?;
    Ok((repo, user))
}

async fn active_session(
    req: &Request,
    depot: &Depot,
) -> Result<(BoxRepository, coauth_data::BrowserSession), AppError> {
    let mut repo = depot.repo().await.map_err(AppError::from)?;
    let session = extract_session_info(req, depot)
        .load_active_session(&mut repo)
        .await?
        .ok_or_else(|| AppError::unauthorized("active browser session required"))?;
    Ok((repo, session))
}

async fn recently_authenticated_session(
    req: &Request,
    depot: &Depot,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(BoxRepository, coauth_data::BrowserSession), AppError> {
    let (mut repo, session) = active_session(req, depot).await?;
    let authentication = repo
        .browser_session()
        .get_last_authentication(&session)
        .await?
        .ok_or_else(|| AppError::forbidden("recent authentication required"))?;
    if !is_recent_authentication(&authentication, now) {
        return Err(AppError::forbidden("recent authentication required"));
    }
    Ok((repo, session))
}

fn is_recent_authentication(
    authentication: &Authentication,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let age = now.signed_duration_since(authentication.created_at);
    (Duration::zero()..=RECENT_AUTH_MAX_AGE).contains(&age)
        && matches!(
            &authentication.authentication_method,
            AuthenticationMethod::Password { .. }
                | AuthenticationMethod::UpstreamOAuth { .. }
                | AuthenticationMethod::Passkey { .. }
        )
}

fn session_binding(session: &coauth_data::BrowserSession) -> String {
    format!("session:{}", session.id)
}

fn parse_ceremony_id(value: &str) -> Result<Ulid, AppError> {
    value
        .parse()
        .map_err(|_| AppError::bad_request("invalid ceremony_id"))
}

fn parse_credential_path(req: &Request) -> Result<Ulid, AppError> {
    req.param::<String>("id")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| AppError::bad_request("invalid passkey id"))
}

fn passkey_request_is_same_origin(
    public_base_url: &url::Url,
    origin: Option<&str>,
    fetch_site: Option<&str>,
) -> bool {
    if fetch_site.is_some_and(|value| {
        !value.eq_ignore_ascii_case("same-origin") && !value.eq_ignore_ascii_case("none")
    }) {
        return false;
    }

    origin.is_none_or(|value| {
        url::Url::parse(value).is_ok_and(|candidate| candidate.origin() == public_base_url.origin())
    })
}

fn enforce_passkey_same_origin(req: &Request, depot: &Depot) -> Result<(), AppError> {
    let origin = req
        .headers()
        .get(http::header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let fetch_site = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok());
    let public_base_url = depot.url_builder().map_err(AppError::from)?.http_base();
    if !passkey_request_is_same_origin(&public_base_url, origin, fetch_site) {
        return Err(AppError::forbidden("passkey_same_origin_required"));
    }
    Ok(())
}

async fn enforce_passkey_rate_limit(
    req: &Request,
    depot: &Depot,
    user: &User,
) -> Result<(), AppError> {
    let requester = extract_bound_activity_tracker(req, depot)
        .ip()
        .map_or(RequesterFingerprint::EMPTY, RequesterFingerprint::new);
    depot
        .limiter()
        .map_err(AppError::from)?
        .check_password(requester, user)
        .await
        .map_err(|_| AppError::too_many_requests("rate_limited"))
}

fn load_browser_binding(req: &Request, depot: &Depot) -> Result<Option<String>, AppError> {
    let binding = depot
        .cookie_jar(req)
        .map_err(AppError::from)?
        .load::<String>(BROWSER_BINDING_COOKIE)
        .map_err(AppError::internal)?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    Ok(binding)
}

fn browser_binding(req: &Request, depot: &Depot) -> Result<String, AppError> {
    load_browser_binding(req, depot)?
        .ok_or_else(|| AppError::bad_request("passkey_ceremony_invalid"))
}

fn security_event(
    req: &Request,
    depot: &Depot,
    user_id: Ulid,
    event_type: SecurityEventType,
    metadata: serde_json::Value,
) -> NewAccountSecurityEvent {
    let mut event = NewAccountSecurityEvent::new(user_id, event_type, metadata);
    if let Some(ip) = extract_bound_activity_tracker(req, depot).ip() {
        event = event.with_ip_address(ip);
    }
    if let Some(user_agent) = req
        .headers()
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
    {
        event = event.with_user_agent(user_agent);
    }
    event
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.register_start", skip_all)]
pub async fn register_start(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyRegisterStartOutcome> {
    enforce_passkey_same_origin(req, depot)?;
    let body: PasskeyRegisterStartRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let clock = make_clock();
    let now = clock.now();
    let (repo, session) = recently_authenticated_session(req, depot, now).await?;
    enforce_passkey_rate_limit(req, depot, &session.user).await?;
    let display_name = trimmed(body.display_name.as_ref())
        .or(session.user.display_name.as_deref())
        .unwrap_or(&session.user.localpart);

    let start = depot
        .webauthn_service()
        .map_err(AppError::from)?
        .register_start(
            session.user.id,
            &session.user.localpart,
            display_name,
            &session_binding(&session),
            now,
        )
        .await
        .map_err(map_webauthn_error)?;
    repo.cancel().await?;

    Ok(Json(PasskeyRegisterStartOutcome {
        ceremony_id: start.id.to_string(),
        account_id: session.user.id.to_string(),
        handle: session.user.localpart,
        challenge: serde_json::to_value(start.challenge).map_err(AppError::internal)?,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.register_finish", skip_all)]
pub async fn register_finish(
    req: &mut Request,
    depot: &Depot,
) -> JsonResult<PasskeyRegisterFinishOutcome> {
    enforce_passkey_same_origin(req, depot)?;
    let body: PasskeyRegisterFinishRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let attestation: RegisterPublicKeyCredential = serde_json::from_value(body.attestation)
        .map_err(|error| AppError::bad_request(format!("invalid attestation: {error}")))?;
    let clock = make_clock();
    let now = clock.now();
    let (mut repo, session) = recently_authenticated_session(req, depot, now).await?;
    enforce_passkey_rate_limit(req, depot, &session.user).await?;

    let record = depot
        .webauthn_service()
        .map_err(AppError::from)?
        .register_finish(
            parse_ceremony_id(&body.ceremony_id)?,
            session.user.id,
            &session_binding(&session),
            &attestation,
            body.label,
            now,
        )
        .await
        .map_err(map_webauthn_error)?;
    let mut rng = make_rng();
    repo.audit()
        .add_security_event(
            &mut *rng,
            &*clock,
            security_event(
                req,
                depot,
                session.user.id,
                SecurityEventType::PasskeyRegistered,
                serde_json::json!({ "passkey_id": record.id.to_string() }),
            ),
        )
        .await?;
    repo.save().await?;

    Ok(Json(PasskeyRegisterFinishOutcome {
        account_id: session.user.id.to_string(),
        id: record.id.to_string(),
        label: record.label,
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.auth_start", skip_all)]
pub async fn auth_start(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    enforce_passkey_same_origin(req, depot)?;
    let body: PasskeyAccountHint = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let (repo, user) = resolve_user(depot, &body).await?;
    if !user.is_valid() {
        return Err(AppError::bad_request("passkey_unavailable"));
    }
    enforce_passkey_rate_limit(req, depot, &user).await?;

    let clock = make_clock();
    let now = clock.now();
    // Keep one opaque binding for the lifetime of the browser ceremony window.
    // Rotating it on every start would invalidate a ceremony already open in
    // another tab. Each ceremony still has its own single-use server-side id.
    let binding = load_browser_binding(req, depot)?.unwrap_or_else(|| Ulid::new().to_string());
    let start = depot
        .webauthn_service()
        .map_err(AppError::from)?
        .auth_start(user.id, &binding, now)
        .await
        .map_err(map_webauthn_error)?;
    repo.cancel().await?;

    let cookie_jar = depot.cookie_jar(req).map_err(AppError::from)?.save(
        BROWSER_BINDING_COOKIE,
        &binding,
        CookieExpiration::MaxAge(Duration::minutes(10)),
    );
    cookie_jar.finalize(
        res,
        Json(PasskeyAuthStartOutcome {
            ceremony_id: start.id.to_string(),
            account_id: user.id.to_string(),
            handle: user.localpart,
            challenge: serde_json::to_value(start.challenge).map_err(AppError::internal)?,
        }),
    );
    Ok(())
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.auth_finish", skip_all)]
pub async fn auth_finish(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), AppError> {
    enforce_passkey_same_origin(req, depot)?;
    let body: PasskeyAuthFinishRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let assertion: PublicKeyCredential = serde_json::from_value(body.assertion)
        .map_err(|error| AppError::bad_request(format!("invalid assertion: {error}")))?;
    let binding = browser_binding(req, depot)?;
    let clock = make_clock();
    let now = clock.now();
    let verified = depot
        .webauthn_service()
        .map_err(AppError::from)?
        .auth_finish(
            parse_ceremony_id(&body.ceremony_id)?,
            &binding,
            &assertion,
            now,
        )
        .await
        .map_err(map_webauthn_error)?;

    let mut repo = depot.repo().await.map_err(AppError::from)?;
    let user = repo
        .user()
        .lookup(verified.account_id)
        .await?
        .filter(User::is_valid)
        .ok_or_else(|| AppError::unauthorized("account unavailable"))?;
    enforce_passkey_rate_limit(req, depot, &user).await?;
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let mut rng = make_rng();
    let session = repo
        .browser_session()
        .add(&mut *rng, &*clock, &user, user_agent)
        .await?;
    repo.browser_session()
        .authenticate_with_passkey(&mut *rng, &*clock, &session, verified.credential_record_id)
        .await?;
    repo.audit()
        .add_security_event(
            &mut *rng,
            &*clock,
            security_event(
                req,
                depot,
                user.id,
                SecurityEventType::PasskeyLoginSuccess,
                serde_json::json!({
                    "passkey_id": verified.credential_record_id.to_string(),
                    "user_verified": verified.user_verified,
                    "backup_eligible": verified.backup_eligible,
                    "backup_state": verified.backup_state,
                }),
            ),
        )
        .await?;
    repo.save().await?;

    extract_bound_activity_tracker(req, depot)
        .record_browser_session(&*clock, &session)
        .await;
    let cookie_jar = depot
        .cookie_jar(req)
        .map_err(AppError::from)?
        .set_session(&session);
    cookie_jar.finalize(
        res,
        Json(PasskeyAuthFinishOutcome {
            status: "authenticated".to_owned(),
            account_id: user.id.to_string(),
            passkey_id: verified.credential_record_id.to_string(),
        }),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authentication(
        authentication_method: AuthenticationMethod,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Authentication {
        Authentication {
            id: Ulid::new(),
            created_at,
            authentication_method,
        }
    }

    #[test]
    fn recent_authentication_accepts_supported_factors_inside_window() {
        let now = chrono::Utc::now();
        for authentication_method in [
            AuthenticationMethod::Password {
                user_password_id: Ulid::new(),
            },
            AuthenticationMethod::UpstreamOAuth {
                upstream_oauth_session_id: Ulid::new(),
            },
            AuthenticationMethod::Passkey {
                webauthn_credential_id: Ulid::new(),
            },
        ] {
            assert!(is_recent_authentication(
                &authentication(authentication_method, now - Duration::minutes(5)),
                now
            ));
        }
    }

    #[test]
    fn recent_authentication_rejects_unknown_stale_and_future_records() {
        let now = chrono::Utc::now();
        assert!(!is_recent_authentication(
            &authentication(AuthenticationMethod::Unknown, now),
            now
        ));
        assert!(!is_recent_authentication(
            &authentication(
                AuthenticationMethod::Password {
                    user_password_id: Ulid::new(),
                },
                now - RECENT_AUTH_MAX_AGE - Duration::milliseconds(1),
            ),
            now
        ));
        assert!(!is_recent_authentication(
            &authentication(
                AuthenticationMethod::Password {
                    user_password_id: Ulid::new(),
                },
                now + Duration::milliseconds(1),
            ),
            now
        ));
    }

    #[test]
    fn passkey_origin_policy_accepts_only_same_origin_browser_requests() {
        let public_base_url = url::Url::parse("https://auth.example.com/coauth/").unwrap();

        assert!(passkey_request_is_same_origin(
            &public_base_url,
            Some("https://auth.example.com"),
            Some("same-origin"),
        ));
        assert!(passkey_request_is_same_origin(&public_base_url, None, None));
        assert!(passkey_request_is_same_origin(
            &public_base_url,
            None,
            Some("none"),
        ));
        assert!(!passkey_request_is_same_origin(
            &public_base_url,
            Some("https://evil.example"),
            Some("cross-site"),
        ));
        assert!(!passkey_request_is_same_origin(
            &public_base_url,
            Some("https://other.example.com"),
            Some("same-site"),
        ));
        assert!(!passkey_request_is_same_origin(
            &public_base_url,
            Some("null"),
            None,
        ));
    }
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.list", skip_all)]
pub async fn list(req: &mut Request, depot: &Depot) -> JsonResult<PasskeyListOutcome> {
    enforce_passkey_same_origin(req, depot)?;
    let (repo, session) = active_session(req, depot).await?;
    let records = depot
        .webauthn_service()
        .map_err(AppError::from)?
        .list(session.user.id)
        .await
        .map_err(map_webauthn_error)?;
    repo.cancel().await?;

    Ok(Json(PasskeyListOutcome {
        passkeys: records
            .into_iter()
            .map(|record| PasskeySummary {
                id: record.id.to_string(),
                label: record.label,
                backup_eligible: record.backup_eligible,
                backup_state: record.backup_state,
                user_verified: record.user_verified,
                created_at: record.created_at.to_rfc3339(),
                last_used_at: record.last_used_at.map(|value| value.to_rfc3339()),
            })
            .collect(),
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.rename", skip_all)]
pub async fn rename(req: &mut Request, depot: &Depot) -> JsonResult<PasskeyMutationOutcome> {
    enforce_passkey_same_origin(req, depot)?;
    let id = parse_credential_path(req)?;
    let body: PasskeyRenameRequestBody = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let clock = make_clock();
    let (mut repo, session) = recently_authenticated_session(req, depot, clock.now()).await?;
    depot
        .webauthn_service()
        .map_err(AppError::from)?
        .rename(session.user.id, id, body.label)
        .await
        .map_err(map_webauthn_error)?;
    let mut rng = make_rng();
    repo.audit()
        .add_security_event(
            &mut *rng,
            &*clock,
            security_event(
                req,
                depot,
                session.user.id,
                SecurityEventType::PasskeyRenamed,
                serde_json::json!({ "passkey_id": id.to_string() }),
            ),
        )
        .await?;
    repo.save().await?;
    Ok(Json(PasskeyMutationOutcome {
        status: "renamed".to_owned(),
        id: id.to_string(),
    }))
}

#[endpoint]
#[tracing::instrument(name = "handler.account.auth.passkey.revoke", skip_all)]
pub async fn revoke(req: &mut Request, depot: &Depot) -> JsonResult<PasskeyMutationOutcome> {
    enforce_passkey_same_origin(req, depot)?;
    let id = parse_credential_path(req)?;
    let _: serde_json::Value = req
        .parse_json()
        .await
        .map_err(|error| AppError::bad_request(format!("invalid request body: {error}")))?;
    let clock = make_clock();
    let now = clock.now();
    let (mut repo, session) = recently_authenticated_session(req, depot, now).await?;
    let webauthn = depot.webauthn_service().map_err(AppError::from)?;
    webauthn
        .revoke(session.user.id, id, now)
        .await
        .map_err(map_webauthn_error)?;
    let mut rng = make_rng();
    repo.audit()
        .add_security_event(
            &mut *rng,
            &*clock,
            security_event(
                req,
                depot,
                session.user.id,
                SecurityEventType::PasskeyRevoked,
                serde_json::json!({ "passkey_id": id.to_string() }),
            ),
        )
        .await?;
    repo.save().await?;
    Ok(Json(PasskeyMutationOutcome {
        status: "revoked".to_owned(),
        id: id.to_string(),
    }))
}
