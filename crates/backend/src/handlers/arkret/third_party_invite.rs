//! The four registered IVS operations. Private custody never authors Events.

use std::sync::Arc;
use std::time::Duration;

use arkret_models_collaboration::governance::third_party_invite::*;
use chrono::{DateTime, Utc};
use coauth_data::{RepositoryAccess, RepositoryFactory};
use salvo::prelude::*;

use super::ArkretRouteError;
use crate::handlers::common::DepotExt;
use crate::services::third_party_invite::{self as custody, InviteError, ThirdPartyInviteRuntime};

fn provider(depot: &Depot) -> Result<Arc<ThirdPartyInviteRuntime>, ArkretRouteError> {
    depot
        .get::<Arc<ThirdPartyInviteRuntime>>("third_party_invite_provider")
        .cloned()
        .map_err(|_| {
            ArkretRouteError::coded(
                StatusCode::NOT_IMPLEMENTED,
                "unsupported_feature",
                "third-party invite provider is unavailable",
            )
        })
}

fn failure(error: InviteError) -> ArkretRouteError {
    match error {
        InviteError::NotFound => unavailable(),
        InviteError::DuplicateConflict => ArkretRouteError::coded(
            StatusCode::CONFLICT,
            "duplicate_conflict",
            "original invite intent differs",
        ),
        InviteError::AlreadyBound => detailed_failure(
            "duplicate_conflict",
            "third_party_invite_provisioning_already_bound",
        ),
        InviteError::AcceptanceStale => {
            detailed_failure("failed_precondition", "third_party_invite_acceptance_stale")
        }
        InviteError::ProvisioningExpired => detailed_failure(
            "failed_precondition",
            "third_party_invite_provisioning_expired",
        ),
        InviteError::MaterialMismatch => detailed_failure(
            "failed_precondition",
            "third_party_invite_material_mismatch",
        ),
        InviteError::RateLimited => {
            ArkretRouteError::rate_limited("invitation rate exceeded", 60_000)
        }
        InviteError::QuotaExceeded => ArkretRouteError::coded(
            StatusCode::FORBIDDEN,
            "quota_exceeded",
            "unactivated invite quota exceeded",
        ),
        InviteError::UnsupportedFeature => ArkretRouteError::coded(
            StatusCode::NOT_IMPLEMENTED,
            "unsupported_feature",
            "delivery scheme is unsupported",
        ),
        InviteError::Internal => ArkretRouteError::coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "private invite custody failed",
        ),
    }
}

fn detailed_failure(code: &'static str, reason: &'static str) -> ArkretRouteError {
    ArkretRouteError::CodedDetailed {
        status: StatusCode::CONFLICT,
        code,
        message: "invite activation precondition failed".into(),
        details: vec![("reason_code", serde_json::json!(reason))],
    }
}

fn unavailable() -> ArkretRouteError {
    ArkretRouteError::coded(
        StatusCode::NOT_FOUND,
        "not_found",
        "third-party invite unavailable",
    )
}

pub(super) fn present_guard_failure(error: coland_storage::PersistenceError) -> ArkretRouteError {
    match error {
        coland_storage::PersistenceError::Conflict(reason)
            if reason.starts_with("unsupported_join_rule:") =>
        {
            ArkretRouteError::coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_join_rule",
                "join rule is unsupported",
            )
        }
        _ => unavailable(),
    }
}

// Use the connection's accepted transport source, never caller-controlled XFF.
// Same-Station reverse proxies deliberately share one conservative IP budget.
fn source_bucket(req: &Request) -> String {
    req.extensions()
        .get::<crate::listener::ConnectionInfo>()
        .and_then(crate::listener::ConnectionInfo::client_ip)
        .map_or_else(|| "local".into(), |ip| ip.to_string())
}

#[handler]
pub async fn provision_third_party_invite(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ThirdPartyInviteProvisionOutcome>, ArkretRouteError> {
    let runtime = provider(depot)?;
    let request: ThirdPartyInviteProvisionRequestBody =
        req.parse_json().await.map_err(|_| unavailable())?;
    let owning = runtime
        .config
        .runtime_owning_station_identity
        .get()
        .ok_or_else(unavailable)?;
    request
        .validate_for_service(&owning.station_id)
        .map_err(|_| unavailable())?;
    // Current accepted Device authority is held across the private mint commit.
    let guard = runtime
        .provision_guard(&request)
        .await
        .map_err(|_| unavailable())?;
    let mut repo = runtime
        .factory
        .create()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    let result = custody::provision_verified(
        &mut repo,
        &runtime.encrypter,
        crate::handlers::make_rng().as_mut(),
        &request,
        &owning.did,
        &source_bucket(req),
        guard.observed_at(),
    )
    .await;
    repo.save()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    guard
        .finish()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    result.map(Json).map_err(failure)
}

#[handler]
pub async fn activate_third_party_invite(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ThirdPartyInviteActivationOutcome>, ArkretRouteError> {
    let runtime = provider(depot)?;
    let request: ThirdPartyInviteActivationRequestBody =
        req.parse_json().await.map_err(|_| unavailable())?;
    let mut preview = runtime
        .factory
        .create()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    let row = preview
        .third_party_invite()
        .find(&custody::digest(request.provisioning_id.as_str()))
        .await
        .map_err(|_| failure(InviteError::Internal))?
        .ok_or_else(unavailable)?;
    let c = custody::decrypt(&row, &runtime.encrypter).map_err(failure)?;
    if request.provisioning_id != request.acceptance_attestation.provisioning_id {
        return Err(unavailable());
    }
    let request_digest = custody::digest(
        arkret_canonical::canonical_json_bytes(&request).map_err(|_| unavailable())?,
    );
    if let Some(original) = &c.activation
        && c.activation_digest.as_ref() == Some(&request_digest)
    {
        // Exact bytes name the previously authenticated durable outcome, even
        // after expiry or revocation. A changed request has no such authority.
        preview
            .cancel()
            .await
            .map_err(|_| failure(InviteError::Internal))?;
        return Ok(Json(original.clone()));
    }
    if c.activation.is_none()
        && c.public.inviter_account_id != request.acceptance_attestation.inviter_account_id
    {
        return Err(unavailable());
    }
    preview
        .cancel()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    custody::authentication::verify_activation(
        &depot.http_client()?,
        &runtime.config,
        &request,
        Utc::now(),
    )
    .await
    .map_err(failure)?;
    // The signature's explicit validity is checked again after resolution.
    request
        .acceptance_attestation
        .validate_freshness(Utc::now())
        .map_err(|_| failure(InviteError::AcceptanceStale))?;
    let mut repo = runtime
        .factory
        .create()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    let result =
        custody::activate_verified(&mut repo, &runtime.encrypter, &request, Utc::now()).await;
    repo.save()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    result.map(Json).map_err(failure)
}

#[handler]
pub async fn third_party_invite_status(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<ThirdPartyInviteProvisioningStatusOutcome>, ArkretRouteError> {
    let runtime = provider(depot)?;
    if req.uri().query().is_some() {
        return Err(unavailable());
    }
    let request: ThirdPartyInviteProvisioningStatusRequestBody =
        req.parse_json().await.map_err(|_| unavailable())?;
    let mut repo = runtime
        .factory
        .create()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    let row = repo
        .third_party_invite()
        .find(&custody::digest(request.provisioning_id.as_str()))
        .await
        .map_err(|_| failure(InviteError::Internal))?
        .ok_or_else(unavailable)?;
    let mut c = custody::decrypt(&row, &runtime.encrypter).map_err(failure)?;
    let now = Utc::now();
    if (c.state == ThirdPartyInviteProvisioningState::Provisioned
        && now >= c.public.activation_expires_at)
        || (c.state == ThirdPartyInviteProvisioningState::Activated && now >= c.public.expires_at)
    {
        c.state = ThirdPartyInviteProvisioningState::Expired;
        c.secrets = None;
        custody::update(&mut repo, row, &c, &runtime.encrypter)
            .await
            .map_err(failure)?;
    }
    let outcome = custody::status(&c);
    repo.save()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    Ok(Json(outcome))
}

async fn rate(
    repo: &mut coauth_data::BoxRepository,
    label: &str,
    now: DateTime<Utc>,
) -> Result<bool, InviteError> {
    let bucket = custody::digest(label);
    repo.third_party_invite().lock_namespace(&bucket).await?;
    let minute = DateTime::from_timestamp(now.timestamp().div_euclid(60) * 60, 0)
        .ok_or(InviteError::Internal)?;
    let day = DateTime::from_timestamp(now.timestamp().div_euclid(86400) * 86400, 0)
        .ok_or(InviteError::Internal)?;
    let minute_ok = repo
        .third_party_invite()
        .take_rate(&format!("{bucket}:minute"), minute, 5)
        .await?;
    let day_ok = repo
        .third_party_invite()
        .take_rate(&format!("{bucket}:day"), day, 50)
        .await?;
    Ok(minute_ok && day_ok)
}

async fn present(
    req: &mut Request,
    depot: &Depot,
) -> Result<ThirdPartyInvitePresentOutcome, ArkretRouteError> {
    let runtime = provider(depot)?;
    let request: ThirdPartyInvitePresentRequestBody =
        req.parse_json().await.map_err(|_| unavailable())?;
    let mut preview = runtime
        .factory
        .create()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    let now = Utc::now();
    let ip_ok = rate(
        &mut preview,
        &format!("present:ip:{}", source_bucket(req)),
        now,
    )
    .await
    .map_err(failure)?;
    let subject = custody::digest(
        arkret_canonical::canonical_json_bytes(&request.subject_account_id)
            .map_err(|_| unavailable())?,
    );
    let subject_ok = rate(&mut preview, &format!("present:subject:{subject}"), now)
        .await
        .map_err(failure)?;
    // Commit rate accounting even for unknown or invalid tokens.
    if !ip_ok || !subject_ok {
        preview
            .save()
            .await
            .map_err(|_| failure(InviteError::Internal))?;
        return Err(failure(InviteError::RateLimited));
    }
    let row = preview
        .third_party_invite()
        .find_token(&custody::token_selector(&request.invite_token))
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    let Some(row) = row else {
        preview
            .save()
            .await
            .map_err(|_| failure(InviteError::Internal))?;
        return Err(unavailable());
    };
    let c = custody::decrypt(&row, &runtime.encrypter).map_err(failure)?;
    let issuer_ok = rate(
        &mut preview,
        &format!("present:inviter:{}", row.issuer_digest),
        now,
    )
    .await
    .map_err(failure)?;
    if !issuer_ok {
        preview
            .save()
            .await
            .map_err(|_| failure(InviteError::Internal))?;
        return Err(failure(InviteError::RateLimited));
    }
    if request.validate_minimal().is_err()
        || request.realm_id != c.public.realm_id
        || !custody::matches_token(&c, &request.invite_token)
        || c.state != ThirdPartyInviteProvisioningState::Activated
        || now >= c.public.expires_at
    {
        let result =
            custody::consume_locked(&mut preview, row, c, &runtime.encrypter, &request, now).await;
        preview
            .save()
            .await
            .map_err(|_| failure(InviteError::Internal))?;
        return result.map_err(failure);
    }
    let handle = row.handle_digest.clone();
    preview
        .save()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    // Governance locks precede private custody locks on every delivery/consume.
    let guard = runtime.guard(&c).await.map_err(present_guard_failure)?;
    let mut repo = runtime
        .factory
        .create()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    let row = repo
        .third_party_invite()
        .find(&handle)
        .await
        .map_err(|_| failure(InviteError::Internal))?
        .ok_or_else(unavailable)?;
    let c = custody::decrypt(&row, &runtime.encrypter).map_err(failure)?;
    let result =
        custody::consume_locked(&mut repo, row, c, &runtime.encrypter, &request, Utc::now()).await;
    repo.save()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    guard
        .finish()
        .await
        .map_err(|_| failure(InviteError::Internal))?;
    result.map_err(failure)
}

#[handler]
pub async fn present_third_party_invite(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), ArkretRouteError> {
    let started = tokio::time::Instant::now();
    let result = present(req, depot).await;
    let evaluated = tokio::time::Instant::now();
    // Uniform negative body and a common floor for local token/custody checks.
    // Governance/database contention is not represented as a timing guarantee.
    if result.is_err() {
        tokio::time::sleep_until(started + Duration::from_millis(250)).await;
        tracing::debug!(
            boundary = "third_party_invite_provider_rejection",
            evaluation_ms = (evaluated - started).as_secs_f64() * 1000.0,
            padding_ms = evaluated.elapsed().as_secs_f64() * 1000.0,
            total_ms = started.elapsed().as_secs_f64() * 1000.0,
            "invite provider response timing"
        );
    }
    render_present_result(result, res)
}

pub(super) fn render_present_result(
    result: Result<ThirdPartyInvitePresentOutcome, ArkretRouteError>,
    res: &mut Response,
) -> Result<(), ArkretRouteError> {
    match result {
        Ok(outcome) => {
            res.render(Json(outcome));
            Ok(())
        }
        Err(ArkretRouteError::Coded {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            ..
        }) => {
            // Spec third-party-invites §6.1 requires byte-identical negative
            // bodies. Keep per-request correlation in the response header;
            // a fresh problem instance would distinguish otherwise equal 404s.
            super::render_problem(
                res,
                StatusCode::NOT_FOUND,
                arkret_wire::problem_details::Problem::from_code(
                    arkret_wire::ErrorCode::NOT_FOUND,
                    "third-party invite unavailable",
                ),
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Reject URL credentials before selector validation or request-body reads.
#[handler]
pub async fn reject_third_party_invite_url_credentials(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    const PRESENT: &str = "/_arkret/open/third-party-invites/present";
    if req.uri().path() == PRESENT && req.uri().query().is_none() {
        ctrl.call_next(req, depot, res).await;
        return;
    }
    if req.uri().path() != PRESENT && !req.uri().path().starts_with(&format!("{PRESENT}/")) {
        ctrl.call_next(req, depot, res).await;
        return;
    }
    if let Ok(runtime) = provider(depot) {
        let mut tokens: Vec<String> =
            url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .filter(|(key, _)| matches!(key.as_ref(), "invite_token" | "token"))
                .map(|(_, value)| value.into_owned())
                .collect();
        if let Some(path_token) = req.uri().path().strip_prefix(&format!("{PRESENT}/")) {
            tokens.push(path_token.to_owned());
        }
        for token in tokens {
            if let Ok(mut repo) = runtime.factory.create().await {
                let found = repo
                    .third_party_invite()
                    .find_token(&custody::token_selector(&token))
                    .await;
                if let Ok(Some(row)) = found
                    && let Ok(mut c) = custody::decrypt(&row, &runtime.encrypter)
                    && custody::matches_token(&c, &token)
                {
                    c.state = ThirdPartyInviteProvisioningState::Revoked;
                    c.secrets = None;
                    if custody::update(&mut repo, row, &c, &runtime.encrypter)
                        .await
                        .is_ok()
                    {
                        let _ = repo.save().await;
                    }
                }
            }
        }
    }
    ArkretRouteError::CodedDetailed {
        status: StatusCode::CONFLICT,
        code: "failed_precondition",
        message: "invitation credentials belong only in the request body".into(),
        details: vec![(
            "reason_code",
            serde_json::json!("third_party_invite_token_in_query"),
        )],
    }
    .render(res);
    ctrl.skip_rest();
}
