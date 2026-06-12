use std::collections::BTreeMap;
use std::error::Error as StdError;

use anyhow::Context;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use coauth_data::notification::{
    NewNotificationDelivery, NewNotificationEventLog, NewNotificationRequest,
};
use coauth_data::queue::{
    ContactVerificationTarget, DispatchNotificationJob, ProcessNotificationDeliveriesJob,
    QueueJobRepositoryExt as _,
};
use coauth_data::user::UserEmailFilter;
use coauth_data::{
    BoxRepository, NotificationChannel, NotificationDelivery, NotificationDeliveryFailure,
    NotificationDestination, NotificationEventActor, NotificationEventKind,
    NotificationRequest as PersistedNotificationRequest, NotificationRequestSource,
    NotificationRequestStatus, Pagination, RepositoryAccess,
};
use coauth_i18n::Locale;
use coauth_messaging::email::{Address, DELIVERY_ID_TAG, Mailbox, REQUEST_ID_TAG};
use coauth_messaging::{NotificationError, NotificationRequest};
use coauth_templates::{EmailRecoveryContext, EmailVerificationContext, TemplateContext as _};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{error, info, warn};
use ulid::Ulid;

use crate::State;
use crate::new_queue::{JobContext, JobError, RunnableJob};

const TEMPLATE_EMAIL_VERIFICATION: &str = "email_verification";
const TEMPLATE_SMS_VERIFICATION: &str = "sms_verification_code";
const TEMPLATE_EMAIL_RECOVERY: &str = "email_recovery";
const EMAIL_VERIFICATION_LANGUAGE: &str = "en";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailVerificationPayload {
    code: String,
    language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SmsVerificationPayload {
    code: String,
    language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailRecoveryPayload {
    user_id: Ulid,
    ticket: String,
}

#[allow(clippy::large_enum_variant)]
enum PreparedDelivery {
    Ready(NotificationRequest),
    Cancelled {
        summary: &'static str,
        metadata: Value,
    },
}

fn delivery_tracking_tags(
    request: &PersistedNotificationRequest,
    delivery: &NotificationDelivery,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (DELIVERY_ID_TAG.to_owned(), delivery.id.to_string()),
        (REQUEST_ID_TAG.to_owned(), request.id.to_string()),
    ])
}

#[allow(clippy::too_many_arguments)]
async fn append_event(
    repo: &mut BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    notification_request: &PersistedNotificationRequest,
    notification_delivery: Option<&NotificationDelivery>,
    kind: NotificationEventKind,
    summary: Option<&str>,
    metadata: Value,
) -> Result<(), JobError> {
    let params = summary.map_or_else(
        || NewNotificationEventLog::new(kind, NotificationEventActor::System, metadata.clone()),
        |summary| {
            NewNotificationEventLog::new(kind, NotificationEventActor::System, metadata.clone())
                .with_summary(summary)
        },
    );

    repo.notification()
        .append_event(
            rng,
            clock,
            notification_request,
            notification_delivery,
            params,
        )
        .await
        .map_err(JobError::retry)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_notification_request(
    repo: &mut BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    template_key: &str,
    locale: &str,
    source: NotificationRequestSource,
    payload: Value,
    destination: NotificationDestination,
    channel: NotificationChannel,
    provider_binding_key: Option<&str>,
) -> Result<(), JobError> {
    let request = repo
        .notification()
        .add_request(
            rng,
            clock,
            NewNotificationRequest::new(template_key, locale, source, payload.clone()),
        )
        .await
        .map_err(JobError::retry)?;

    append_event(
        repo,
        rng,
        clock,
        &request,
        None,
        NotificationEventKind::RequestCreated,
        Some("Notification request created"),
        json!({
            "template_key": template_key,
            "payload_redacted": true,
            "locale": locale,
        }),
    )
    .await?;

    let mut delivery = NewNotificationDelivery::new(channel, destination.clone());
    if let Some(provider_binding_key) = provider_binding_key {
        delivery = delivery.with_provider_binding_key(provider_binding_key);
    }

    let delivery = repo
        .notification()
        .add_delivery(rng, clock, &request, delivery)
        .await
        .map_err(JobError::retry)?;

    append_event(
        repo,
        rng,
        clock,
        &request,
        Some(&delivery),
        NotificationEventKind::DeliveryQueued,
        Some("Notification delivery queued"),
        json!({
            "channel": delivery.channel,
            "destination": destination,
            "provider_binding_key": delivery.provider_binding_key,
        }),
    )
    .await?;

    Ok(())
}

async fn schedule_processing_job(
    repo: &mut BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
) -> Result<(), JobError> {
    repo.queue_job()
        .schedule_job(rng, clock, ProcessNotificationDeliveriesJob::default())
        .await
        .map_err(JobError::retry)
}

pub(crate) async fn send_email_authentication_code(
    state: &State,
    user_email_authentication_id: Ulid,
    _language: &str,
) -> Result<(), JobError> {
    let clock = state.clock();
    let notifications = state.notifications();
    let mut rng = state.rng();
    let mut repo = state.repository().await.map_err(JobError::retry)?;

    let user_email_authentication = repo
        .user_email()
        .lookup_authentication(user_email_authentication_id)
        .await
        .map_err(JobError::retry)?
        .ok_or(JobError::fail(anyhow::anyhow!(
            "User email authentication not found"
        )))?;

    if user_email_authentication.completed_at.is_some() {
        info!("Email authentication already completed, skipping notification request");
        repo.cancel().await.map_err(JobError::retry)?;
        return Ok(());
    }

    let code = format!("{:06}", rng.next_u32() % 1_000_000);
    let code = repo
        .user_email()
        .add_authentication_code(
            &mut rng,
            clock,
            Duration::minutes(5),
            &user_email_authentication,
            code,
        )
        .await
        .map_err(JobError::retry)?;

    if state
        .site_config()
        .registration_email_delivery_bypass_allowed
    {
        info!(
            email = %user_email_authentication.email,
            authentication_code.id = %code.id,
            code = %code.code,
            "Email verification code generated (dev: code shown because registration_email_delivery_bypass_allowed=true)"
        );
    } else {
        info!(
            email = %user_email_authentication.email,
            authentication_code.id = %code.id,
            "Email verification code generated"
        );
    }

    enqueue_notification_request(
        &mut repo,
        &mut rng,
        clock,
        TEMPLATE_EMAIL_VERIFICATION,
        EMAIL_VERIFICATION_LANGUAGE,
        NotificationRequestSource::UserEmailAuthentication {
            user_email_authentication_id,
        },
        serde_json::to_value(EmailVerificationPayload {
            code: code.code.clone(),
            language: EMAIL_VERIFICATION_LANGUAGE.to_owned(),
        })
        .map_err(JobError::fail)?,
        NotificationDestination::Email {
            email: user_email_authentication.email.clone(),
        },
        NotificationChannel::Email,
        notifications.email_provider_binding_key(),
    )
    .await?;

    schedule_processing_job(&mut repo, &mut rng, clock).await?;

    repo.save().await.map_err(JobError::fail)?;

    Ok(())
}

pub(crate) async fn send_sms_authentication_code(
    state: &State,
    user_phone_authentication_id: Ulid,
    language: &str,
) -> Result<(), JobError> {
    let clock = state.clock();
    let mut rng = state.rng();
    let mut repo = state.repository().await.map_err(JobError::retry)?;

    let user_phone_authentication = repo
        .user_phone()
        .lookup_authentication(user_phone_authentication_id)
        .await
        .map_err(JobError::retry)?
        .ok_or(JobError::fail(anyhow::anyhow!(
            "User phone authentication not found"
        )))?;

    if user_phone_authentication.completed_at.is_some() {
        info!("Phone authentication already completed, skipping notification request");
        repo.cancel().await.map_err(JobError::retry)?;
        return Ok(());
    }

    let code = format!("{:06}", rng.next_u32() % 1_000_000);
    let code = repo
        .user_phone()
        .add_authentication_code(
            &mut rng,
            clock,
            Duration::minutes(5),
            &user_phone_authentication,
            code,
        )
        .await
        .map_err(JobError::retry)?;

    info!(
        phone = %user_phone_authentication.phone,
        authentication_code.id = %code.id,
        "SMS verification code generated"
    );

    enqueue_notification_request(
        &mut repo,
        &mut rng,
        clock,
        TEMPLATE_SMS_VERIFICATION,
        language,
        NotificationRequestSource::UserPhoneAuthentication {
            user_phone_authentication_id,
        },
        serde_json::to_value(SmsVerificationPayload {
            code: code.code.clone(),
            language: language.to_owned(),
        })
        .map_err(JobError::fail)?,
        NotificationDestination::Sms {
            phone_number: user_phone_authentication.phone.clone(),
        },
        NotificationChannel::Sms,
        state.notifications().sms_provider_binding_key(),
    )
    .await?;

    schedule_processing_job(&mut repo, &mut rng, clock).await?;

    repo.save().await.map_err(JobError::fail)?;

    Ok(())
}

pub(crate) async fn send_account_recovery(
    state: &State,
    user_recovery_session_id: Ulid,
) -> Result<(), JobError> {
    let clock = state.clock();
    let mut rng = state.rng();
    let mut repo = state.repository().await.map_err(JobError::retry)?;

    let session = repo
        .user_recovery()
        .lookup_session(user_recovery_session_id)
        .await
        .map_err(JobError::retry)?
        .context("User recovery session not found")
        .map_err(JobError::fail)?;

    tracing::Span::current().record("user_recovery_session.email", &session.email);

    if session.consumed_at.is_some() {
        info!("Recovery session already consumed, skipping notification request");
        repo.cancel().await.map_err(JobError::retry)?;
        return Ok(());
    }

    let mut cursor = Pagination::first(50);
    let mut queued_any = false;

    loop {
        let page = repo
            .user_email()
            .list(UserEmailFilter::new().for_email(&session.email), cursor)
            .await
            .map_err(JobError::retry)?;

        for edge in &page.edges {
            let ticket = {
                const CHARSET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                bytes
                    .iter()
                    .map(|b| CHARSET[*b as usize % CHARSET.len()] as char)
                    .collect::<String>()
            };
            let ticket = repo
                .user_recovery()
                .add_ticket(&mut rng, clock, &session, &edge.node, ticket)
                .await
                .map_err(JobError::retry)?;

            enqueue_notification_request(
                &mut repo,
                &mut rng,
                clock,
                TEMPLATE_EMAIL_RECOVERY,
                &session.locale,
                NotificationRequestSource::UserRecoverySession {
                    user_recovery_session_id,
                },
                serde_json::to_value(EmailRecoveryPayload {
                    user_id: edge.node.user_id,
                    ticket: ticket.ticket,
                })
                .map_err(JobError::fail)?,
                NotificationDestination::Email {
                    email: edge.node.email.clone(),
                },
                NotificationChannel::Email,
                state.notifications().email_provider_binding_key(),
            )
            .await?;

            queued_any = true;
        }

        if !page.has_next_page {
            break;
        }

        if let Some(last_edge) = page.edges.last() {
            cursor = cursor.after(last_edge.cursor);
        } else {
            break;
        }
    }

    if queued_any {
        schedule_processing_job(&mut repo, &mut rng, clock).await?;
    }

    repo.save().await.map_err(JobError::fail)?;

    Ok(())
}

fn error_chain_contains_any(error: &(dyn StdError + 'static), needles: &[&str]) -> bool {
    let mut current = Some(error);

    while let Some(err) = current {
        let message = err.to_string().to_ascii_lowercase();
        if needles.iter().any(|needle| message.contains(needle)) {
            return true;
        }
        current = err.source();
    }

    false
}

fn is_permanent_tls_validation_error(error: &(dyn StdError + 'static)) -> bool {
    error_chain_contains_any(
        error,
        &[
            "invalid peer certificate",
            "unknownissuer",
            "certificate verify failed",
            "self-signed certificate",
            "certificate has expired",
            "not valid for name",
            "hostname mismatch",
        ],
    )
}

fn notification_failure_from_error(error: &NotificationError) -> NotificationDeliveryFailure {
    let (code, message, retryable) = match error {
        NotificationError::EmailNotConfigured => (
            Some("email_not_configured".to_owned()),
            Some("email notifications are not configured".to_owned()),
            false,
        ),
        NotificationError::SmsNotConfigured => (
            Some("sms_not_configured".to_owned()),
            Some("sms notifications are not configured".to_owned()),
            false,
        ),
        NotificationError::Email(error) => match error {
            coauth_messaging::email::MailerError::Transport(error) => (
                match error {
                    coauth_messaging::email::EmailTransportError::Message(_) => {
                        Some("email_message".to_owned())
                    }
                    coauth_messaging::email::EmailTransportError::Smtp(_) => {
                        Some("email_smtp".to_owned())
                    }
                    coauth_messaging::email::EmailTransportError::Sendmail(_) => {
                        Some("email_sendmail".to_owned())
                    }
                    coauth_messaging::email::EmailTransportError::Json(_) => {
                        Some("email_json".to_owned())
                    }
                    coauth_messaging::email::EmailTransportError::Http(error) => {
                        if is_permanent_tls_validation_error(error) {
                            Some("email_tls_certificate".to_owned())
                        } else {
                            Some("email_http".to_owned())
                        }
                    }
                    coauth_messaging::email::EmailTransportError::ProviderError {
                        status, ..
                    } => Some(format!("email_provider_{status}")),
                },
                Some(error.to_string()),
                match error {
                    coauth_messaging::email::EmailTransportError::ProviderError {
                        retryable,
                        ..
                    } => *retryable,
                    coauth_messaging::email::EmailTransportError::Message(_)
                    | coauth_messaging::email::EmailTransportError::Json(_) => false,
                    coauth_messaging::email::EmailTransportError::Smtp(_)
                    | coauth_messaging::email::EmailTransportError::Sendmail(_) => true,
                    coauth_messaging::email::EmailTransportError::Http(error) => {
                        !is_permanent_tls_validation_error(error)
                    }
                },
            ),
            coauth_messaging::email::MailerError::Templates(error) => (
                Some("email_template".to_owned()),
                Some(error.to_string()),
                false,
            ),
        },
        NotificationError::Sms(error) => match error {
            coauth_messaging::sms::SmsTransportError::Http(error) => {
                let is_permanent_tls = is_permanent_tls_validation_error(error);
                let code = if is_permanent_tls {
                    Some("sms_tls_certificate".to_owned())
                } else {
                    Some("sms_http".to_owned())
                };
                (code, Some(error.to_string()), !is_permanent_tls)
            }
            coauth_messaging::sms::SmsTransportError::ProviderError { status, .. } => (
                Some(format!("sms_provider_{status}")),
                Some(format!("SMS provider returned non-success status {status}")),
                *status >= 500 || *status == 429,
            ),
        },
    };

    NotificationDeliveryFailure {
        code,
        message,
        retryable,
    }
}

fn terminal_failure(code: &str, message: impl Into<String>) -> NotificationDeliveryFailure {
    NotificationDeliveryFailure {
        code: Some(code.to_owned()),
        message: Some(message.into()),
        retryable: false,
    }
}

// Uses `Utc::now()` deliberately: callers don't pass a clock and the
// deadline check is heuristic anyway, so wall time is acceptable here.
#[allow(clippy::disallowed_methods)]
fn next_retry_delay(
    request: &PersistedNotificationRequest,
    delivery: &NotificationDelivery,
    failure: &NotificationDeliveryFailure,
) -> Option<Duration> {
    if !failure.retryable {
        return None;
    }

    let delay = match delivery.attempt_count {
        1 => Duration::seconds(30),
        2 => Duration::minutes(2),
        3 if request.template_key == TEMPLATE_EMAIL_RECOVERY => Duration::minutes(10),
        _ => return None,
    };

    if matches!(
        request.template_key.as_str(),
        TEMPLATE_EMAIL_VERIFICATION | TEMPLATE_SMS_VERIFICATION
    ) && request.created_at + Duration::minutes(5) <= Utc::now() + delay
    {
        return None;
    }

    Some(delay)
}

fn parse_payload<T: for<'de> Deserialize<'de>>(
    request: &PersistedNotificationRequest,
) -> Result<T, anyhow::Error> {
    serde_json::from_value(request.payload.clone()).with_context(|| {
        format!(
            "Failed to deserialize payload for notification request {}",
            request.id
        )
    })
}

async fn prepare_delivery(
    repo: &mut BoxRepository,
    url_builder: &coauth_data::UrlBuilder,
    request: &PersistedNotificationRequest,
    delivery: &NotificationDelivery,
) -> Result<PreparedDelivery, anyhow::Error> {
    match request.template_key.as_str() {
        TEMPLATE_EMAIL_VERIFICATION => {
            let payload: EmailVerificationPayload = parse_payload(request)?;
            let NotificationRequestSource::UserEmailAuthentication {
                user_email_authentication_id,
            } = &request.source
            else {
                anyhow::bail!("Notification source does not match email verification payload");
            };

            let auth = repo
                .user_email()
                .lookup_authentication(*user_email_authentication_id)
                .await?
                .context("User email authentication not found")?;

            if auth.completed_at.is_some() {
                return Ok(PreparedDelivery::Cancelled {
                    summary: "Email authentication already completed",
                    metadata: json!({
                        "user_email_authentication_id": user_email_authentication_id,
                    }),
                });
            }

            let browser_session = if let Some(browser_session_id) = auth.user_session_id {
                Some(
                    repo.browser_session()
                        .lookup(browser_session_id)
                        .await?
                        .context("Failed to load browser session")?,
                )
            } else {
                None
            };

            let registration = if let Some(registration_id) = auth.user_registration_id {
                Some(
                    repo.user_registration()
                        .lookup(registration_id)
                        .await?
                        .context("Failed to load registration")?,
                )
            } else {
                None
            };

            let handle_from_session = browser_session.as_ref().map(|s| s.user.localpart.clone());
            let handle_from_registration = registration.as_ref().map(|r| r.localpart.clone());
            let handle = handle_from_registration.or(handle_from_session);
            let authentication_code = repo
                .user_email()
                .find_authentication_code(&auth, &payload.code)
                .await?
                .context("User email authentication code not found")?;

            let NotificationDestination::Email { email } = &delivery.destination else {
                anyhow::bail!("Email verification delivery is not an email destination");
            };
            let address: Address = email.parse()?;
            let mailbox = Mailbox::new(handle, address);

            let language: Locale = payload.language.parse()?;
            let context =
                EmailVerificationContext::new(authentication_code, browser_session, registration)
                    .with_language(language);
            let tags = delivery_tracking_tags(request, delivery);

            Ok(PreparedDelivery::Ready(
                NotificationRequest::EmailVerification {
                    to: mailbox,
                    context,
                    tags,
                },
            ))
        }
        TEMPLATE_SMS_VERIFICATION => {
            let payload: SmsVerificationPayload = parse_payload(request)?;
            let NotificationRequestSource::UserPhoneAuthentication {
                user_phone_authentication_id,
            } = &request.source
            else {
                anyhow::bail!("Notification source does not match SMS verification payload");
            };

            let auth = repo
                .user_phone()
                .lookup_authentication(*user_phone_authentication_id)
                .await?
                .context("User phone authentication not found")?;

            if auth.completed_at.is_some() {
                return Ok(PreparedDelivery::Cancelled {
                    summary: "Phone authentication already completed",
                    metadata: json!({
                        "user_phone_authentication_id": user_phone_authentication_id,
                    }),
                });
            }

            let NotificationDestination::Sms { phone_number } = &delivery.destination else {
                anyhow::bail!("SMS verification delivery is not an SMS destination");
            };

            if phone_number != &auth.phone {
                warn!(
                    notification_request.id = %request.id,
                    notification_delivery.id = %delivery.id,
                    stored_phone = phone_number,
                    current_phone = auth.phone,
                    "Notification delivery phone differs from latest authentication phone"
                );
            }

            Ok(PreparedDelivery::Ready(
                NotificationRequest::SmsVerificationCode {
                    to: phone_number.clone(),
                    code: payload.code,
                    language: payload.language,
                },
            ))
        }
        TEMPLATE_EMAIL_RECOVERY => {
            let payload: EmailRecoveryPayload = parse_payload(request)?;
            let NotificationRequestSource::UserRecoverySession {
                user_recovery_session_id,
            } = &request.source
            else {
                anyhow::bail!("Notification source does not match recovery payload");
            };

            let session = repo
                .user_recovery()
                .lookup_session(*user_recovery_session_id)
                .await?
                .context("User recovery session not found")?;

            if session.consumed_at.is_some() {
                return Ok(PreparedDelivery::Cancelled {
                    summary: "Recovery session already consumed",
                    metadata: json!({
                        "user_recovery_session_id": user_recovery_session_id,
                    }),
                });
            }

            let user = repo
                .user()
                .lookup(payload.user_id)
                .await?
                .context("Recovery email user not found")?;

            let language: Locale = session.locale.parse()?;
            let url = url_builder.account_recovery_link(payload.ticket);

            let NotificationDestination::Email { email } = &delivery.destination else {
                anyhow::bail!("Recovery delivery is not an email destination");
            };
            let address: Address = email.parse()?;
            let mailbox = Mailbox::new(Some(user.localpart.clone()), address);
            let context = EmailRecoveryContext::new(user, session, url).with_language(language);
            let tags = delivery_tracking_tags(request, delivery);

            Ok(PreparedDelivery::Ready(
                NotificationRequest::EmailRecovery {
                    to: mailbox,
                    context,
                    tags,
                },
            ))
        }
        other => anyhow::bail!("Unsupported notification template key: {other}"),
    }
}

async fn complete_delivery_with_failure(
    repo: &mut BoxRepository,
    rng: &mut (dyn rand_core::RngCore + Send),
    clock: &dyn coauth_data::Clock,
    mut request: PersistedNotificationRequest,
    delivery: NotificationDelivery,
    failure: NotificationDeliveryFailure,
) -> Result<(), JobError> {
    let now = clock.now();
    let next_retry_at = next_retry_delay(&request, &delivery, &failure).map(|delay| now + delay);
    let delivery = repo
        .notification()
        .mark_delivery_failed(clock, delivery, failure.clone(), None, next_retry_at)
        .await
        .map_err(JobError::retry)?;

    append_event(
        repo,
        rng,
        clock,
        &request,
        Some(&delivery),
        NotificationEventKind::DeliveryFailed,
        Some("Notification delivery failed"),
        json!({
            "failure": failure,
            "next_retry_at": next_retry_at,
            "attempt_count": delivery.attempt_count,
        }),
    )
    .await?;

    if let Some(next_retry_at) = next_retry_at {
        append_event(
            repo,
            rng,
            clock,
            &request,
            Some(&delivery),
            NotificationEventKind::DeliveryRetried,
            Some("Notification delivery scheduled for retry"),
            json!({
                "next_retry_at": next_retry_at,
                "attempt_count": delivery.attempt_count,
            }),
        )
        .await?;

        repo.queue_job()
            .schedule_job_later(
                rng,
                clock,
                ProcessNotificationDeliveriesJob::default(),
                next_retry_at,
            )
            .await
            .map_err(JobError::retry)?;

        request = repo
            .notification()
            .set_request_status(clock, request, NotificationRequestStatus::Processing)
            .await
            .map_err(JobError::retry)?;

        let _ = request;
    } else {
        request = repo
            .notification()
            .set_request_status(clock, request, NotificationRequestStatus::Failed)
            .await
            .map_err(JobError::retry)?;

        append_event(
            repo,
            rng,
            clock,
            &request,
            Some(&delivery),
            NotificationEventKind::RequestFailed,
            Some("Notification request reached terminal failure"),
            json!({
                "failure": failure,
            }),
        )
        .await?;
    }

    Ok(())
}

async fn process_single_delivery(state: &State) -> Result<bool, JobError> {
    let clock = state.clock();
    let notifications = state.notifications();
    let url_builder = state.url_builder();
    let mut rng = state.rng();
    let mut repo = state.repository().await.map_err(JobError::retry)?;

    let Some(delivery) = repo
        .notification()
        .reserve_deliveries(clock, 1)
        .await
        .map_err(JobError::retry)?
        .into_iter()
        .next()
    else {
        repo.cancel().await.map_err(JobError::retry)?;
        return Ok(false);
    };

    let mut request = repo
        .notification()
        .lookup_request(delivery.notification_request_id)
        .await
        .map_err(JobError::retry)?
        .ok_or(JobError::fail(anyhow::anyhow!(
            "Notification request not found for delivery {}",
            delivery.id
        )))?;

    append_event(
        &mut repo,
        &mut rng,
        clock,
        &request,
        Some(&delivery),
        NotificationEventKind::DeliveryReserved,
        Some("Notification delivery reserved"),
        json!({
            "attempt_count": delivery.attempt_count,
            "provider_binding_key": delivery.provider_binding_key,
        }),
    )
    .await?;

    request = repo
        .notification()
        .set_request_status(clock, request, NotificationRequestStatus::Processing)
        .await
        .map_err(JobError::retry)?;

    match prepare_delivery(&mut repo, url_builder, &request, &delivery).await {
        Ok(PreparedDelivery::Cancelled { summary, metadata }) => {
            let delivery = repo
                .notification()
                .cancel_delivery(clock, delivery)
                .await
                .map_err(JobError::retry)?;
            request = repo
                .notification()
                .set_request_status(clock, request, NotificationRequestStatus::Cancelled)
                .await
                .map_err(JobError::retry)?;

            append_event(
                &mut repo,
                &mut rng,
                clock,
                &request,
                Some(&delivery),
                NotificationEventKind::RequestCancelled,
                Some(summary),
                metadata,
            )
            .await?;

            repo.save().await.map_err(JobError::fail)?;
            return Ok(true);
        }
        Err(error) => {
            complete_delivery_with_failure(
                &mut repo,
                &mut rng,
                clock,
                request,
                delivery,
                terminal_failure("notification_prepare_failed", error.to_string()),
            )
            .await?;

            repo.save().await.map_err(JobError::fail)?;
            return Ok(true);
        }
        Ok(PreparedDelivery::Ready(outbound_request)) => {
            let delivery = repo
                .notification()
                .mark_delivery_sending(clock, delivery, None)
                .await
                .map_err(JobError::retry)?;

            append_event(
                &mut repo,
                &mut rng,
                clock,
                &request,
                Some(&delivery),
                NotificationEventKind::DeliverySendStarted,
                Some("Notification delivery send started"),
                json!({
                    "attempt_count": delivery.attempt_count,
                }),
            )
            .await?;

            match notifications.dispatch(outbound_request).await {
                Ok(result) => {
                    let delivery = repo
                        .notification()
                        .mark_delivery_delivered(
                            clock,
                            delivery,
                            result.provider_message_id.clone(),
                        )
                        .await
                        .map_err(JobError::retry)?;
                    request = repo
                        .notification()
                        .set_request_status(clock, request, NotificationRequestStatus::Succeeded)
                        .await
                        .map_err(JobError::retry)?;

                    append_event(
                        &mut repo,
                        &mut rng,
                        clock,
                        &request,
                        Some(&delivery),
                        NotificationEventKind::DeliveryAccepted,
                        Some("Notification delivery accepted by provider"),
                        json!({
                            "attempt_count": delivery.attempt_count,
                            "provider_message_id": delivery.provider_message_id,
                        }),
                    )
                    .await?;

                    append_event(
                        &mut repo,
                        &mut rng,
                        clock,
                        &request,
                        Some(&delivery),
                        NotificationEventKind::RequestCompleted,
                        Some("Notification request completed"),
                        json!({
                            "delivery_id": delivery.id,
                        }),
                    )
                    .await?;
                }
                Err(error) => {
                    let failure = notification_failure_from_error(&error);
                    let verification_code = match request.template_key.as_str() {
                        TEMPLATE_EMAIL_VERIFICATION => {
                            serde_json::from_value::<EmailVerificationPayload>(
                                request.payload.clone(),
                            )
                            .ok()
                            .map(|p| p.code)
                        }
                        TEMPLATE_SMS_VERIFICATION => {
                            serde_json::from_value::<SmsVerificationPayload>(
                                request.payload.clone(),
                            )
                            .ok()
                            .map(|p| p.code)
                        }
                        _ => None,
                    };
                    error!(
                        error = &error as &dyn std::error::Error,
                        notification_request.id = %request.id,
                        notification_delivery.id = %delivery.id,
                        verification_code = verification_code.as_deref(),
                        "Failed to deliver notification"
                    );

                    complete_delivery_with_failure(
                        &mut repo, &mut rng, clock, request, delivery, failure,
                    )
                    .await?;
                }
            }
        }
    }

    repo.save().await.map_err(JobError::fail)?;

    Ok(true)
}

pub(crate) async fn process_notification_deliveries(
    state: &State,
    limit: usize,
) -> Result<(), JobError> {
    let clock = state.clock();
    let mut rng = state.rng();
    let mut processed = 0usize;

    while processed < limit {
        if !process_single_delivery(state).await? {
            break;
        }
        processed += 1;
    }

    if processed == limit {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        repo.queue_job()
            .schedule_job(&mut rng, clock, ProcessNotificationDeliveriesJob::default())
            .await
            .map_err(JobError::retry)?;
        repo.save().await.map_err(JobError::fail)?;
    }

    Ok(())
}

#[async_trait]
impl RunnableJob for DispatchNotificationJob {
    #[tracing::instrument(name = "job.dispatch_notification", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        match self {
            Self::ContactVerification { target, language } => match target {
                ContactVerificationTarget::Email {
                    user_email_authentication_id,
                } => {
                    send_email_authentication_code(state, *user_email_authentication_id, language)
                        .await
                }
                ContactVerificationTarget::Phone {
                    user_phone_authentication_id,
                } => {
                    send_sms_authentication_code(state, *user_phone_authentication_id, language)
                        .await
                }
            },
            Self::EmailAuthenticationCode {
                user_email_authentication_id,
                language,
            } => {
                send_email_authentication_code(state, *user_email_authentication_id, language).await
            }
            Self::SmsAuthenticationCode {
                user_phone_authentication_id,
                language,
            } => send_sms_authentication_code(state, *user_phone_authentication_id, language).await,
            Self::AccountRecovery {
                user_recovery_session_id,
            } => send_account_recovery(state, *user_recovery_session_id).await,
        }
    }
}

#[async_trait]
impl RunnableJob for ProcessNotificationDeliveriesJob {
    #[tracing::instrument(name = "job.process_notification_deliveries", skip_all)]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        process_notification_deliveries(state, self.limit()).await
    }
}

#[cfg(test)]
mod tests {
    use thiserror::Error;

    use super::{
        EMAIL_VERIFICATION_LANGUAGE, NotificationError, is_permanent_tls_validation_error,
        notification_failure_from_error,
    };

    #[derive(Debug, Error)]
    #[error("{message}")]
    struct LeafError {
        message: &'static str,
    }

    #[derive(Debug, Error)]
    #[error("transport failed")]
    struct WrapperError {
        #[source]
        source: LeafError,
    }

    #[test]
    fn detects_tls_validation_errors_from_nested_sources() {
        let error = WrapperError {
            source: LeafError {
                message: "invalid peer certificate: UnknownIssuer",
            },
        };

        assert!(is_permanent_tls_validation_error(&error));
    }

    #[test]
    fn ignores_non_certificate_transport_errors() {
        let error = WrapperError {
            source: LeafError {
                message: "connection reset by peer",
            },
        };

        assert!(!is_permanent_tls_validation_error(&error));
    }

    #[test]
    fn email_verification_language_is_fixed_to_english() {
        assert_eq!(EMAIL_VERIFICATION_LANGUAGE, "en");
    }

    #[test]
    fn sms_provider_failure_redacts_provider_body() {
        let error =
            NotificationError::Sms(coauth_messaging::sms::SmsTransportError::ProviderError {
                status: 400,
                body: "Your verification code is 123456".to_owned(),
            });

        let failure = notification_failure_from_error(&error);

        assert_eq!(failure.code.as_deref(), Some("sms_provider_400"));
        assert_eq!(
            failure.message.as_deref(),
            Some("SMS provider returned non-success status 400")
        );
        assert!(!format!("{failure:?}").contains("123456"));
    }
}
