use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, anyhow};
use base64ct::{Base64, Encoding};
use chrono::{TimeZone, Utc};
use coauth_config::{
    AwsSesEmailProviderConfig, AwsSesWebhookConfig, BrevoWebhookConfig, EmailConfig,
    EmailProviderConfig, ResendWebhookConfig, SendgridWebhookConfig,
};
use coauth_data::{
    BoxRepository, Clock, NotificationDelivery, NotificationDeliveryFailure,
    NotificationDeliveryStatus, NotificationEventActor, NotificationEventKind,
    NotificationRequestStatus, RepositoryAccess, notification::NewNotificationEventLog,
};
use coauth_messaging::email::DELIVERY_ID_TAG;
use der::{DecodePem as _, Encode as _};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier as _,
};
use pkcs8::DecodePublicKey;
use rand_core::RngCore;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaVerifyingKey},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;
use thiserror::Error;
use url::Url;
use x509_cert::Certificate;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct EmailWebhookService {
    provider: ProviderRuntime,
}

#[derive(Clone)]
enum ProviderRuntime {
    Resend(ResendWebhookRuntime),
    Sendgrid(SendgridWebhookRuntime),
    Brevo(BrevoWebhookRuntime),
    AwsSes(AwsSesWebhookRuntime),
}

#[derive(Clone)]
struct ResendWebhookRuntime {
    binding_key: &'static str,
    signing_secret: Vec<u8>,
    max_age_seconds: u64,
}

#[derive(Clone)]
struct SendgridWebhookRuntime {
    binding_key: &'static str,
    verifying_key: P256VerifyingKey,
}

#[derive(Clone)]
struct BrevoWebhookRuntime {
    binding_key: &'static str,
    expected_headers: BTreeMap<String, String>,
}

#[derive(Clone)]
struct AwsSesWebhookRuntime {
    binding_key: &'static str,
    client: reqwest::Client,
    topic_arn: String,
    auto_confirm_subscription: bool,
    allowed_signing_cert_url_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EmailWebhookProcessResult {
    pub processed: usize,
    pub ignored: usize,
    pub subscription_confirmed: bool,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("email webhooks are not configured")]
    NotConfigured,

    #[error("webhook provider `{0}` does not match the configured email provider")]
    ProviderMismatch(String),

    #[error("invalid webhook payload: {0}")]
    BadRequest(String),

    #[error("unauthorized webhook request: {0}")]
    Unauthorized(String),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
struct ParsedWebhook {
    updates: Vec<DeliveryUpdate>,
    subscription_confirmed: bool,
}

#[derive(Debug, Clone)]
struct DeliveryUpdate {
    lookup: DeliveryLookup,
    provider_message_id: Option<String>,
    event_kind: NotificationEventKind,
    event_summary: &'static str,
    metadata: Value,
    status: DeliveryTerminalStatus,
}

#[derive(Debug, Clone)]
enum DeliveryLookup {
    DeliveryId(coauth_data::Ulid),
    ProviderMessageId(String),
}

#[derive(Debug, Clone)]
enum DeliveryTerminalStatus {
    Delivered,
    Failed(NotificationDeliveryFailure),
}

impl EmailWebhookService {
    pub fn from_email_config(
        config: &EmailConfig,
        client: reqwest::Client,
    ) -> Result<Option<Self>, Error> {
        match &config.provider {
            EmailProviderConfig::Resend(provider) => {
                provider.webhook.as_ref().map(Self::resend).transpose()
            }
            EmailProviderConfig::Sendgrid(provider) => {
                provider.webhook.as_ref().map(Self::sendgrid).transpose()
            }
            EmailProviderConfig::Twilio(provider) => {
                provider.webhook.as_ref().map(Self::twilio).transpose()
            }
            EmailProviderConfig::Brevo(provider) => {
                provider.webhook.as_ref().map(Self::brevo).transpose()
            }
            EmailProviderConfig::AwsSes(provider) => provider
                .webhook
                .as_ref()
                .map(|webhook| Self::aws_ses(provider, webhook, client))
                .transpose(),
            EmailProviderConfig::Blackhole
            | EmailProviderConfig::Smtp(_)
            | EmailProviderConfig::Sendmail(_)
            | EmailProviderConfig::HttpWebhook(_)
            | EmailProviderConfig::PaloudInternal(_) => Ok(None),
        }
    }

    fn resend(webhook: &ResendWebhookConfig) -> Result<Self, Error> {
        Ok(Self {
            provider: ProviderRuntime::Resend(ResendWebhookRuntime {
                binding_key: "email.resend",
                signing_secret: decode_resend_signing_secret(&webhook.signing_secret)?,
                max_age_seconds: webhook.max_age_seconds,
            }),
        })
    }

    fn sendgrid(webhook: &SendgridWebhookConfig) -> Result<Self, Error> {
        Ok(Self {
            provider: ProviderRuntime::Sendgrid(SendgridWebhookRuntime {
                binding_key: "email.sendgrid",
                verifying_key: parse_sendgrid_public_key(&webhook.public_key_pem)?,
            }),
        })
    }

    fn twilio(webhook: &SendgridWebhookConfig) -> Result<Self, Error> {
        Ok(Self {
            provider: ProviderRuntime::Sendgrid(SendgridWebhookRuntime {
                binding_key: "email.twilio",
                verifying_key: parse_sendgrid_public_key(&webhook.public_key_pem)?,
            }),
        })
    }

    fn brevo(webhook: &BrevoWebhookConfig) -> Result<Self, Error> {
        Ok(Self {
            provider: ProviderRuntime::Brevo(BrevoWebhookRuntime {
                binding_key: "email.brevo",
                expected_headers: normalize_expected_headers(&webhook.headers),
            }),
        })
    }

    fn aws_ses(
        _provider: &AwsSesEmailProviderConfig,
        webhook: &AwsSesWebhookConfig,
        client: reqwest::Client,
    ) -> Result<Self, Error> {
        Ok(Self {
            provider: ProviderRuntime::AwsSes(AwsSesWebhookRuntime {
                binding_key: "email.aws_ses",
                client,
                topic_arn: webhook.topic_arn.clone(),
                auto_confirm_subscription: webhook.auto_confirm_subscription,
                allowed_signing_cert_url_prefixes: webhook
                    .allowed_signing_cert_url_prefixes
                    .clone(),
            }),
        })
    }

    pub async fn process(
        &self,
        provider: &str,
        headers: &HeaderMap,
        body: &[u8],
        repo: &mut BoxRepository,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<EmailWebhookProcessResult, Error> {
        self.ensure_provider(provider)?;

        let parsed = match &self.provider {
            ProviderRuntime::Resend(runtime) => runtime.parse(headers, body)?,
            ProviderRuntime::Sendgrid(runtime) => runtime.parse(headers, body)?,
            ProviderRuntime::Brevo(runtime) => runtime.parse(headers, body)?,
            ProviderRuntime::AwsSes(runtime) => runtime.parse(body).await?,
        };

        let mut result = EmailWebhookProcessResult {
            subscription_confirmed: parsed.subscription_confirmed,
            ..EmailWebhookProcessResult::default()
        };
        let mut touched_requests = BTreeSet::new();

        for update in parsed.updates {
            let Some(delivery) = self.lookup_delivery(repo, &update.lookup).await? else {
                result.ignored += 1;
                continue;
            };

            if delivery.status == NotificationDeliveryStatus::Cancelled {
                result.ignored += 1;
                continue;
            }

            let Some(request) = repo
                .notification()
                .lookup_request(delivery.notification_request_id)
                .await
                .map_err(|error| Error::Internal(anyhow!(error)))?
            else {
                return Err(Error::Internal(anyhow!(
                    "notification request {} was not found for delivery {}",
                    delivery.notification_request_id,
                    delivery.id
                )));
            };

            let changed_delivery = self
                .apply_delivery_update(repo, clock, &delivery, &update)
                .await?;

            let Some(changed_delivery) = changed_delivery else {
                result.ignored += 1;
                continue;
            };

            repo.notification()
                .append_event(
                    rng,
                    clock,
                    &request,
                    Some(&changed_delivery),
                    NewNotificationEventLog::new(
                        update.event_kind,
                        NotificationEventActor::System,
                        update.metadata.clone(),
                    )
                    .with_summary(update.event_summary),
                )
                .await
                .map_err(|error| Error::Internal(anyhow!(error)))?;

            touched_requests.insert(request.id);
            result.processed += 1;
        }

        for request_id in touched_requests {
            self.reconcile_request_status(repo, rng, clock, request_id)
                .await?;
        }

        Ok(result)
    }

    fn ensure_provider(&self, provider: &str) -> Result<(), Error> {
        if self.accepts_provider(provider) {
            Ok(())
        } else {
            Err(Error::ProviderMismatch(provider.to_owned()))
        }
    }

    fn accepts_provider(&self, provider: &str) -> bool {
        let provider = provider.trim().to_ascii_lowercase().replace('_', "-");

        match &self.provider {
            ProviderRuntime::Resend(_) => provider == "resend",
            ProviderRuntime::Sendgrid(runtime) if runtime.binding_key == "email.sendgrid" => {
                provider == "sendgrid"
            }
            ProviderRuntime::Sendgrid(_) => provider == "twilio" || provider == "sendgrid",
            ProviderRuntime::Brevo(_) => provider == "brevo",
            ProviderRuntime::AwsSes(_) => {
                provider == "aws-ses" || provider == "aws_ses" || provider == "ses"
            }
        }
    }

    fn binding_key(&self) -> &'static str {
        match &self.provider {
            ProviderRuntime::Resend(runtime) => runtime.binding_key,
            ProviderRuntime::Sendgrid(runtime) => runtime.binding_key,
            ProviderRuntime::Brevo(runtime) => runtime.binding_key,
            ProviderRuntime::AwsSes(runtime) => runtime.binding_key,
        }
    }

    async fn lookup_delivery(
        &self,
        repo: &mut BoxRepository,
        lookup: &DeliveryLookup,
    ) -> Result<Option<NotificationDelivery>, Error> {
        match lookup {
            DeliveryLookup::DeliveryId(id) => repo
                .notification()
                .lookup_delivery(*id)
                .await
                .map_err(|error| Error::Internal(anyhow!(error))),
            DeliveryLookup::ProviderMessageId(provider_message_id) => repo
                .notification()
                .lookup_delivery_by_provider_message_id(self.binding_key(), provider_message_id)
                .await
                .map_err(|error| Error::Internal(anyhow!(error))),
        }
    }

    async fn apply_delivery_update(
        &self,
        repo: &mut BoxRepository,
        clock: &dyn Clock,
        delivery: &NotificationDelivery,
        update: &DeliveryUpdate,
    ) -> Result<Option<NotificationDelivery>, Error> {
        if !should_apply_delivery_update(
            delivery.status,
            delivery.last_failure.as_ref(),
            &update.status,
        ) {
            return Ok(None);
        }

        match &update.status {
            DeliveryTerminalStatus::Delivered => repo
                .notification()
                .mark_delivery_delivered(
                    clock,
                    delivery.clone(),
                    update.provider_message_id.clone(),
                )
                .await
                .map(Some)
                .map_err(|error| Error::Internal(anyhow!(error))),
            DeliveryTerminalStatus::Failed(failure) => repo
                .notification()
                .mark_delivery_failed(
                    clock,
                    delivery.clone(),
                    failure.clone(),
                    update.provider_message_id.clone(),
                    None,
                )
                .await
                .map(Some)
                .map_err(|error| Error::Internal(anyhow!(error))),
        }
    }

    async fn reconcile_request_status(
        &self,
        repo: &mut BoxRepository,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        request_id: coauth_data::Ulid,
    ) -> Result<(), Error> {
        let Some(request) = repo
            .notification()
            .lookup_request(request_id)
            .await
            .map_err(|error| Error::Internal(anyhow!(error)))?
        else {
            return Ok(());
        };

        if request.status == NotificationRequestStatus::Cancelled {
            return Ok(());
        }

        let deliveries = repo
            .notification()
            .list_deliveries(&request)
            .await
            .map_err(|error| Error::Internal(anyhow!(error)))?;
        let next_status = if deliveries
            .iter()
            .any(|delivery| !delivery.status.is_terminal())
        {
            NotificationRequestStatus::Processing
        } else if deliveries
            .iter()
            .any(|delivery| delivery.status == NotificationDeliveryStatus::Delivered)
        {
            NotificationRequestStatus::Succeeded
        } else {
            NotificationRequestStatus::Failed
        };

        if next_status == request.status {
            return Ok(());
        }

        let request = repo
            .notification()
            .set_request_status(clock, request, next_status)
            .await
            .map_err(|error| Error::Internal(anyhow!(error)))?;

        let event = match next_status {
            NotificationRequestStatus::Succeeded => Some((
                NotificationEventKind::RequestCompleted,
                "Notification request completed after provider callback",
            )),
            NotificationRequestStatus::Failed => Some((
                NotificationEventKind::RequestFailed,
                "Notification request reached terminal failure after provider callback",
            )),
            NotificationRequestStatus::Pending
            | NotificationRequestStatus::Processing
            | NotificationRequestStatus::Cancelled => None,
        };

        if let Some((kind, summary)) = event {
            repo.notification()
                .append_event(
                    rng,
                    clock,
                    &request,
                    None,
                    NewNotificationEventLog::new(
                        kind,
                        NotificationEventActor::System,
                        json!({
                            "provider_binding_key": self.binding_key(),
                            "notification_request_id": request.id,
                            "status": next_status,
                        }),
                    )
                    .with_summary(summary),
                )
                .await
                .map_err(|error| Error::Internal(anyhow!(error)))?;
        }

        Ok(())
    }
}

impl ResendWebhookRuntime {
    fn parse(&self, headers: &HeaderMap, body: &[u8]) -> Result<ParsedWebhook, Error> {
        let message_id = header_str(headers, "svix-id")
            .ok_or_else(|| Error::Unauthorized("missing svix-id header".to_owned()))?;
        let timestamp = header_str(headers, "svix-timestamp")
            .ok_or_else(|| Error::Unauthorized("missing svix-timestamp header".to_owned()))?;
        let signature = header_str(headers, "svix-signature")
            .ok_or_else(|| Error::Unauthorized("missing svix-signature header".to_owned()))?;

        verify_resend_signature(
            &self.signing_secret,
            self.max_age_seconds,
            &message_id,
            &timestamp,
            &signature,
            body,
        )?;

        let event: ResendWebhookEvent =
            serde_json::from_slice(body).map_err(|error| Error::BadRequest(error.to_string()))?;
        let Some(status) = resend_event_status(&event.event_type) else {
            return Ok(ParsedWebhook {
                updates: Vec::new(),
                subscription_confirmed: false,
            });
        };

        let provider_message_id = event.data.email_id.clone();
        let lookup = lookup_from_key_value_tags(
            event.data.tags.as_ref().map_or(&[][..], Vec::as_slice),
            provider_message_id.clone(),
        )?;

        Ok(ParsedWebhook {
            updates: vec![DeliveryUpdate {
                lookup,
                provider_message_id: provider_message_id.clone(),
                event_kind: match status {
                    DeliveryTerminalStatus::Delivered => NotificationEventKind::DeliveryDelivered,
                    DeliveryTerminalStatus::Failed(_) => NotificationEventKind::DeliveryFailed,
                },
                event_summary: match status {
                    DeliveryTerminalStatus::Delivered => {
                        "Notification delivery confirmed by Resend"
                    }
                    DeliveryTerminalStatus::Failed(_) => {
                        "Notification delivery failed according to Resend"
                    }
                },
                metadata: json!({
                    "provider": "resend",
                    "event_type": event.event_type,
                    "provider_message_id": provider_message_id,
                }),
                status,
            }],
            subscription_confirmed: false,
        })
    }
}

impl SendgridWebhookRuntime {
    fn parse(&self, headers: &HeaderMap, body: &[u8]) -> Result<ParsedWebhook, Error> {
        let signature = header_str(headers, "x-twilio-email-event-webhook-signature")
            .ok_or_else(|| Error::Unauthorized("missing SendGrid signature header".to_owned()))?;
        let timestamp = header_str(headers, "x-twilio-email-event-webhook-timestamp")
            .ok_or_else(|| Error::Unauthorized("missing SendGrid timestamp header".to_owned()))?;

        verify_sendgrid_signature(&self.verifying_key, &timestamp, &signature, body)?;

        let events: Vec<SendgridWebhookEvent> = parse_json_array_or_single(body)?;
        let updates = events
            .into_iter()
            .filter_map(|event| {
                let status = sendgrid_event_status(&event.event_type)?;
                let provider_message_id = event.provider_message_id();
                let lookup = lookup_from_sendgrid_event(&event, provider_message_id.clone()).ok()?;
                Some(DeliveryUpdate {
                    lookup,
                    provider_message_id: provider_message_id.clone(),
                    event_kind: match status {
                        DeliveryTerminalStatus::Delivered => {
                            NotificationEventKind::DeliveryDelivered
                        }
                        DeliveryTerminalStatus::Failed(_) => NotificationEventKind::DeliveryFailed,
                    },
                    event_summary: match status {
                        DeliveryTerminalStatus::Delivered => {
                            "Notification delivery confirmed by SendGrid"
                        }
                        DeliveryTerminalStatus::Failed(_) => {
                            "Notification delivery failed according to SendGrid"
                        }
                    },
                    metadata: json!({
                        "provider": if self.binding_key == "email.twilio" { "twilio" } else { "sendgrid" },
                        "event_type": event.event_type,
                        "provider_message_id": provider_message_id,
                    }),
                    status,
                })
            })
            .collect();

        Ok(ParsedWebhook {
            updates,
            subscription_confirmed: false,
        })
    }
}

impl BrevoWebhookRuntime {
    fn parse(&self, headers: &HeaderMap, body: &[u8]) -> Result<ParsedWebhook, Error> {
        verify_expected_headers(headers, &self.expected_headers)?;

        let events: Vec<BrevoWebhookEvent> = parse_json_array_or_single(body)?;
        let updates = events
            .into_iter()
            .filter_map(|event| {
                let status = brevo_event_status(&event.event_type)?;
                let provider_message_id = event.provider_message_id();
                let lookup =
                    lookup_from_string_tags(&event.tags(), provider_message_id.clone()).ok()?;
                Some(DeliveryUpdate {
                    lookup,
                    provider_message_id: provider_message_id.clone(),
                    event_kind: match status {
                        DeliveryTerminalStatus::Delivered => {
                            NotificationEventKind::DeliveryDelivered
                        }
                        DeliveryTerminalStatus::Failed(_) => NotificationEventKind::DeliveryFailed,
                    },
                    event_summary: match status {
                        DeliveryTerminalStatus::Delivered => {
                            "Notification delivery confirmed by Brevo"
                        }
                        DeliveryTerminalStatus::Failed(_) => {
                            "Notification delivery failed according to Brevo"
                        }
                    },
                    metadata: json!({
                        "provider": "brevo",
                        "event_type": event.event_type,
                        "provider_message_id": provider_message_id,
                    }),
                    status,
                })
            })
            .collect();

        Ok(ParsedWebhook {
            updates,
            subscription_confirmed: false,
        })
    }
}

impl AwsSesWebhookRuntime {
    async fn parse(&self, body: &[u8]) -> Result<ParsedWebhook, Error> {
        let envelope: SnsEnvelope =
            serde_json::from_slice(body).map_err(|error| Error::BadRequest(error.to_string()))?;

        if envelope.topic_arn != self.topic_arn {
            return Err(Error::Unauthorized(format!(
                "unexpected SNS topic {}, expected {}",
                envelope.topic_arn, self.topic_arn
            )));
        }

        verify_sns_signature(
            &self.client,
            &self.allowed_signing_cert_url_prefixes,
            &envelope,
        )
        .await?;

        match envelope.message_type.as_str() {
            "SubscriptionConfirmation" => {
                if self.auto_confirm_subscription {
                    let subscribe_url = envelope.subscribe_url.as_ref().ok_or_else(|| {
                        Error::BadRequest(
                            "SNS SubscriptionConfirmation missing SubscribeURL".into(),
                        )
                    })?;
                    self.client
                        .get(subscribe_url)
                        .send()
                        .await
                        .context("failed to confirm SNS subscription")?
                        .error_for_status()
                        .context("SNS subscription confirmation was rejected")?;
                }

                Ok(ParsedWebhook {
                    updates: Vec::new(),
                    subscription_confirmed: self.auto_confirm_subscription,
                })
            }
            "Notification" => {
                let message: SesSnsMessage = serde_json::from_str(&envelope.message)
                    .map_err(|error| Error::BadRequest(error.to_string()))?;
                let Some(status) = ses_event_status(message.event_type()) else {
                    return Ok(ParsedWebhook {
                        updates: Vec::new(),
                        subscription_confirmed: false,
                    });
                };

                let provider_message_id = message.mail_message_id();
                let lookup =
                    lookup_from_string_map_tags(&message.mail_tags(), provider_message_id.clone())?;

                Ok(ParsedWebhook {
                    updates: vec![DeliveryUpdate {
                        lookup,
                        provider_message_id: provider_message_id.clone(),
                        event_kind: match status {
                            DeliveryTerminalStatus::Delivered => {
                                NotificationEventKind::DeliveryDelivered
                            }
                            DeliveryTerminalStatus::Failed(_) => {
                                NotificationEventKind::DeliveryFailed
                            }
                        },
                        event_summary: match status {
                            DeliveryTerminalStatus::Delivered => {
                                "Notification delivery confirmed by AWS SES"
                            }
                            DeliveryTerminalStatus::Failed(_) => {
                                "Notification delivery failed according to AWS SES"
                            }
                        },
                        metadata: json!({
                            "provider": "aws_ses",
                            "event_type": message.event_type(),
                            "provider_message_id": provider_message_id,
                        }),
                        status,
                    }],
                    subscription_confirmed: false,
                })
            }
            "UnsubscribeConfirmation" => Ok(ParsedWebhook {
                updates: Vec::new(),
                subscription_confirmed: false,
            }),
            other => Err(Error::BadRequest(format!(
                "unsupported SNS message type {other}"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ResendWebhookEvent {
    #[serde(rename = "type")]
    event_type: String,
    data: ResendWebhookData,
}

#[derive(Debug, Deserialize)]
struct ResendWebhookData {
    #[serde(default)]
    email_id: Option<String>,
    #[serde(default)]
    tags: Option<Vec<ResendWebhookTag>>,
}

#[derive(Debug, Deserialize)]
struct ResendWebhookTag {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct SendgridWebhookEvent {
    #[serde(rename = "event")]
    event_type: String,
    #[serde(rename = "sg_message_id")]
    sg_message_id: Option<String>,
    #[serde(rename = "smtp-id")]
    smtp_id: Option<String>,
    #[serde(default)]
    custom_args: BTreeMap<String, String>,
    #[serde(default)]
    unique_args: BTreeMap<String, String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl SendgridWebhookEvent {
    fn provider_message_id(&self) -> Option<String> {
        self.sg_message_id
            .clone()
            .or_else(|| self.smtp_id.clone())
            .filter(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Deserialize)]
struct BrevoWebhookEvent {
    #[serde(rename = "event")]
    event_type: String,
    #[serde(rename = "message-id")]
    message_id: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    tags: Option<BrevoTagList>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BrevoTagList {
    One(String),
    Many(Vec<String>),
}

impl BrevoWebhookEvent {
    fn provider_message_id(&self) -> Option<String> {
        self.message_id
            .clone()
            .filter(|value| !value.trim().is_empty())
    }

    fn tags(&self) -> Vec<String> {
        let mut tags = Vec::new();
        if let Some(tag) = &self.tag {
            tags.push(tag.clone());
        }
        match &self.tags {
            Some(BrevoTagList::One(tag)) => tags.push(tag.clone()),
            Some(BrevoTagList::Many(values)) => tags.extend(values.iter().cloned()),
            None => {}
        }
        tags
    }
}

#[derive(Debug, Deserialize)]
struct SnsEnvelope {
    #[serde(rename = "Type")]
    message_type: String,
    #[serde(rename = "MessageId")]
    message_id: String,
    #[serde(rename = "TopicArn")]
    topic_arn: String,
    #[serde(rename = "Subject")]
    subject: Option<String>,
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "SignatureVersion")]
    signature_version: String,
    #[serde(rename = "Signature")]
    signature: String,
    #[serde(rename = "SigningCertURL")]
    signing_cert_url: String,
    #[serde(rename = "SubscribeURL")]
    subscribe_url: Option<String>,
    #[serde(rename = "Token")]
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SesSnsMessage {
    #[serde(rename = "eventType")]
    event_type: String,
    mail: SesMail,
}

#[derive(Debug, Deserialize)]
struct SesMail {
    #[serde(rename = "messageId")]
    message_id: Option<String>,
    #[serde(default)]
    tags: BTreeMap<String, Vec<String>>,
}

impl SesSnsMessage {
    fn event_type(&self) -> &str {
        &self.event_type
    }

    fn mail_message_id(&self) -> Option<String> {
        self.mail.message_id.clone()
    }

    fn mail_tags(&self) -> BTreeMap<String, String> {
        flatten_ses_tags(&self.mail.tags)
    }
}

fn flatten_ses_tags(tags: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, String> {
    tags.iter()
        .filter_map(|(name, values)| values.first().map(|value| (name.clone(), value.clone())))
        .collect()
}

fn parse_json_array_or_single<T>(body: &[u8]) -> Result<Vec<T>, Error>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice::<Vec<T>>(body)
        .or_else(|_| serde_json::from_slice(body).map(|value| vec![value]))
        .map_err(|error| Error::BadRequest(error.to_string()))
}

fn resend_event_status(event_type: &str) -> Option<DeliveryTerminalStatus> {
    match event_type.trim().to_ascii_lowercase().as_str() {
        "email.delivered" => Some(DeliveryTerminalStatus::Delivered),
        "email.bounced" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "email_bounced",
            "Resend reported that the email bounced",
        ))),
        "email.complained" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "email_complained",
            "Resend reported a recipient complaint",
        ))),
        _ => None,
    }
}

fn sendgrid_event_status(event_type: &str) -> Option<DeliveryTerminalStatus> {
    match event_type.trim().to_ascii_lowercase().as_str() {
        "delivered" => Some(DeliveryTerminalStatus::Delivered),
        "bounce" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "bounce",
            "SendGrid reported that the email bounced",
        ))),
        "blocked" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "blocked",
            "SendGrid blocked the email",
        ))),
        "dropped" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "dropped",
            "SendGrid dropped the email before delivery",
        ))),
        "spamreport" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "spamreport",
            "SendGrid reported the email as spam",
        ))),
        _ => None,
    }
}

fn brevo_event_status(event_type: &str) -> Option<DeliveryTerminalStatus> {
    match normalize_event_type(event_type).as_str() {
        "delivered" => Some(DeliveryTerminalStatus::Delivered),
        "hardbounce" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "hard_bounce",
            "Brevo reported a hard bounce",
        ))),
        "softbounce" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "soft_bounce",
            "Brevo reported a soft bounce",
        ))),
        "blocked" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "blocked",
            "Brevo blocked the email",
        ))),
        "error" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "error",
            "Brevo reported a delivery error",
        ))),
        "invalid" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "invalid",
            "Brevo reported an invalid recipient",
        ))),
        "spam" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "spam",
            "Brevo reported the email as spam",
        ))),
        _ => None,
    }
}

fn ses_event_status(event_type: &str) -> Option<DeliveryTerminalStatus> {
    match normalize_event_type(event_type).as_str() {
        "delivery" | "delivered" => Some(DeliveryTerminalStatus::Delivered),
        "bounce" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "bounce",
            "AWS SES reported that the email bounced",
        ))),
        "complaint" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "complaint",
            "AWS SES reported a recipient complaint",
        ))),
        "reject" | "rejected" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "reject",
            "AWS SES rejected the email",
        ))),
        "renderingfailure" => Some(DeliveryTerminalStatus::Failed(webhook_failure(
            "rendering_failure",
            "AWS SES reported a rendering failure",
        ))),
        _ => None,
    }
}

fn normalize_event_type(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn webhook_failure(code: &str, message: &str) -> NotificationDeliveryFailure {
    NotificationDeliveryFailure {
        code: Some(code.to_owned()),
        message: Some(message.to_owned()),
        retryable: false,
    }
}

fn lookup_from_key_value_tags(
    tags: &[ResendWebhookTag],
    provider_message_id: Option<String>,
) -> Result<DeliveryLookup, Error> {
    let tags = tags
        .iter()
        .map(|tag| (tag.name.clone(), tag.value.clone()))
        .collect::<BTreeMap<_, _>>();
    lookup_from_string_map_tags(&tags, provider_message_id)
}

fn lookup_from_sendgrid_event(
    event: &SendgridWebhookEvent,
    provider_message_id: Option<String>,
) -> Result<DeliveryLookup, Error> {
    if let Some(value) = event
        .custom_args
        .get(DELIVERY_ID_TAG)
        .or_else(|| event.unique_args.get(DELIVERY_ID_TAG))
        .cloned()
    {
        return value
            .parse()
            .map(DeliveryLookup::DeliveryId)
            .map_err(|error| {
                Error::BadRequest(format!("invalid delivery id in webhook tag: {error}"))
            });
    }

    if let Some(value) = event
        .extra
        .get(DELIVERY_ID_TAG)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    {
        return value
            .parse()
            .map(DeliveryLookup::DeliveryId)
            .map_err(|error| {
                Error::BadRequest(format!("invalid delivery id in webhook tag: {error}"))
            });
    }

    provider_message_id
        .map(DeliveryLookup::ProviderMessageId)
        .ok_or_else(|| {
            Error::BadRequest("webhook event is missing a correlating message id".into())
        })
}

fn lookup_from_string_tags(
    tags: &[String],
    provider_message_id: Option<String>,
) -> Result<DeliveryLookup, Error> {
    for tag in tags {
        if let Some((name, value)) = parse_key_value_tag(tag)
            && name == DELIVERY_ID_TAG
        {
            return value
                .parse()
                .map(DeliveryLookup::DeliveryId)
                .map_err(|error| {
                    Error::BadRequest(format!("invalid delivery id in webhook tag: {error}"))
                });
        }
    }

    provider_message_id
        .map(DeliveryLookup::ProviderMessageId)
        .ok_or_else(|| {
            Error::BadRequest("webhook event is missing a correlating message id".into())
        })
}

fn lookup_from_string_map_tags(
    tags: &BTreeMap<String, String>,
    provider_message_id: Option<String>,
) -> Result<DeliveryLookup, Error> {
    if let Some(value) = tags.get(DELIVERY_ID_TAG) {
        return value
            .parse()
            .map(DeliveryLookup::DeliveryId)
            .map_err(|error| {
                Error::BadRequest(format!("invalid delivery id in webhook tag: {error}"))
            });
    }

    provider_message_id
        .map(DeliveryLookup::ProviderMessageId)
        .ok_or_else(|| {
            Error::BadRequest("webhook event is missing a correlating message id".into())
        })
}

fn parse_key_value_tag(tag: &str) -> Option<(&str, &str)> {
    tag.split_once('=').or_else(|| tag.split_once(':'))
}

fn should_apply_delivery_update(
    current_status: NotificationDeliveryStatus,
    current_failure: Option<&NotificationDeliveryFailure>,
    update: &DeliveryTerminalStatus,
) -> bool {
    match update {
        DeliveryTerminalStatus::Delivered => !matches!(
            current_status,
            NotificationDeliveryStatus::Delivered
                | NotificationDeliveryStatus::Failed
                | NotificationDeliveryStatus::Cancelled
        ),
        DeliveryTerminalStatus::Failed(failure) => {
            !(current_status == NotificationDeliveryStatus::Failed
                && current_failure == Some(failure))
        }
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_expected_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}

fn verify_expected_headers(
    headers: &HeaderMap,
    expected_headers: &BTreeMap<String, String>,
) -> Result<(), Error> {
    for (name, expected) in expected_headers {
        let actual = header_str(headers, name)
            .ok_or_else(|| Error::Unauthorized(format!("missing expected header {name}")))?;
        if actual != *expected {
            return Err(Error::Unauthorized(format!(
                "unexpected value for header {name}"
            )));
        }
    }

    Ok(())
}

fn decode_resend_signing_secret(secret: &str) -> Result<Vec<u8>, Error> {
    let secret = secret.strip_prefix("whsec_").unwrap_or(secret);
    Base64::decode_vec(secret).map_err(|error| {
        Error::BadRequest(format!("invalid Resend webhook signing secret: {error}"))
    })
}

fn verify_resend_signature(
    signing_secret: &[u8],
    max_age_seconds: u64,
    message_id: &str,
    timestamp: &str,
    signature_header: &str,
    body: &[u8],
) -> Result<(), Error> {
    let timestamp = timestamp
        .parse::<i64>()
        .map_err(|error| Error::Unauthorized(format!("invalid svix timestamp: {error}")))?;
    let signed_at = Utc
        .timestamp_opt(timestamp, 0)
        .single()
        .ok_or_else(|| Error::Unauthorized("invalid svix timestamp".to_owned()))?;
    let age = Utc::now()
        .signed_duration_since(signed_at)
        .num_seconds()
        .unsigned_abs();
    if age > max_age_seconds {
        return Err(Error::Unauthorized(
            "svix timestamp is outside the accepted age".into(),
        ));
    }

    let payload = std::str::from_utf8(body)
        .map_err(|error| Error::BadRequest(format!("webhook body is not valid UTF-8: {error}")))?;
    let signed_content = format!("{message_id}.{timestamp}.{payload}");

    for part in signature_header.split_whitespace() {
        let Some(signature) = part.strip_prefix("v1,") else {
            continue;
        };
        let Ok(signature_bytes) = Base64::decode_vec(signature) else {
            continue;
        };
        let mut mac =
            HmacSha256::new_from_slice(signing_secret).expect("HMAC accepts arbitrary key lengths");
        mac.update(signed_content.as_bytes());
        if mac.verify_slice(&signature_bytes).is_ok() {
            return Ok(());
        }
    }

    Err(Error::Unauthorized(
        "failed to verify Resend webhook signature".into(),
    ))
}

fn parse_sendgrid_public_key(public_key_pem: &str) -> Result<P256VerifyingKey, Error> {
    P256VerifyingKey::from_public_key_pem(public_key_pem).map_err(|error| {
        Error::BadRequest(format!(
            "invalid SendGrid event webhook public key: {error}"
        ))
    })
}

fn verify_sendgrid_signature(
    verifying_key: &P256VerifyingKey,
    timestamp: &str,
    signature: &str,
    body: &[u8],
) -> Result<(), Error> {
    let mut signed_payload = timestamp.as_bytes().to_vec();
    signed_payload.extend_from_slice(body);
    let signature = Base64::decode_vec(signature).map_err(|error| {
        Error::Unauthorized(format!("invalid SendGrid signature encoding: {error}"))
    })?;
    let signature = P256Signature::from_der(&signature).map_err(|error| {
        Error::Unauthorized(format!("invalid SendGrid signature bytes: {error}"))
    })?;
    verifying_key
        .verify(&signed_payload, &signature)
        .map_err(|_| Error::Unauthorized("failed to verify SendGrid webhook signature".into()))
}

fn sns_signed_content(envelope: &SnsEnvelope) -> Result<String, Error> {
    let mut output = String::new();
    match envelope.message_type.as_str() {
        "Notification" => {
            append_sns_field(&mut output, "Message", &envelope.message);
            append_sns_field(&mut output, "MessageId", &envelope.message_id);
            if let Some(subject) = &envelope.subject {
                append_sns_field(&mut output, "Subject", subject);
            }
            append_sns_field(&mut output, "Timestamp", &envelope.timestamp);
            append_sns_field(&mut output, "TopicArn", &envelope.topic_arn);
            append_sns_field(&mut output, "Type", &envelope.message_type);
        }
        "SubscriptionConfirmation" | "UnsubscribeConfirmation" => {
            append_sns_field(&mut output, "Message", &envelope.message);
            append_sns_field(&mut output, "MessageId", &envelope.message_id);
            append_sns_field(
                &mut output,
                "SubscribeURL",
                envelope.subscribe_url.as_deref().ok_or_else(|| {
                    Error::BadRequest("SNS message is missing SubscribeURL".into())
                })?,
            );
            append_sns_field(&mut output, "Timestamp", &envelope.timestamp);
            append_sns_field(
                &mut output,
                "Token",
                envelope
                    .token
                    .as_deref()
                    .ok_or_else(|| Error::BadRequest("SNS message is missing Token".into()))?,
            );
            append_sns_field(&mut output, "TopicArn", &envelope.topic_arn);
            append_sns_field(&mut output, "Type", &envelope.message_type);
        }
        other => {
            return Err(Error::BadRequest(format!(
                "unsupported SNS message type {other}"
            )));
        }
    }

    Ok(output)
}

fn append_sns_field(output: &mut String, name: &str, value: &str) {
    output.push_str(name);
    output.push('\n');
    output.push_str(value);
    output.push('\n');
}

async fn verify_sns_signature(
    client: &reqwest::Client,
    allowed_prefixes: &[String],
    envelope: &SnsEnvelope,
) -> Result<(), Error> {
    validate_sns_signing_cert_url(&envelope.signing_cert_url, allowed_prefixes)?;

    let cert_pem = client
        .get(&envelope.signing_cert_url)
        .send()
        .await
        .context("failed to fetch SNS signing certificate")?
        .error_for_status()
        .context("SNS signing certificate request failed")?
        .text()
        .await
        .context("failed to read SNS signing certificate")?;
    let certificate = Certificate::from_pem(&cert_pem).map_err(|error| {
        Error::Unauthorized(format!("invalid SNS signing certificate: {error}"))
    })?;
    let public_key_der = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("failed to encode SNS subject public key")?;
    let public_key = RsaPublicKey::from_public_key_der(&public_key_der).map_err(|error| {
        Error::Unauthorized(format!("failed to parse SNS signing public key: {error}"))
    })?;
    let signature = Base64::decode_vec(&envelope.signature)
        .map_err(|error| Error::Unauthorized(format!("invalid SNS signature: {error}")))?;
    let signature = RsaPkcs1v15Signature::try_from(signature.as_slice())
        .map_err(|error| Error::Unauthorized(format!("invalid SNS signature bytes: {error}")))?;
    let signed_content = sns_signed_content(envelope)?;

    match envelope.signature_version.as_str() {
        "1" => RsaVerifyingKey::<Sha1>::new(public_key)
            .verify(signed_content.as_bytes(), &signature)
            .map_err(|_| Error::Unauthorized("failed to verify SNS signature".into())),
        "2" => RsaVerifyingKey::<Sha256>::new(public_key)
            .verify(signed_content.as_bytes(), &signature)
            .map_err(|_| Error::Unauthorized("failed to verify SNS signature".into())),
        other => Err(Error::Unauthorized(format!(
            "unsupported SNS signature version {other}"
        ))),
    }
}

fn validate_sns_signing_cert_url(
    signing_cert_url: &str,
    allowed_prefixes: &[String],
) -> Result<(), Error> {
    let url = Url::parse(signing_cert_url)
        .map_err(|error| Error::Unauthorized(format!("invalid SNS SigningCertURL: {error}")))?;

    if url.scheme() != "https" {
        return Err(Error::Unauthorized(
            "SNS SigningCertURL must use HTTPS".into(),
        ));
    }

    if !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Unauthorized(
            "SNS SigningCertURL must not contain credentials, ports, query strings, or fragments"
                .into(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| Error::Unauthorized("SNS SigningCertURL is missing a host".into()))?
        .to_ascii_lowercase();
    let path = url.path();

    if !host.ends_with(".amazonaws.com") && !host.ends_with(".amazonaws.com.cn") {
        return Err(Error::Unauthorized(
            "SNS SigningCertURL host must be an AWS SNS endpoint".into(),
        ));
    }

    if !path.starts_with("/SimpleNotificationService-")
        || !path
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("pem"))
    {
        return Err(Error::Unauthorized(
            "SNS SigningCertURL path must reference a SimpleNotificationService PEM certificate"
                .into(),
        ));
    }

    let normalized_url = format!("https://{host}{path}");
    if !allowed_prefixes.iter().any(|prefix| {
        let prefix = prefix.trim().trim_end_matches('/').to_ascii_lowercase();
        if prefix.is_empty() {
            return false;
        }

        if prefix.starts_with("https://") {
            normalized_url.starts_with(&prefix)
        } else {
            host.starts_with(
                prefix
                    .trim_start_matches("http://")
                    .trim_start_matches("https://"),
            )
        }
    }) {
        return Err(Error::Unauthorized(
            "SNS SigningCertURL does not match the allowed prefixes".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tracking_tag_with_equals() {
        let lookup = lookup_from_string_tags(
            &[format!("{DELIVERY_ID_TAG}=01J00000000000000000000000")],
            None,
        )
        .unwrap();

        assert!(matches!(lookup, DeliveryLookup::DeliveryId(_)));
    }

    #[test]
    fn sendgrid_event_uses_custom_args() {
        let event = SendgridWebhookEvent {
            event_type: "delivered".to_owned(),
            sg_message_id: Some("sg_123".to_owned()),
            smtp_id: None,
            custom_args: BTreeMap::from([(
                DELIVERY_ID_TAG.to_owned(),
                "01J00000000000000000000000".to_owned(),
            )]),
            unique_args: BTreeMap::new(),
            extra: BTreeMap::new(),
        };

        let lookup = lookup_from_sendgrid_event(&event, event.provider_message_id()).unwrap();
        assert!(matches!(lookup, DeliveryLookup::DeliveryId(_)));
    }

    #[test]
    fn brevo_event_uses_tracking_tag() {
        let lookup = lookup_from_string_tags(
            &[format!("{DELIVERY_ID_TAG}:01J00000000000000000000000")],
            Some("message-1".to_owned()),
        )
        .unwrap();

        assert!(matches!(lookup, DeliveryLookup::DeliveryId(_)));
    }

    #[test]
    fn delivered_webhook_does_not_override_failed_delivery() {
        assert!(!should_apply_delivery_update(
            NotificationDeliveryStatus::Failed,
            Some(&webhook_failure(
                "bounce",
                "SendGrid reported that the email bounced"
            )),
            &DeliveryTerminalStatus::Delivered,
        ));
    }

    #[test]
    fn sns_signing_cert_url_rejects_lookalike_host() {
        let error = validate_sns_signing_cert_url(
            "https://sns.evil.com/SimpleNotificationService-test.pem",
            &[String::from("https://sns.")],
        )
        .unwrap_err();

        assert!(matches!(error, Error::Unauthorized(_)));
    }

    #[test]
    fn sns_signing_cert_url_accepts_aws_host() {
        validate_sns_signing_cert_url(
            "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem",
            &[String::from("https://sns.")],
        )
        .unwrap();
    }
}
