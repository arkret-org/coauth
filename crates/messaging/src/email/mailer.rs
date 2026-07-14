//! Send emails to users

use std::collections::BTreeMap;

use coauth_email_types::Mailbox;
use coauth_templates::{EmailRecoveryContext, EmailVerificationContext, Templates, WithLanguage};
use thiserror::Error;

use super::transport::{Error as TransportError, Transport as MailTransport};
use super::{OutboundEmail, SendResult};

/// Helps sending mails to users
#[derive(Clone)]
pub struct Mailer {
    templates: Templates,
    transport: MailTransport,
    from: Mailbox,
    reply_to: Mailbox,
}

/// Errors that can occur while preparing or sending an email.
#[derive(Debug, Error)]
#[error(transparent)]
pub enum Error {
    /// The configured email transport failed.
    Transport(#[from] TransportError),
    /// Rendering the email templates failed.
    Templates(#[from] coauth_templates::TemplateError),
}

impl Mailer {
    /// Constructs a new [`Mailer`]
    #[must_use]
    pub fn new(
        templates: Templates,
        transport: MailTransport,
        from: Mailbox,
        reply_to: Mailbox,
    ) -> Self {
        Self {
            templates,
            transport,
            from,
            reply_to,
        }
    }

    fn outbound_email(
        &self,
        to: Mailbox,
        subject: String,
        text_body: String,
        html_body: Option<String>,
        tags: &BTreeMap<String, String>,
    ) -> OutboundEmail {
        OutboundEmail {
            from: self.from.clone(),
            reply_to: Some(self.reply_to.clone()),
            to: vec![to],
            subject: subject.trim().to_owned(),
            text_body,
            html_body,
            headers: BTreeMap::new(),
            tags: tags.clone(),
        }
    }

    fn prepare_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<OutboundEmail, Error> {
        let text_body = self.templates.render_email_verification_txt(context)?;
        let html_body = self.templates.render_email_verification_html(context)?;
        let subject = self.templates.render_email_verification_subject(context)?;

        Ok(self.outbound_email(to, subject, text_body, Some(html_body), tags))
    }

    fn prepare_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<OutboundEmail, Error> {
        let text_body = self.templates.render_email_recovery_txt(context)?;
        let html_body = self.templates.render_email_recovery_html(context)?;
        let subject = self.templates.render_email_recovery_subject(context)?;

        Ok(self.outbound_email(to, subject, text_body, Some(html_body), tags))
    }

    /// Send the verification email to a user.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending.
    #[tracing::instrument(
        name = "email.verification.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
        ),
    )]
    pub async fn send_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<SendResult, Error> {
        tracing::debug!("Preparing verification email");
        let email = self.prepare_verification_email(to, context, tags)?;
        tracing::debug!("Sending verification email");
        let result = self.transport.send(&email).await?;
        tracing::debug!("Verification email accepted by provider");
        Ok(result)
    }

    /// Send the recovery email to a user.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending.
    #[tracing::instrument(
        name = "email.recovery.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
            user.id = %context.user().id,
            user_recovery_session.id = %context.session().id,
        ),
    )]
    pub async fn send_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
        tags: &BTreeMap<String, String>,
    ) -> Result<SendResult, Error> {
        tracing::debug!("Preparing recovery email");
        let email = self.prepare_recovery_email(to, context, tags)?;
        tracing::debug!("Sending recovery email");
        let result = self.transport.send(&email).await?;
        tracing::debug!("Recovery email accepted by provider");
        Ok(result)
    }

    /// Test the connection to the mail server.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection failed.
    #[tracing::instrument(name = "email.test_connection", skip_all)]
    pub async fn test_connection(&self) -> Result<(), TransportError> {
        self.transport.test_connection(&self.from).await
    }

    /// Return the stable provider binding key for the configured transport.
    #[must_use]
    pub fn provider_binding_key(&self) -> &'static str {
        self.transport.binding_key()
    }
}
