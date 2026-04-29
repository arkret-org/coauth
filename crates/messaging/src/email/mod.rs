//! Helps sending emails to users, with different email backends

mod mailer;
mod transport;

/// Internal metadata key used to round-trip the notification delivery id
/// through provider-specific tags or custom arguments.
pub const DELIVERY_ID_TAG: &str = "coauth_delivery_id";

/// Internal metadata key used to round-trip the notification request id
/// through provider-specific tags or custom arguments.
pub const REQUEST_ID_TAG: &str = "coauth_notification_request_id";

pub use coauth_templates::EmailVerificationContext;
pub use lettre::{
    Address, message::Mailbox, transport::smtp::authentication::Credentials as SmtpCredentials,
};

pub use self::{
    mailer::{Error as MailerError, Mailer},
    transport::{
        EmailProvider, Error as EmailTransportError, OutboundEmail, SendResult, SmtpMode, Transport,
    },
};
