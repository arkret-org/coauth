//! Unified notification delivery for the Pasion authentication service.
//!
//! Provides email and SMS transports behind a common trait interface.

#![deny(missing_docs)]

pub mod email;
mod notification;
pub mod sms;

// Re-export commonly used types from email for backward compatibility
pub use lettre::{
    Address, message::Mailbox, transport::smtp::authentication::Credentials as SmtpCredentials,
};
pub use coauth_templates::EmailVerificationContext;

pub use self::{
    email::{Mailer, SendResult as EmailSendResult, SmtpMode, Transport as MailTransport},
    notification::{
        NotificationCenter, NotificationDispatchResult, NotificationError, NotificationRequest,
    },
    sms::{SmsSender, SmsTransport, SmsTransportError},
};
