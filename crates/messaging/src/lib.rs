//! Unified notification delivery for the coauth authentication service.
//!
//! Provides email and SMS transports behind a common trait interface.

#![deny(missing_docs)]

pub mod email;
mod notification;
pub mod sms;

pub use self::notification::{
    NotificationCenter, NotificationDispatchResult, NotificationError, NotificationRequest,
};
