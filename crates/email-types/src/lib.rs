//! Validated email address and mailbox value types.
//!
//! These types intentionally contain no delivery/runtime dependencies. Shared
//! API and data crates can validate addresses without pulling an SMTP client
//! (and all of its optional runtimes) into browser or admin applications.

use std::fmt;
use std::str::FromStr;

use email_address::{EmailAddress, Options};

/// A validated addr-spec without an RFC 5322 display name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(EmailAddress);

impl Address {
    /// Return the local part of the address.
    #[must_use]
    pub fn user(&self) -> &str {
        self.0.local_part()
    }

    /// Return the domain part of the address.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.0.domain()
    }
}

impl FromStr for Address {
    type Err = email_address::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        EmailAddress::parse_with_options(value, Options::default().without_display_text()).map(Self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0.as_str())
    }
}

impl AsRef<str> for Address {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// A validated email address with an optional display name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mailbox {
    /// Display name associated with the address.
    pub name: Option<String>,
    /// Validated addr-spec.
    pub email: Address,
}

impl Mailbox {
    /// Construct a mailbox from an already validated address.
    #[must_use]
    pub fn new(name: Option<String>, email: Address) -> Self {
        let name = name.and_then(|name| {
            let name = name.trim();
            (!name.is_empty()).then(|| name.to_owned())
        });
        Self { name, email }
    }
}

impl From<Address> for Mailbox {
    fn from(address: Address) -> Self {
        Self::new(None, address)
    }
}

impl FromStr for Mailbox {
    type Err = email_address::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = EmailAddress::from_str(value)?;
        let address = Address::from_str(&parsed.email())?;
        let display = parsed.display_part().trim();
        let name = if display.len() >= 2 && display.starts_with('"') && display.ends_with('"') {
            Some(
                display[1..display.len() - 1]
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\"),
            )
        } else {
            (!display.is_empty()).then(|| display.to_owned())
        };
        Ok(Self::new(name, address))
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            Some(name) => write!(formatter, "{name} <{}>", self.email),
            None => self.email.fmt(formatter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_rejects_display_name() {
        assert!("Alice <alice@example.com>".parse::<Address>().is_err());
        assert!("alice@example.com".parse::<Address>().is_ok());
    }

    #[test]
    fn mailbox_parses_display_name() {
        let mailbox: Mailbox = "Alice <alice@example.com>".parse().unwrap();
        assert_eq!(mailbox.name.as_deref(), Some("Alice"));
        assert_eq!(mailbox.email.as_ref(), "alice@example.com");
        assert_eq!(mailbox.to_string(), "Alice <alice@example.com>");
    }

    #[test]
    fn mailbox_rejects_header_injection() {
        assert!(
            "alice@example.com\r\nBcc: victim@example.com"
                .parse::<Mailbox>()
                .is_err()
        );
    }
}
