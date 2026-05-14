//! The [`ClientRegistrationResponse`] type returned by the dynamic client
//! registration endpoint.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{TimestampSeconds, serde_as, skip_serializing_none};

/// The issuer response to dynamic client registration.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ClientRegistrationResponse {
    /// A unique client identifier.
    pub client_id: String,

    /// A client secret, if the `token_endpoint_auth_method` requires one.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Time at which the Client Identifier was issued.
    #[serde(default)]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub client_id_issued_at: Option<DateTime<Utc>>,

    /// Time at which the `client_secret` will expire or 0 if it will not
    /// expire.
    ///
    /// Required if `client_secret` is issued.
    #[serde(default)]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub client_secret_expires_at: Option<DateTime<Utc>>,
}
