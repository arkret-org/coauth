//! Post-authentication action types.
//!
//! These types describe what should happen after a user completes an
//! authentication step (login, registration, etc.).

use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Actions parameters as defined by MSC4191.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum AccountAction {
    #[serde(rename = "org.matrix.profile")]
    OrgMatrixProfile,
    #[serde(rename = "profile")]
    Profile,

    #[serde(rename = "org.matrix.devices_list")]
    OrgMatrixDevicesList,
    #[serde(rename = "org.matrix.sessions_list")]
    OrgMatrixSessionsList,
    #[serde(rename = "sessions_list")]
    SessionsList,

    #[serde(rename = "org.matrix.device_view")]
    OrgMatrixDeviceView { device_id: String },
    #[serde(rename = "org.matrix.session_view")]
    OrgMatrixSessionView { device_id: String },
    #[serde(rename = "session_view")]
    SessionView { device_id: String },

    #[serde(rename = "org.matrix.device_delete")]
    OrgMatrixDeviceDelete { device_id: String },
    #[serde(rename = "org.matrix.session_end")]
    OrgMatrixSessionEnd { device_id: String },
    #[serde(rename = "session_end")]
    SessionEnd { device_id: String },

    #[serde(rename = "org.matrix.cross_signing_reset")]
    OrgMatrixCrossSigningReset,
}

/// Describes what should happen after a user completes authentication.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PostAuthAction {
    ContinueAuthorizationGrant {
        id: Ulid,
    },
    ContinueDeviceCodeGrant {
        id: Ulid,
    },
    ChangePassword,
    LinkUpstream {
        id: Ulid,
    },
    ManageAccount {
        #[serde(flatten)]
        action: Option<AccountAction>,
    },
}

impl PostAuthAction {
    #[must_use]
    pub const fn continue_grant(id: Ulid) -> Self {
        PostAuthAction::ContinueAuthorizationGrant { id }
    }

    #[must_use]
    pub const fn continue_device_code_grant(id: Ulid) -> Self {
        PostAuthAction::ContinueDeviceCodeGrant { id }
    }

    #[must_use]
    pub const fn link_upstream(id: Ulid) -> Self {
        PostAuthAction::LinkUpstream { id }
    }

    #[must_use]
    pub const fn manage_account(action: Option<AccountAction>) -> Self {
        PostAuthAction::ManageAccount { action }
    }
}
