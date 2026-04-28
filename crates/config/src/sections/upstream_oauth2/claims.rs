// ── Claims Import Configuration ──
//
// Defines how user attributes from an upstream identity provider are
// mapped and imported into the local system during account linking.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Import Action ──

/// Controls how a single upstream claim is handled during account linking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportAction {
    /// Ignore the claim entirely
    #[default]
    Ignore,

    /// Pre-fill the claim value but let the user modify it
    Suggest,

    /// Overwrite the local value unconditionally (skip if missing)
    Force,

    /// Overwrite the local value unconditionally (fail if missing)
    Require,
}

impl ImportAction {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) const fn is_default(&self) -> bool {
        matches!(self, Self::Ignore)
    }
}

// ── On Conflict ──

/// Determines what happens when an upstream identity matches an existing
/// local account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OnConflict {
    /// Reject the upstream login when a conflict is detected
    #[default]
    Fail,

    /// Link the upstream identity unconditionally, even if another link exists
    Add,

    /// Remove any prior upstream identity link and create a new one
    Replace,

    /// Link only when no prior link for this provider exists on the user
    Set,
}

impl OnConflict {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) const fn is_default(&self) -> bool {
        matches!(self, Self::Fail)
    }
}

// ── Subject Import ──

/// Controls how the subject identifier is derived from upstream claims
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct SubjectImportPreference {
    /// A Jinja2 template for the subject attribute.
    ///
    /// Defaults to `{{ user.sub }}` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl SubjectImportPreference {
    pub(crate) const fn is_default(&self) -> bool {
        self.template.is_none()
    }
}

// ── Localpart Import ──

/// Controls how the MXID localpart is imported from upstream claims
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct LocalpartImportPreference {
    /// How to handle the localpart attribute
    #[serde(default, skip_serializing_if = "ImportAction::is_default")]
    pub action: ImportAction,

    /// A Jinja2 template for the localpart attribute.
    ///
    /// Defaults to `{{ user.preferred_username }}` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,

    /// How to handle conflicts on the localpart claim
    #[serde(default, skip_serializing_if = "OnConflict::is_default")]
    pub on_conflict: OnConflict,
}

impl LocalpartImportPreference {
    pub(crate) const fn is_default(&self) -> bool {
        self.action.is_default() && self.template.is_none()
    }
}

// ── Displayname Import ──

/// Controls how the display name attribute is imported from upstream claims
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct DisplaynameImportPreference {
    /// How to handle the displayname attribute
    #[serde(default, skip_serializing_if = "ImportAction::is_default")]
    pub action: ImportAction,

    /// A Jinja2 template for the displayname attribute.
    ///
    /// Defaults to `{{ user.name }}` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl DisplaynameImportPreference {
    pub(crate) const fn is_default(&self) -> bool {
        self.action.is_default() && self.template.is_none()
    }
}

// ── Email Import ──

/// Controls how the email address attribute is imported from upstream claims
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct EmailImportPreference {
    /// How to handle the email claim
    #[serde(default, skip_serializing_if = "ImportAction::is_default")]
    pub action: ImportAction,

    /// A Jinja2 template for the email address attribute.
    ///
    /// Defaults to `{{ user.email }}` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl EmailImportPreference {
    pub(crate) const fn is_default(&self) -> bool {
        self.action.is_default() && self.template.is_none()
    }
}

// ── Avatar Import ──

/// Controls how the avatar URL attribute is imported from upstream claims
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct AvatarImportPreference {
    /// How to handle the avatar attribute
    #[serde(default, skip_serializing_if = "ImportAction::is_default")]
    pub action: ImportAction,

    /// A Jinja2 template for the avatar URL attribute.
    ///
    /// Defaults to `{{ user.picture }}` when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl AvatarImportPreference {
    pub(crate) const fn is_default(&self) -> bool {
        self.action.is_default() && self.template.is_none()
    }
}

// ── Account Name Import ──

/// Controls how the upstream account display name is derived
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct AccountNameImportPreference {
    /// A Jinja2 template for the account name (used for display only).
    ///
    /// When omitted the account name is not imported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl AccountNameImportPreference {
    pub(crate) const fn is_default(&self) -> bool {
        self.template.is_none()
    }
}

// ── Aggregate Claims Imports ──

/// Governs how user attributes are imported from the upstream provider
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
pub struct ClaimsImports {
    /// How to determine the subject of the user
    #[serde(default, skip_serializing_if = "SubjectImportPreference::is_default")]
    pub subject: SubjectImportPreference,

    /// When `true`, the interactive confirmation screen is skipped.
    /// Requires `localpart.action` to be `require` and other attribute
    /// actions to be `ignore`, `force`, or `require`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_confirmation: bool,

    /// Import the localpart of the MXID
    #[serde(default, skip_serializing_if = "LocalpartImportPreference::is_default")]
    pub localpart: LocalpartImportPreference,

    /// Import the displayname of the user
    #[serde(
        default,
        skip_serializing_if = "DisplaynameImportPreference::is_default"
    )]
    pub displayname: DisplaynameImportPreference,

    /// Import the email address of the user
    #[serde(default, skip_serializing_if = "EmailImportPreference::is_default")]
    pub email: EmailImportPreference,

    /// Import the avatar URL of the user
    #[serde(default, skip_serializing_if = "AvatarImportPreference::is_default")]
    pub avatar: AvatarImportPreference,

    /// Set a human-readable name for the upstream account for display purposes
    #[serde(
        default,
        skip_serializing_if = "AccountNameImportPreference::is_default"
    )]
    pub account_name: AccountNameImportPreference,
}

impl ClaimsImports {
    pub(crate) const fn is_default(&self) -> bool {
        self.subject.is_default()
            && self.localpart.is_default()
            && !self.skip_confirmation
            && self.displayname.is_default()
            && self.email.is_default()
            && self.avatar.is_default()
            && self.account_name.is_default()
    }
}
