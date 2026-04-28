//! Flow engine data model types.
//!
//! A "flow" is a multi-step user interaction such as registration, account
//! recovery, password change, MFA enrollment, or OAuth consent.  Each flow is
//! composed of an ordered sequence of "stages", where every stage defines what
//! to show the user (a **challenge**) and what to accept back (a **response**).
//!
//! At runtime a [`FlowSession`] tracks the user's progress through the stages,
//! accumulating context data that later stages can reference.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Ulid;

// ---------------------------------------------------------------------------
// Flow designation
// ---------------------------------------------------------------------------

/// The purpose/designation of a flow — determines when it is triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDesignation {
    /// User registration flow.
    Registration,
    /// Account recovery / password reset flow.
    Recovery,
    /// Password change flow (authenticated).
    PasswordChange,
    /// Authentication / login flow.
    Authentication,
    /// OAuth2 authorization consent flow.
    Authorization,
    /// MFA device enrollment flow.
    Enrollment,
    /// User profile / settings flow.
    StageConfiguration,
}

// ---------------------------------------------------------------------------
// Flow definition
// ---------------------------------------------------------------------------

/// A flow definition — a named sequence of stages for a specific purpose.
///
/// Flow definitions are configuration-time objects.  They describe *what*
/// should happen (which stages, in which order) but do not carry any runtime
/// state — that lives in [`FlowSession`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDefinition {
    /// Unique identifier.
    pub id: Ulid,
    /// URL-friendly identifier, e.g., `"default-registration"`.
    pub slug: String,
    /// Human-readable title shown in admin UIs.
    pub title: String,
    /// What this flow is used for.
    pub designation: FlowDesignation,
    /// Whether the flow is currently active.
    pub enabled: bool,
    /// Optional template override key. When set, the template engine
    /// looks for templates under this key instead of the default.
    pub template_override: Option<String>,
    /// Timestamp when this definition was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when this definition was last modified.
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Stages
// ---------------------------------------------------------------------------

/// A stage type — defines what kind of interaction this step performs.
///
/// Each variant carries the configuration data specific to that stage kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StageKind {
    /// Identify the user (username/email input).
    Identification {
        /// Which fields are accepted for identification.
        user_fields: Vec<IdentificationField>,
        /// Whether to show a password field inline.
        password_stage: bool,
    },
    /// Verify an email address via a one-time code.
    EmailVerification {
        /// Purpose context for the email.
        purpose: String,
        /// Template key for the verification email.
        template_key: String,
        /// Code expiry in seconds.
        code_expiry_seconds: u32,
        /// Maximum verification attempts before the code is invalidated.
        max_attempts: u32,
    },
    /// Collect and validate a password.
    PasswordWrite {
        /// Whether to require the current password (e.g. for password change).
        require_current: bool,
    },
    /// Create or update a user record.
    UserWrite {
        /// Whether newly created users should start as inactive.
        create_users_as_inactive: bool,
    },
    /// Display a CAPTCHA challenge.
    Captcha,
    /// Display an OAuth2 consent screen.
    Consent,
    /// Collect arbitrary prompted fields.
    Prompt {
        /// The fields to present to the user.
        fields: Vec<PromptField>,
    },
    /// Validate a second factor (TOTP, WebAuthn, etc.)
    AuthenticatorValidate {
        /// Which authenticator types are accepted.
        allowed_types: Vec<AuthenticatorType>,
    },
    /// Validate an enrollment/invitation token.
    EnrollmentToken {
        /// Whether the token is required or optional.
        required: bool,
    },
}

/// Fields accepted by the identification stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationField {
    /// Identify by username.
    Username,
    /// Identify by email address.
    Email,
    /// Identify by phone number.
    Phone,
}

/// Types of second-factor authenticators accepted by the
/// [`StageKind::AuthenticatorValidate`] stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatorType {
    /// Time-based one-time password (RFC 6238).
    Totp,
    /// WebAuthn / FIDO2 security key or passkey.
    WebAuthn,
}

/// A prompted field definition used by the [`StageKind::Prompt`] variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptField {
    /// Machine-readable key for the field value.
    pub field_key: String,
    /// Human-readable label.
    pub label: String,
    /// The input type to render.
    pub field_type: PromptFieldType,
    /// Whether the user must fill this field.
    pub required: bool,
    /// Placeholder text, if any.
    pub placeholder: Option<String>,
    /// Display order (lower = earlier).
    pub order: i32,
}

/// Types of prompted fields rendered in a [`StageKind::Prompt`] stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptFieldType {
    /// Single-line text input.
    Text,
    /// Email address input.
    Email,
    /// Password (masked) input.
    Password,
    /// Boolean checkbox.
    Checkbox,
    /// Hidden field (not rendered).
    Hidden,
    /// Dropdown / select list.
    Select,
}

// ---------------------------------------------------------------------------
// Flow-stage binding
// ---------------------------------------------------------------------------

/// Binds a stage to a flow with ordering and an optional policy expression.
///
/// The planner iterates these bindings in [`order`](Self::order) to build the
/// list of stages the user must complete.  If
/// [`evaluate_on_plan`](Self::evaluate_on_plan) is `true`, the
/// [`policy_expression`](Self::policy_expression) is evaluated at plan time to
/// decide whether the stage should be included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStageBinding {
    /// Unique identifier.
    pub id: Ulid,
    /// The flow this binding belongs to.
    pub flow_id: Ulid,
    /// The stage configuration.
    pub stage: StageKind,
    /// Execution order within the flow (lower = earlier).
    pub order: i32,
    /// Whether to evaluate [`policy_expression`](Self::policy_expression) at
    /// plan time.
    pub evaluate_on_plan: bool,
    /// Optional policy expression (stored as JSON).  When present and
    /// [`evaluate_on_plan`](Self::evaluate_on_plan) is `true`, the planner
    /// evaluates this to decide whether the stage should run.
    pub policy_expression: Option<Value>,
    /// Timestamp when this binding was created.
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Flow session (runtime state)
// ---------------------------------------------------------------------------

/// Runtime session tracking a user's progress through a flow.
///
/// Created when a user begins a flow and updated as they advance through
/// stages.  The [`context`](Self::context) field accumulates data that later
/// stages can read (e.g., the identified user, a pending email address).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSession {
    /// Unique identifier.
    pub id: Ulid,
    /// The flow definition this session is executing.
    pub flow_id: Ulid,
    /// The current stage binding index (0-based).
    pub current_stage_index: usize,
    /// Session lifecycle status.
    pub status: FlowSessionStatus,
    /// Accumulated context data shared between stages.
    pub context: Value,
    /// IP address of the user who initiated the session.
    pub ip_address: Option<std::net::IpAddr>,
    /// User agent string of the user's browser/client.
    pub user_agent: Option<String>,
    /// Timestamp when this session was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when this session was last updated.
    pub updated_at: DateTime<Utc>,
    /// Timestamp when this session expires.
    pub expires_at: DateTime<Utc>,
    /// Timestamp when the session reached a terminal status, if any.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Flow session lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowSessionStatus {
    /// Flow is in progress.
    InProgress,
    /// Flow completed successfully.
    Completed,
    /// Flow was cancelled or abandoned.
    Cancelled,
    /// Flow expired before completion.
    Expired,
}

impl FlowSessionStatus {
    /// Returns `true` if the status represents a terminal (final) state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Expired)
    }
}

// ---------------------------------------------------------------------------
// Challenges & responses
// ---------------------------------------------------------------------------

/// The challenge presented to the user for a stage.
///
/// Each variant mirrors a [`StageKind`] but carries runtime data needed to
/// render the UI (e.g., the email address to verify, the CAPTCHA site key).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StageChallenge {
    /// Identification challenge — prompt for username/email/phone.
    Identification {
        /// Which identification fields to show.
        user_fields: Vec<IdentificationField>,
        /// Whether to also show an inline password field.
        password_stage: bool,
    },
    /// Email verification challenge — a code has been sent.
    EmailVerification {
        /// The (partially masked) email address the code was sent to.
        email: String,
        /// Human-readable purpose description.
        purpose: String,
    },
    /// Password write challenge — prompt for a new password.
    PasswordWrite {
        /// Whether the current password must also be provided.
        require_current: bool,
    },
    /// User write challenge — prompt for username / display name.
    UserWrite {
        /// A suggested username, if available.
        suggested_username: Option<String>,
    },
    /// CAPTCHA challenge.
    Captcha {
        /// The CAPTCHA provider's public site key.
        site_key: String,
    },
    /// OAuth2 consent challenge.
    Consent {
        /// The requested scope string.
        scope: String,
        /// Human-readable name of the requesting client.
        client_name: Option<String>,
    },
    /// Arbitrary prompted fields challenge.
    Prompt {
        /// The fields to display.
        fields: Vec<PromptField>,
    },
    /// Second-factor authenticator validation challenge.
    AuthenticatorValidate {
        /// Which authenticator types the user may choose from.
        allowed_types: Vec<AuthenticatorType>,
    },
    /// Enrollment token challenge — prompt for an invitation token.
    EnrollmentToken {
        /// Whether the token is required or optional.
        required: bool,
    },
    /// Terminal challenge — the flow is done, redirect the user.
    FlowDone {
        /// URL to redirect to, if any.
        redirect_to: Option<String>,
    },
}

/// A user's response to a stage challenge.
///
/// The engine validates the response against the corresponding
/// [`StageChallenge`] and produces a [`StageOutcome`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StageResponse {
    /// Response to an identification challenge.
    Identification {
        /// The value entered in the identifier field.
        uid_field: String,
        /// Password, if the identification stage included an inline password
        /// field.
        password: Option<String>,
    },
    /// Response to an email verification challenge.
    EmailVerification {
        /// The one-time verification code.
        code: String,
    },
    /// Response to a password write challenge.
    PasswordWrite {
        /// The current password (when required).
        current_password: Option<String>,
        /// The new password.
        new_password: String,
    },
    /// Response to a user write challenge.
    UserWrite {
        /// Chosen username.
        username: String,
        /// Optional display name.
        display_name: Option<String>,
    },
    /// Response to a CAPTCHA challenge.
    Captcha {
        /// The CAPTCHA solution token.
        token: String,
    },
    /// Response to a consent challenge.
    Consent {
        /// Whether the user granted consent.
        granted: bool,
    },
    /// Response to a prompt challenge.
    Prompt {
        /// Collected field values as a JSON object.
        data: Value,
    },
    /// Response to an authenticator validation challenge.
    AuthenticatorValidate {
        /// The type of authenticator the user chose.
        authenticator_type: AuthenticatorType,
        /// The one-time code (for TOTP) or assertion payload (for WebAuthn).
        code: String,
    },
    /// Response to an enrollment token challenge.
    EnrollmentToken {
        /// The invitation/enrollment token string.
        token: String,
    },
}

// ---------------------------------------------------------------------------
// Stage outcome
// ---------------------------------------------------------------------------

/// Result of processing a stage response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StageOutcome {
    /// Stage completed successfully — advance to the next stage.
    Continue,
    /// Stage needs to be re-displayed with validation errors.
    Retry {
        /// The validation errors to display.
        errors: Vec<StageValidationError>,
    },
    /// The flow is done.
    Done {
        /// URL to redirect to after completion, if any.
        redirect_to: Option<String>,
    },
}

/// A validation error from processing a stage response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageValidationError {
    /// The field that caused the error, or `None` for form-level errors.
    pub field: Option<String>,
    /// Human-readable error message.
    pub message: String,
    /// Machine-readable error code.
    pub code: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_session_status_is_terminal() {
        assert!(
            !FlowSessionStatus::InProgress.is_terminal(),
            "InProgress should not be terminal"
        );
        assert!(
            FlowSessionStatus::Completed.is_terminal(),
            "Completed should be terminal"
        );
        assert!(
            FlowSessionStatus::Cancelled.is_terminal(),
            "Cancelled should be terminal"
        );
        assert!(
            FlowSessionStatus::Expired.is_terminal(),
            "Expired should be terminal"
        );
    }

    #[test]
    fn flow_designation_roundtrips_through_json() {
        let designation = FlowDesignation::Registration;
        let json = serde_json::to_string(&designation).unwrap();
        assert_eq!(json, "\"registration\"");
        let back: FlowDesignation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, designation);
    }

    #[test]
    fn flow_session_status_roundtrips_through_json() {
        let status = FlowSessionStatus::InProgress;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"in_progress\"");
        let back: FlowSessionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn stage_kind_serializes_with_tag() {
        let stage = StageKind::Identification {
            user_fields: vec![IdentificationField::Email, IdentificationField::Username],
            password_stage: true,
        };
        let json = serde_json::to_value(&stage).unwrap();
        assert_eq!(json["type"], "identification");
        assert!(json["password_stage"].as_bool().unwrap());
    }

    #[test]
    fn stage_outcome_retry_contains_errors() {
        let outcome = StageOutcome::Retry {
            errors: vec![StageValidationError {
                field: Some("email".to_owned()),
                message: "Invalid email address".to_owned(),
                code: "invalid_email".to_owned(),
            }],
        };
        if let StageOutcome::Retry { errors } = outcome {
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].code, "invalid_email");
        } else {
            panic!("expected Retry variant");
        }
    }
}
