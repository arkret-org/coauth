//! # Migration path
//!
//! The registration workflow currently uses `UserRegistrationRepository` for
//! state tracking. It will be progressively migrated to use
//! `WorkflowRepository` for unified workflow state management. The strand engine
//! (`crate::handlers::strand`) can already orchestrate registration as a
//! `default-registration` strand.

mod admin_bootstrap;
mod finish;
mod operations;
mod progress;
mod types;
mod workflow;

#[cfg(test)]
mod tests;

use admin_bootstrap::{PrepareAdminBootstrapError, prepare_admin_bootstrap};
pub(crate) use finish::{check_registration_finish_eligibility, finish_registration};
pub(crate) use operations::{
    begin_password_registration, change_registration_email, resend_registration_verification,
    submit_registration_display_name, submit_registration_email_code,
    submit_registration_phone_code,
};
pub(crate) use progress::{load_registration_progress, load_registration_status};
pub use types::{
    AttachRegistrationTokenError, BeginPasswordRegistrationError, BeginPasswordRegistrationIssue,
    BeginPasswordRegistrationRequestBody, BeginPasswordRegistrationResult,
    CheckRegistrationFinishEligibilityError, CompleteRegistrationRequestBody,
    CompletedRegistration, EmailAvailabilityCheck, LoadRegistrationDisplayNameStepError,
    LoadRegistrationEmailStepError, LoadRegistrationFinishPreparationError,
    LoadRegistrationProgressError, LoadRegistrationTokenStepError,
    PrepareRegistrationCompletionError, PreparedRegistrationCompletion, PrincipalServerCheckMode,
    RegistrationDisplayNameOutcome, RegistrationDisplayNameStepContext,
    RegistrationDisplayNameWorkflowError, RegistrationEmailChangeError,
    RegistrationEmailChangeOutcome, RegistrationEmailStepContext, RegistrationFinishError,
    RegistrationFinishOutcome, RegistrationProgress, RegistrationResendError,
    RegistrationResendOutcome, RegistrationStatusSummary, RegistrationTokenStepContext,
    RegistrationVerificationError, RegistrationVerificationOutcome, RegistrationWorkflowDeadline,
    RegistrationWorkflowDeadlineKind, RegistrationWorkflowEvent, RegistrationWorkflowEventKind,
    RegistrationWorkflowSnapshot, RegistrationWorkflowState, ResendRegistrationVerificationError,
    ResendRegistrationVerificationStatus, SetRegistrationDisplayNameError,
    StartPasswordRegistrationError, StartPasswordRegistrationRequestBody,
    StartedPasswordRegistration, VerifyRegistrationEmailCodeError,
    VerifyRegistrationPhoneCodeError,
};
pub(crate) use workflow::next_registration_step;
