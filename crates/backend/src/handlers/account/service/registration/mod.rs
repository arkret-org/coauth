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
pub use finish::{
    check_registration_finish_eligibility, complete_registration, finish_registration,
    load_registration_finish_preparation, prepare_registration_completion,
};
pub use operations::{
    begin_password_registration, change_registration_email,
    resend_pending_registration_verification, resend_registration_verification,
    set_registration_display_name, start_password_registration, submit_registration_display_name,
    submit_registration_email_code, submit_registration_phone_code, verify_registration_email_code,
    verify_registration_phone_code,
};
pub use progress::{
    attach_registration_token, load_registration_display_name_step, load_registration_email_step,
    load_registration_progress, load_registration_status, load_registration_token_step,
};
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
pub use workflow::{completed_registration_steps, next_registration_step};
