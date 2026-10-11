//! Journey execution engine.
//!
//! Provides a framework for executing multi-step user interaction journeys
//! (registration, recovery, authentication, etc.) as composable stage
//! sequences, inspired by authentik's journey architecture.

pub mod defaults;
mod executor;
mod sessions;

pub(crate) use sessions::{JourneyState, SESSIONS};

pub use self::defaults::{
    default_authentication_journey, default_authorization_journey, default_enrollment_journey,
    default_password_change_journey, default_recovery_journey, default_registration_journey,
};
pub use self::executor::{CaptchaVerifyContext, JourneyExecutor, JourneyPlan, JourneyPlannerError};
