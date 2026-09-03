//! Policy provider traits for supporting multiple policy engines.
//!
//! This module defines the core abstractions that allow a policy backend
//! (Cedar, or a caller-supplied provider) to be plugged in via a common
//! interface.

use async_trait::async_trait;
use coauth_data::PolicyData;

use crate::policy::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, EvaluationResult, RegisterInput,
};
use crate::policy::{EvaluationError, InstantiateError, LoadError};

/// A policy evaluator instance capable of evaluating different policy types.
///
/// Each policy backend provides its own implementation of this trait.
/// Evaluator instances are typically short-lived (one per request) and created
/// by a [`PolicyProviderFactory`].
#[async_trait]
pub trait PolicyEvaluator: Send {
    /// Evaluate the email policy.
    async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError>;

    /// Evaluate the user registration policy.
    async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError>;

    /// Evaluate the client registration policy.
    async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError>;

    /// Evaluate the authorization grant policy.
    async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError>;
}

/// A factory for creating policy evaluator instances and managing policy data.
///
/// Implementations manage the lifecycle of their respective policy engines,
/// including loading policies, managing dynamic data updates, and creating
/// evaluator instances.
#[async_trait]
pub trait PolicyProviderFactory: Send + Sync {
    /// Create a new policy evaluator instance.
    async fn instantiate(&self) -> Result<Box<dyn PolicyEvaluator>, InstantiateError>;

    /// Update the dynamic policy data.
    ///
    /// Returns `true` if the data was updated, `false` if the version was
    /// already up-to-date.
    async fn set_dynamic_data(&self, data: PolicyData) -> Result<bool, LoadError>;

    /// Whether this provider consumes dynamic policy data.
    ///
    /// Static providers (e.g. Cedar) ignore dynamic data updates, so callers
    /// can skip periodic polling of the database for them. Defaults to `false`.
    fn supports_dynamic_data(&self) -> bool {
        false
    }
}
