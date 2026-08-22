//! Policy evaluation abstraction layer.
//!
//! This crate provides a unified interface for policy evaluation. The shipped
//! backend is:
//!
//! - **Cedar** (feature `cedar`): Amazon Cedar policies evaluated natively in Rust, offering a
//!   simpler policy language with high performance.
//!
//! ## Architecture
//!
//! The abstraction is based on two core traits defined in [`provider`]:
//!
//! - [`PolicyProviderFactory`](provider::PolicyProviderFactory): Creates evaluator instances and
//!   manages dynamic data.
//! - [`PolicyEvaluator`](provider::PolicyEvaluator): Evaluates individual policy checks
//!   (registration, email, authorization, etc.).
//!
//! [`PolicyFactory`] and [`PolicyInstance`] are the public-facing types that wrap
//! these traits and form the public API used by handler code.

pub mod model;
pub mod provider;

#[cfg(feature = "cedar")]
pub mod cedar;

use thiserror::Error;

pub use self::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, EvaluationResult, GrantType,
    RegisterInput, RegistrationMethod, Requester, Violation, ViolationCode,
};
pub use self::provider::{PolicyEvaluator, PolicyProviderFactory};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read module")]
    Read(#[from] tokio::io::Error),

    #[error("failed to compile policy module")]
    Compilation(#[source] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum InstantiateError {
    #[error("failed to create policy runtime")]
    Runtime(#[source] anyhow::Error),

    #[error("missing entrypoint {entrypoint}")]
    MissingEntrypoint { entrypoint: String },

    #[error("failed to load policy data")]
    LoadData(#[source] anyhow::Error),
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] anyhow::Error),
}

// ---------------------------------------------------------------------------
// PolicyFactory - the main public-facing factory
// ---------------------------------------------------------------------------

/// Factory for creating [`PolicyInstance`] instances.
///
/// Wraps a [`PolicyProviderFactory`] implementation, allowing different
/// backends to be used transparently. The backend is selected at construction
/// time via one of the `load_*` methods.
pub struct PolicyFactory {
    inner: Box<dyn PolicyProviderFactory>,
}

impl PolicyFactory {
    /// Load Cedar policies from a file.
    ///
    /// Requires the `cedar` feature to be enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if Cedar is not compiled in, the file can't be read,
    /// or policies can't be parsed.
    #[cfg(feature = "cedar")]
    pub async fn load_cedar_from_file(path: &str) -> Result<Self, LoadError> {
        let factory = cedar::CedarProviderFactory::from_file(path).await?;
        Ok(Self {
            inner: Box::new(factory),
        })
    }

    /// Set the dynamic data for the policy.
    ///
    /// Returns `true` if the data was updated, `false` if the version
    /// was already up-to-date.
    ///
    /// # Errors
    ///
    /// Returns an error if the data can't be applied or the policy can't be
    /// instantiated with the new data.
    pub async fn set_dynamic_data(
        &self,
        dynamic_data: coauth_data::PolicyData,
    ) -> Result<bool, LoadError> {
        self.inner.set_dynamic_data(dynamic_data).await
    }

    /// Whether the underlying backend consumes dynamic policy data.
    ///
    /// Returns `false` for static backends (e.g. Cedar), allowing callers to
    /// skip periodic polling of the database.
    #[must_use]
    pub fn supports_dynamic_data(&self) -> bool {
        self.inner.supports_dynamic_data()
    }

    /// Create a new policy instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy can't be instantiated.
    #[tracing::instrument(name = "policy.instantiate", skip_all)]
    pub async fn instantiate(&self) -> Result<PolicyInstance, InstantiateError> {
        let evaluator = self.inner.instantiate().await?;
        Ok(PolicyInstance { inner: evaluator })
    }
}

// ---------------------------------------------------------------------------
// PolicyInstance - the main public-facing evaluator
// ---------------------------------------------------------------------------

/// An instantiated policy evaluator.
///
/// Created by [`PolicyFactory::instantiate`]. Wraps a [`PolicyEvaluator`]
/// trait object, delegating evaluation calls to the selected backend.
pub struct PolicyInstance {
    inner: Box<dyn PolicyEvaluator>,
}

impl PolicyInstance {
    /// Evaluate the 'email' policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(
        name = "policy.evaluate_email",
        skip_all,
        fields(
            %input.email,
        ),
    )]
    pub async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_email(input).await
    }

    /// Evaluate the 'register' policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(
        name = "policy.evaluate.register",
        skip_all,
        fields(
            ?input.registration_method,
            input.handle = input.handle,
            input.email = input.email,
        ),
    )]
    pub async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_register(input).await
    }

    /// Evaluate the `client_registration` policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(skip(self))]
    pub async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_client_registration(input).await
    }

    /// Evaluate the `authorization_grant` policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy engine fails to evaluate.
    #[tracing::instrument(
        name = "policy.evaluate.authorization_grant",
        skip_all,
        fields(
            %input.scope,
            %input.client.id,
        ),
    )]
    pub async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.inner.evaluate_authorization_grant(input).await
    }
}
