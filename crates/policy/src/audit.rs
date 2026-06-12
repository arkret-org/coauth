//! Audit logging decorator for policy evaluation.
//!
//! Wraps any [`PolicyEvaluator`] implementation to log evaluation results
//! and timing information via the `tracing` crate.

use std::time::Instant;

use async_trait::async_trait;
use tracing::{info, warn};

use crate::EvaluationError;
use crate::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, EvaluationResult, RegisterInput,
};
use crate::provider::PolicyEvaluator;

/// A policy evaluator decorator that logs audit information for every
/// evaluation.
///
/// Wraps an inner [`PolicyEvaluator`] and records:
/// - The action type being evaluated
/// - The outcome (number of violations, or error)
/// - The wall-clock duration of the evaluation
pub struct AuditingEvaluator<E> {
    inner: E,
}

impl<E> AuditingEvaluator<E> {
    /// Create a new auditing evaluator wrapping the given inner evaluator.
    pub fn new(inner: E) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<E: PolicyEvaluator + Send> PolicyEvaluator for AuditingEvaluator<E> {
    async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let start = Instant::now();
        let result = self.inner.evaluate_email(input).await;
        let duration = start.elapsed();

        match &result {
            Ok(eval) => {
                let violation_count = eval.violations.len();
                if violation_count > 0 {
                    warn!(
                        action = "email",
                        violations = violation_count,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed with violations"
                    );
                } else {
                    info!(
                        action = "email",
                        violations = 0,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed"
                    );
                }
            }
            Err(e) => {
                warn!(
                    action = "email",
                    error = %e,
                    duration_ms = duration.as_millis() as u64,
                    "policy evaluation failed"
                );
            }
        }

        result
    }

    async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let start = Instant::now();
        let result = self.inner.evaluate_register(input).await;
        let duration = start.elapsed();

        match &result {
            Ok(eval) => {
                let violation_count = eval.violations.len();
                if violation_count > 0 {
                    warn!(
                        action = "register",
                        violations = violation_count,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed with violations"
                    );
                } else {
                    info!(
                        action = "register",
                        violations = 0,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed"
                    );
                }
            }
            Err(e) => {
                warn!(
                    action = "register",
                    error = %e,
                    duration_ms = duration.as_millis() as u64,
                    "policy evaluation failed"
                );
            }
        }

        result
    }

    async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let start = Instant::now();
        let result = self.inner.evaluate_client_registration(input).await;
        let duration = start.elapsed();

        match &result {
            Ok(eval) => {
                let violation_count = eval.violations.len();
                if violation_count > 0 {
                    warn!(
                        action = "client_registration",
                        violations = violation_count,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed with violations"
                    );
                } else {
                    info!(
                        action = "client_registration",
                        violations = 0,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed"
                    );
                }
            }
            Err(e) => {
                warn!(
                    action = "client_registration",
                    error = %e,
                    duration_ms = duration.as_millis() as u64,
                    "policy evaluation failed"
                );
            }
        }

        result
    }

    async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let start = Instant::now();
        let result = self.inner.evaluate_authorization_grant(input).await;
        let duration = start.elapsed();

        match &result {
            Ok(eval) => {
                let violation_count = eval.violations.len();
                if violation_count > 0 {
                    warn!(
                        action = "authorization_grant",
                        violations = violation_count,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed with violations"
                    );
                } else {
                    info!(
                        action = "authorization_grant",
                        violations = 0,
                        duration_ms = duration.as_millis() as u64,
                        "policy evaluation completed"
                    );
                }
            }
            Err(e) => {
                warn!(
                    action = "authorization_grant",
                    error = %e,
                    duration_ms = duration.as_millis() as u64,
                    "policy evaluation failed"
                );
            }
        }

        result
    }
}
