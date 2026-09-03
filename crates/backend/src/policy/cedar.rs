//! Cedar policy provider.
//!
//! This module implements policy evaluation using [Amazon Cedar](https://www.cedarpolicy.com/),
//! a language for defining permissions as policies. Cedar is natively written
//! in Rust, making it a high-performance choice for policy evaluation in this
//! project.
//!
//! ## Policy Structure
//!
//! Cedar evaluates authorization requests of the form
//! `(principal, action, resource, context)`. This adapter maps evaluations as:
//!
//! - **Principal**: `Requester::"anonymous"` (or user-specific if available)
//! - **Action**: `Action::"register"`, `Action::"add_email"`, `Action::"register_client"`,
//!   `Action::"authorize"`
//! - **Resource**: `Resource::"default"`
//! - **Context**: The serialized evaluation input data
//!
//! ## Example Cedar Policy
//!
//! ```cedar
//! // Block registration with short handles
//! forbid(
//!     principal,
//!     action == Action::"register",
//!     resource
//! ) when {
//!     context.handle.size() < 3
//! };
//!
//! // Block banned email domains
//! forbid(
//!     principal,
//!     action == Action::"add_email",
//!     resource
//! ) when {
//!     context.email like "*@banned-domain.com"
//! };
//! ```

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use chrono::{Datelike, Timelike};
use coauth_data::{Clock, PolicyData, SystemClock};

use crate::policy::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, EvaluationResult, RegisterInput,
    Violation,
};
use crate::policy::provider::{PolicyEvaluator, PolicyProviderFactory};
use crate::policy::{EvaluationError, InstantiateError, LoadError};

/// Cedar policy provider factory.
///
/// Manages a set of Cedar policies and creates [`CedarEvaluator`] instances
/// for per-request evaluation.
pub struct CedarProviderFactory {
    policy_set: Arc<PolicySet>,
    entities: Arc<Entities>,
}

impl CedarProviderFactory {
    /// Create a new Cedar provider factory from policy source text.
    ///
    /// The `policy_src` should contain one or more Cedar policy statements.
    ///
    /// # Errors
    ///
    /// Returns an error if the Cedar policies cannot be parsed.
    pub fn new(policy_src: &str) -> Result<Self, LoadError> {
        let policy_set: PolicySet = policy_src.parse().map_err(|e| {
            LoadError::Compilation(anyhow::anyhow!("Failed to parse Cedar policies: {e}"))
        })?;

        let entities = Entities::empty();

        Ok(Self {
            policy_set: Arc::new(policy_set),
            entities: Arc::new(entities),
        })
    }

    /// Create a new Cedar provider factory from a policy file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the policies cannot be
    /// parsed.
    pub async fn from_file(path: &str) -> Result<Self, LoadError> {
        let policy_src = tokio::fs::read_to_string(path)
            .await
            .map_err(LoadError::Read)?;
        Self::new(&policy_src)
    }
}

#[async_trait]
impl PolicyProviderFactory for CedarProviderFactory {
    async fn instantiate(&self) -> Result<Box<dyn PolicyEvaluator>, InstantiateError> {
        Ok(Box::new(CedarEvaluator {
            authorizer: Authorizer::new(),
            policy_set: Arc::clone(&self.policy_set),
            entities: Arc::clone(&self.entities),
        }))
    }

    async fn set_dynamic_data(&self, _data: PolicyData) -> Result<bool, LoadError> {
        // Cedar policies are currently static. Dynamic data updates could be
        // implemented by updating the entity store in the future.
        Ok(false)
    }
}

/// Cedar policy evaluator instance.
///
/// Evaluates authorization requests against a Cedar policy set.
pub struct CedarEvaluator {
    authorizer: Authorizer,
    policy_set: Arc<PolicySet>,
    entities: Arc<Entities>,
}

impl CedarEvaluator {
    /// Evaluate a Cedar authorization request for the given action.
    ///
    /// Serializes the input as the Cedar request context and maps the
    /// Cedar decision back to an [`EvaluationResult`].
    fn evaluate_action(
        &self,
        action_name: &str,
        input: &impl serde::Serialize,
    ) -> Result<EvaluationResult, EvaluationError> {
        let mut context_json =
            serde_json::to_value(input).map_err(EvaluationError::Serialization)?;

        // Inject time context fields for time-based policy evaluation.
        let now = SystemClock::default().now();
        let day_of_week = match now.weekday() {
            chrono::Weekday::Mon => "monday",
            chrono::Weekday::Tue => "tuesday",
            chrono::Weekday::Wed => "wednesday",
            chrono::Weekday::Thu => "thursday",
            chrono::Weekday::Fri => "friday",
            chrono::Weekday::Sat => "saturday",
            chrono::Weekday::Sun => "sunday",
        };
        if let serde_json::Value::Object(ref mut map) = context_json {
            map.insert(
                "current_hour".to_owned(),
                serde_json::Value::from(now.hour()),
            );
            map.insert(
                "current_day_of_week".to_owned(),
                serde_json::Value::from(day_of_week),
            );
            map.insert(
                "current_timestamp".to_owned(),
                serde_json::Value::from(now.timestamp()),
            );
        }

        // The principal and resource EntityUids are constant; parse them once
        // and clone the cached value (cloning an `EntityUid` is cheap).
        static PRINCIPAL: OnceLock<EntityUid> = OnceLock::new();
        static RESOURCE: OnceLock<EntityUid> = OnceLock::new();
        let principal = PRINCIPAL
            .get_or_init(|| {
                r#"Requester::"anonymous""#
                    .parse()
                    .expect("constant principal EntityUid must parse")
            })
            .clone();
        let resource = RESOURCE
            .get_or_init(|| {
                r#"Resource::"default""#
                    .parse()
                    .expect("constant resource EntityUid must parse")
            })
            .clone();

        // The action is genuinely dynamic, so parse it per-call.
        let action: EntityUid = format!(r#"Action::"{action_name}""#).parse().map_err(|e| {
            EvaluationError::Evaluation(anyhow::anyhow!("Failed to parse action: {e}"))
        })?;

        // Cedar does not support JSON null values; strip them before building
        // the context so that Optional fields serialised as null do not cause
        // a parse error.
        strip_json_nulls(&mut context_json);

        let context = Context::from_json_value(context_json, None).map_err(|e| {
            tracing::error!(
                action = action_name,
                error = %e,
                "Failed to build Cedar context"
            );
            EvaluationError::Evaluation(anyhow::anyhow!("Failed to build Cedar context: {e}"))
        })?;

        let request = Request::new(principal, action, resource, context, None).map_err(|e| {
            EvaluationError::Evaluation(anyhow::anyhow!("Failed to build Cedar request: {e}"))
        })?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &self.entities);

        let violations = match response.decision() {
            Decision::Allow => vec![],
            Decision::Deny => {
                let mut violations = Vec::new();

                // Map Cedar policy reasons to violations
                for reason in response.diagnostics().reason() {
                    violations.push(Violation {
                        msg: format!("Denied by Cedar policy: {reason}"),
                        redirect_uri: None,
                        field: None,
                        code: None,
                    });
                }

                // Map Cedar evaluation errors to violations
                for error in response.diagnostics().errors() {
                    violations.push(Violation {
                        msg: format!("Cedar policy error: {error}"),
                        redirect_uri: None,
                        field: None,
                        code: None,
                    });
                }

                // Ensure at least one violation is present for a Deny decision
                if violations.is_empty() {
                    violations.push(Violation {
                        msg: "Denied by Cedar policy".to_owned(),
                        redirect_uri: None,
                        field: None,
                        code: None,
                    });
                }

                violations
            }
        };

        Ok(EvaluationResult { violations })
    }
}

#[async_trait]
impl PolicyEvaluator for CedarEvaluator {
    async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_action("add_email", &input)
    }

    async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_action("register", &input)
    }

    async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_action("register_client", &input)
    }

    async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_action("authorize", &input)
    }
}

/// Recursively remove JSON `null` values from objects so they do not trip
/// Cedar's context parser, which rejects `null`.
fn strip_json_nulls(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                strip_json_nulls(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_json_nulls(v);
            }
        }
        _ => {}
    }
}
