//! Remote HTTP policy provider.
//!
//! This module implements policy evaluation by delegating to an external HTTP
//! service. This is the most flexible approach: the remote service can be
//! implemented in any language (Python, Go, Node.js, etc.) and can use any
//! decision logic, including AI models.
//!
//! ## Protocol
//!
//! The remote service must expose the following HTTP endpoints:
//!
//! - `POST {base_url}/evaluate/email` - Email policy evaluation
//! - `POST {base_url}/evaluate/register` - Registration policy evaluation
//! - `POST {base_url}/evaluate/client_registration` - Client registration
//!   evaluation
//! - `POST {base_url}/evaluate/authorization_grant` - Authorization grant
//!   evaluation
//! - `POST {base_url}/data` - Dynamic data update (optional)
//!
//! ### Request Format
//!
//! Each evaluation endpoint receives a JSON body containing the evaluation
//! input (same structure as the Rust input types, serialized via serde).
//!
//! ### Response Format
//!
//! Each evaluation endpoint must return a JSON response:
//!
//! ```json
//! {
//!     "violations": [
//!         {
//!             "msg": "Username too short",
//!             "field": "username",
//!             "code": "username-too-short",
//!             "redirect_uri": null
//!         }
//!     ]
//! }
//! ```
//!
//! An empty `violations` array means the request is allowed.

use async_trait::async_trait;
use coauth_data::PolicyData;
use serde::Deserialize;

use crate::{
    EvaluationError, InstantiateError, LoadError,
    model::{
        AuthorizationGrantInput, ClientRegistrationInput, EmailInput, EvaluationResult,
        RegisterInput, Violation,
    },
    provider::{PolicyEvaluator, PolicyProviderFactory},
};

/// Remote HTTP policy provider factory.
///
/// Delegates all policy evaluation to an external HTTP service.
pub struct RemoteProviderFactory {
    client: reqwest::Client,
    base_url: String,
}

impl RemoteProviderFactory {
    /// Create a new remote provider factory.
    ///
    /// - `base_url`: The base URL of the remote policy service (e.g., `http://localhost:8181`)
    /// - `client`: A shared `reqwest::Client` for making HTTP requests
    #[must_use]
    pub fn new(base_url: String, client: reqwest::Client) -> Self {
        Self { client, base_url }
    }
}

#[async_trait]
impl PolicyProviderFactory for RemoteProviderFactory {
    async fn instantiate(&self) -> Result<Box<dyn PolicyEvaluator>, InstantiateError> {
        Ok(Box::new(RemoteEvaluator {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
        }))
    }

    async fn set_dynamic_data(&self, data: PolicyData) -> Result<bool, LoadError> {
        let response = self
            .client
            .post(format!("{}/data", self.base_url))
            .json(&data.data)
            .send()
            .await
            .map_err(|e| {
                LoadError::InvalidData(anyhow::anyhow!("Remote data update failed: {e}"))
            })?;

        if response.status().is_success() {
            Ok(true)
        } else {
            Err(LoadError::InvalidData(anyhow::anyhow!(
                "Remote data update failed with status: {}",
                response.status()
            )))
        }
    }
}

/// The response format expected from the remote policy service.
#[derive(Deserialize)]
struct RemoteResponse {
    violations: Vec<Violation>,
}

/// Remote HTTP policy evaluator instance.
///
/// Sends evaluation requests to the configured remote HTTP service and
/// parses the response into an [`EvaluationResult`].
pub struct RemoteEvaluator {
    client: reqwest::Client,
    base_url: String,
}

impl RemoteEvaluator {
    /// Send an evaluation request to the remote service.
    async fn evaluate_remote(
        &self,
        path: &str,
        input: &(impl serde::Serialize + Sync),
    ) -> Result<EvaluationResult, EvaluationError> {
        let url = format!("{}/evaluate/{}", self.base_url, path);

        let response = self
            .client
            .post(&url)
            .json(input)
            .send()
            .await
            .map_err(|e| {
                EvaluationError::Evaluation(anyhow::anyhow!(
                    "Remote policy request to {url} failed: {e}"
                ))
            })?;

        if !response.status().is_success() {
            return Err(EvaluationError::Evaluation(anyhow::anyhow!(
                "Remote policy service returned status {} for {url}",
                response.status()
            )));
        }

        let remote_response: RemoteResponse = response.json().await.map_err(|e| {
            EvaluationError::Evaluation(anyhow::anyhow!(
                "Failed to parse remote policy response: {e}"
            ))
        })?;

        Ok(EvaluationResult {
            violations: remote_response.violations,
        })
    }
}

#[async_trait]
impl PolicyEvaluator for RemoteEvaluator {
    async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("email", &input).await
    }

    async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("register", &input).await
    }

    async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("client_registration", &input).await
    }

    async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        self.evaluate_remote("authorization_grant", &input).await
    }
}
