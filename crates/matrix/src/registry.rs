//! Connector provider registry.
//!
//! Manages multiple connector providers and provides lookup by name.

use std::{collections::HashMap, sync::Arc};

use crate::{ConnectorCapabilities, ConnectorProvider};

/// A registry of connector providers.
///
/// The registry holds named providers and provides lookup, health check,
/// and capability discovery operations. The first provider registered
/// becomes the primary (default) provider.
#[derive(Clone)]
pub struct ConnectorRegistry {
    providers: HashMap<String, Arc<dyn ConnectorProvider>>,
    /// The primary/default provider name.
    primary: Option<String>,
}

impl ConnectorRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            primary: None,
        }
    }

    /// Register a provider. The first provider registered becomes the primary.
    pub fn register(&mut self, provider: Arc<dyn ConnectorProvider>) {
        let name = provider.provider_name().to_owned();
        if self.primary.is_none() {
            self.primary = Some(name.clone());
        }
        self.providers.insert(name, provider);
    }

    /// Get the primary (default) provider.
    #[must_use]
    pub fn primary(&self) -> Option<&Arc<dyn ConnectorProvider>> {
        self.primary
            .as_ref()
            .and_then(|name| self.providers.get(name))
    }

    /// Get a provider by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<dyn ConnectorProvider>> {
        self.providers.get(name)
    }

    /// List all registered provider names.
    #[must_use]
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.keys().map(String::as_str).collect()
    }

    /// Get capabilities for all providers.
    #[must_use]
    pub fn all_capabilities(&self) -> Vec<(&str, ConnectorCapabilities)> {
        self.providers
            .iter()
            .map(|(name, provider)| (name.as_str(), provider.capabilities()))
            .collect()
    }

    /// Check health of all providers by calling
    /// `is_localpart_available("__health_check__")` on each.
    pub async fn check_all_health(&self) -> Vec<(&str, Result<(), String>)> {
        let mut results = Vec::with_capacity(self.providers.len());
        for (name, provider) in &self.providers {
            let result = provider
                .is_localpart_available("__health_check__")
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            results.push((name.as_str(), result));
        }
        results
    }
}

impl Default for ConnectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
