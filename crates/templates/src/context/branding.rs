use std::sync::Arc;

use minijinja::{
    Value,
    value::{Enumerator, Object},
};

const BRANDING_NAMES: [&str; 4] = ["server_name", "policy_uri", "tos_uri", "imprint"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrandingField {
    PolicyUri,
    TosUri,
    Imprint,
}

impl BrandingField {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "policy_uri" => Some(Self::PolicyUri),
            "tos_uri" => Some(Self::TosUri),
            "imprint" => Some(Self::Imprint),
            _ => None,
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::PolicyUri => 0,
            Self::TosUri => 1,
            Self::Imprint => 2,
        }
    }
}

/// Site branding information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBranding {
    server_name: Arc<str>,
    links: [Option<Arc<str>>; 3],
}

impl SiteBranding {
    /// Create a new site branding based on the given server name.
    #[must_use]
    pub fn new(server_name: impl Into<Arc<str>>) -> Self {
        Self {
            server_name: server_name.into(),
            links: [None, None, None],
        }
    }

    fn with_link(mut self, field: BrandingField, value: impl Into<Arc<str>>) -> Self {
        self.links[field.slot()] = Some(value.into());
        self
    }

    fn resolve(&self, name: &str) -> Option<Value> {
        if name == BRANDING_NAMES[0] {
            return Some(self.server_name.clone().into());
        }

        let field = BrandingField::from_name(name)?;
        Some(Value::from(self.links[field.slot()].clone()))
    }

    /// Set the policy URI.
    #[must_use]
    pub fn with_policy_uri(mut self, policy_uri: impl Into<Arc<str>>) -> Self {
        self = self.with_link(BrandingField::PolicyUri, policy_uri);
        self
    }

    /// Set the terms of service URI.
    #[must_use]
    pub fn with_tos_uri(mut self, tos_uri: impl Into<Arc<str>>) -> Self {
        self = self.with_link(BrandingField::TosUri, tos_uri);
        self
    }

    /// Set the imprint.
    #[must_use]
    pub fn with_imprint(mut self, imprint: impl Into<Arc<str>>) -> Self {
        self = self.with_link(BrandingField::Imprint, imprint);
        self
    }
}

impl Object for SiteBranding {
    fn get_value(self: &Arc<Self>, name: &Value) -> Option<Value> {
        self.resolve(name.as_str()?)
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&BRANDING_NAMES)
    }
}
