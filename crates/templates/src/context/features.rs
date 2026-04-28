use std::sync::Arc;

use minijinja::{
    Value,
    value::{Enumerator, Object},
};

type FeatureReader = fn(&SiteFeatures) -> bool;

struct FeatureField {
    name: &'static str,
    read: FeatureReader,
}

const FEATURE_FIELD_NAMES: [&str; 5] = [
    "password_registration",
    "password_registration_contact_required",
    "password_login",
    "account_recovery",
    "login_with_email_allowed",
];

const FEATURE_FIELDS: [FeatureField; 5] = [
    FeatureField {
        name: FEATURE_FIELD_NAMES[0],
        read: |features| features.password_registration,
    },
    FeatureField {
        name: FEATURE_FIELD_NAMES[1],
        read: |features| features.password_registration_contact_required,
    },
    FeatureField {
        name: FEATURE_FIELD_NAMES[2],
        read: |features| features.password_login,
    },
    FeatureField {
        name: FEATURE_FIELD_NAMES[3],
        read: |features| features.account_recovery,
    },
    FeatureField {
        name: FEATURE_FIELD_NAMES[4],
        read: |features| features.login_with_email_allowed,
    },
];

/// Site features information.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteFeatures {
    /// Whether local password-based registration is enabled.
    pub password_registration: bool,

    /// Whether local password-based registration requires at least one contact
    /// method (email or phone).
    pub password_registration_contact_required: bool,

    /// Whether local password-based login is enabled.
    pub password_login: bool,

    /// Whether email-based account recovery is enabled.
    pub account_recovery: bool,

    /// Whether users can log in with their email address.
    pub login_with_email_allowed: bool,
}

impl SiteFeatures {
    fn resolve(&self, name: &str) -> Option<bool> {
        FEATURE_FIELDS
            .iter()
            .find_map(|field| (field.name == name).then(|| (field.read)(self)))
    }
}

impl Object for SiteFeatures {
    fn get_value(self: &Arc<Self>, field: &Value) -> Option<Value> {
        self.resolve(field.as_str()?).map(Value::from)
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&FEATURE_FIELD_NAMES)
    }
}
