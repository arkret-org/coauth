//! Declarative strand definition parser.
//!
//! Provides [`StrandDefinitionFile`], a YAML-friendly representation of a
//! [`StrandDefinition`] together with its [`StrandStageBinding`] list.  This
//! allows strands to be defined in configuration files rather than purely in
//! code.
//!
//! # Example YAML
//!
//! ```yaml
//! slug: default-registration
//! title: Default Registration
//! designation: registration
//! stages:
//!   - type: user_write
//!     order: 10
//!     create_users_as_inactive: false
//!   - type: email_verification
//!     order: 20
//!     purpose: registration
//!     template_key: verification
//!     code_expiry_seconds: 300
//!     max_attempts: 5
//! ```

use chrono::Utc;
use coauth_data::new_id;
use coauth_data::strand::{
    AuthenticatorType, IdentificationField, PromptField, StageKind, StrandDefinition,
    StrandDesignation, StrandStageBinding,
};
use serde::Deserialize;

/// A declarative strand definition file that can be parsed from YAML (or JSON).
///
/// After parsing, call [`into_strand`](Self::into_strand) to obtain the domain
/// types ([`StrandDefinition`] + [`Vec<StrandStageBinding>`]).
#[derive(Debug, Clone, Deserialize)]
pub struct StrandDefinitionFile {
    /// URL-friendly slug, e.g., `"default-registration"`.
    pub slug: String,
    /// Human-readable title shown in admin UIs.
    pub title: String,
    /// Strand designation — determines when the strand is triggered.
    pub designation: String,
    /// Optional template override key. When set, the template engine
    /// looks for templates under this key instead of the default.
    #[serde(default)]
    pub template_override: Option<String>,
    /// Ordered list of stage definitions.
    pub stages: Vec<StageDefinition>,
}

/// A single stage within a declarative strand definition.
///
/// Uses `#[serde(tag = "type")]` so the YAML/JSON `type` field selects the
/// variant, matching the `snake_case` naming of [`StageKind`].
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StageDefinition {
    /// Identify the user (username/email/phone input).
    Identification {
        order: i32,
        #[serde(default)]
        user_fields: Option<Vec<String>>,
        #[serde(default)]
        password_stage: Option<bool>,
    },
    /// Verify an email address via a one-time code.
    EmailVerification {
        order: i32,
        purpose: String,
        template_key: String,
        code_expiry_seconds: u32,
        max_attempts: u32,
    },
    /// Collect and validate a (new) password.
    PasswordWrite {
        order: i32,
        #[serde(default)]
        require_current: Option<bool>,
    },
    /// Create or update a user record.
    UserWrite {
        order: i32,
        #[serde(default)]
        create_users_as_inactive: Option<bool>,
    },
    /// Display a CAPTCHA challenge.
    Captcha { order: i32 },
    /// Display an OAuth consent screen.
    Consent { order: i32 },
    /// Collect arbitrary prompted fields.
    Prompt {
        order: i32,
        fields: Vec<PromptField>,
    },
    /// Validate a second factor (TOTP, `WebAuthn`, etc.).
    AuthenticatorValidate {
        order: i32,
        allowed_types: Vec<AuthenticatorType>,
    },
}

impl StrandDefinitionFile {
    /// Parse a YAML string into a [`StrandDefinitionFile`].
    ///
    /// # Errors
    ///
    /// Returns a [`serde_yaml::Error`] if the input is not valid YAML or does
    /// not match the expected schema.
    pub fn parse(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Convert this declarative definition into domain types.
    ///
    /// Fresh ULIDs are generated for the [`StrandDefinition`] and each
    /// [`StrandStageBinding`] using the provided RNG.
    pub fn into_strand(
        self,
        rng: &mut (dyn rand_core::RngCore + Send),
    ) -> (StrandDefinition, Vec<StrandStageBinding>) {
        let now = Utc::now();
        let strand_id = new_id(now, rng);

        let designation = match self.designation.as_str() {
            "registration" => StrandDesignation::Registration,
            "recovery" => StrandDesignation::Recovery,
            "password_change" => StrandDesignation::PasswordChange,
            "authentication" => StrandDesignation::Authentication,
            "authorization" => StrandDesignation::Authorization,
            "enrollment" => StrandDesignation::Enrollment,
            "stage_configuration" => StrandDesignation::StageConfiguration,
            other => panic!("unknown strand designation: {other}"),
        };

        let strand = StrandDefinition {
            id: strand_id,
            slug: self.slug,
            title: self.title,
            designation,
            enabled: true,
            template_override: self.template_override,
            created_at: now,
            updated_at: now,
        };

        let bindings = self
            .stages
            .into_iter()
            .map(|stage_def| {
                let (stage, order) = stage_def.into_stage_kind();
                StrandStageBinding {
                    id: new_id(now, rng),
                    strand_id,
                    stage,
                    order,
                    evaluate_on_plan: false,
                    policy_expression: None,
                    created_at: now,
                }
            })
            .collect();

        (strand, bindings)
    }
}

impl StageDefinition {
    /// Convert a [`StageDefinition`] into a ([`StageKind`], order) pair.
    fn into_stage_kind(self) -> (StageKind, i32) {
        match self {
            Self::Identification {
                order,
                user_fields,
                password_stage,
            } => {
                let fields = user_fields
                    .unwrap_or_default()
                    .into_iter()
                    .map(|f| match f.as_str() {
                        "username" => IdentificationField::Username,
                        "email" => IdentificationField::Email,
                        "phone" => IdentificationField::Phone,
                        other => panic!("unknown identification field: {other}"),
                    })
                    .collect();

                (
                    StageKind::Identification {
                        user_fields: fields,
                        password_stage: password_stage.unwrap_or(false),
                    },
                    order,
                )
            }
            Self::EmailVerification {
                order,
                purpose,
                template_key,
                code_expiry_seconds,
                max_attempts,
            } => (
                StageKind::EmailVerification {
                    purpose,
                    template_key,
                    code_expiry_seconds,
                    max_attempts,
                },
                order,
            ),
            Self::PasswordWrite {
                order,
                require_current,
            } => (
                StageKind::PasswordWrite {
                    require_current: require_current.unwrap_or(false),
                },
                order,
            ),
            Self::UserWrite {
                order,
                create_users_as_inactive,
            } => (
                StageKind::UserWrite {
                    create_users_as_inactive: create_users_as_inactive.unwrap_or(false),
                },
                order,
            ),
            Self::Captcha { order } => (StageKind::Captcha, order),
            Self::Consent { order } => (StageKind::Consent, order),
            Self::Prompt { order, fields } => (StageKind::Prompt { fields }, order),
            Self::AuthenticatorValidate {
                order,
                allowed_types,
            } => (StageKind::AuthenticatorValidate { allowed_types }, order),
        }
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::strand::StrandDesignation;
    use rand_core::SeedableRng;

    use super::*;

    fn test_rng() -> rand_chacha::ChaCha8Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(42)
    }

    #[test]
    fn parse_registration_strand_yaml() {
        let yaml = r"
slug: default-registration
title: Default Registration
designation: registration
stages:
  - type: user_write
    order: 10
    create_users_as_inactive: false
  - type: email_verification
    order: 20
    purpose: registration
    template_key: verification
    code_expiry_seconds: 300
    max_attempts: 5
";

        let file = StrandDefinitionFile::parse(yaml).expect("valid YAML");
        assert_eq!(file.slug, "default-registration");
        assert_eq!(file.title, "Default Registration");
        assert_eq!(file.designation, "registration");
        assert_eq!(file.stages.len(), 2);
    }

    #[test]
    fn into_strand_produces_correct_domain_types() {
        let yaml = r"
slug: test-recovery
title: Test Recovery
designation: recovery
stages:
  - type: identification
    order: 10
    user_fields:
      - email
    password_stage: false
  - type: email_verification
    order: 20
    purpose: recovery
    template_key: recovery
    code_expiry_seconds: 600
    max_attempts: 5
  - type: password_write
    order: 30
    require_current: false
";

        let file = StrandDefinitionFile::parse(yaml).expect("valid YAML");
        let mut rng = test_rng();
        let (strand, bindings) = file.into_strand(&mut rng);

        assert_eq!(strand.slug, "test-recovery");
        assert_eq!(strand.designation, StrandDesignation::Recovery);
        assert!(strand.enabled);
        assert_eq!(bindings.len(), 3);

        assert!(matches!(
            bindings[0].stage,
            StageKind::Identification { .. }
        ));
        assert!(matches!(
            bindings[1].stage,
            StageKind::EmailVerification { .. }
        ));
        assert!(matches!(bindings[2].stage, StageKind::PasswordWrite { .. }));

        assert_eq!(bindings[0].order, 10);
        assert_eq!(bindings[1].order, 20);
        assert_eq!(bindings[2].order, 30);

        // All bindings should reference the strand.
        assert!(bindings.iter().all(|b| b.strand_id == strand.id));
    }

    #[test]
    fn parse_minimal_captcha_stage() {
        let yaml = r"
slug: captcha-test
title: Captcha Test
designation: authentication
stages:
  - type: captcha
    order: 5
";

        let file = StrandDefinitionFile::parse(yaml).expect("valid YAML");
        let mut rng = test_rng();
        let (strand, bindings) = file.into_strand(&mut rng);

        assert_eq!(strand.designation, StrandDesignation::Authentication);
        assert_eq!(bindings.len(), 1);
        assert!(matches!(bindings[0].stage, StageKind::Captcha));
        assert_eq!(bindings[0].order, 5);
    }

    #[test]
    fn all_generated_ids_are_unique() {
        let yaml = r"
slug: id-test
title: ID Test
designation: registration
stages:
  - type: user_write
    order: 10
  - type: email_verification
    order: 20
    purpose: registration
    template_key: verification
    code_expiry_seconds: 300
    max_attempts: 5
";

        let file = StrandDefinitionFile::parse(yaml).expect("valid YAML");
        let mut rng = test_rng();
        let (strand, bindings) = file.into_strand(&mut rng);

        let mut ids = vec![strand.id];
        for b in &bindings {
            ids.push(b.id);
        }
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "all generated IDs must be unique");
    }
}
