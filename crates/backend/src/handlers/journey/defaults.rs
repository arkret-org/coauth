//! Built-in default journey definitions.
//!
//! These factory functions produce standard journeys for common user journeys.
//! They can be used directly or as templates for custom journeys stored in the
//! database.

use chrono::Utc;
use coauth_data::journey::{
    IdentificationField, JourneyDefinition, JourneyDesignation, JourneyStageBinding, StageKind,
};
use coauth_data::new_id;

/// Create the default registration journey:
/// 1. `UserWrite` — collect username / display name
/// 2. `EmailVerification` — verify the user's email address
pub fn default_registration_journey(
    rng: &mut (dyn rand_core::RngCore + Send),
) -> (JourneyDefinition, Vec<JourneyStageBinding>) {
    let now = Utc::now();
    let journey_id = new_id(now, rng);

    let journey = JourneyDefinition {
        id: journey_id,
        slug: "default-registration".into(),
        title: "Default Registration".into(),
        designation: JourneyDesignation::Registration,
        enabled: true,
        template_override: None,
        created_at: now,
        updated_at: now,
    };

    let bindings = vec![
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::UserWrite {
                create_users_as_inactive: false,
            },
            order: 10,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::EmailVerification {
                purpose: "registration".into(),
                template_key: "verification".into(),
                code_expiry_seconds: 300,
                max_attempts: 5,
            },
            order: 20,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
    ];

    (journey, bindings)
}

/// Create the default recovery journey:
/// 1. `Identification` — find the user by email
/// 2. `EmailVerification` — verify ownership of the email address
/// 3. `PasswordWrite` — set a new password
pub fn default_recovery_journey(
    rng: &mut (dyn rand_core::RngCore + Send),
) -> (JourneyDefinition, Vec<JourneyStageBinding>) {
    let now = Utc::now();
    let journey_id = new_id(now, rng);

    let journey = JourneyDefinition {
        id: journey_id,
        slug: "default-recovery".into(),
        title: "Default Recovery".into(),
        designation: JourneyDesignation::Recovery,
        enabled: true,
        template_override: None,
        created_at: now,
        updated_at: now,
    };

    let bindings = vec![
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::Identification {
                user_fields: vec![IdentificationField::Email],
                password_stage: false,
            },
            order: 10,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::EmailVerification {
                purpose: "recovery".into(),
                template_key: "recovery".into(),
                code_expiry_seconds: 600,
                max_attempts: 5,
            },
            order: 20,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::PasswordWrite {
                require_current: false,
            },
            order: 30,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
    ];

    (journey, bindings)
}

/// Create the default password change journey:
/// 1. `PasswordWrite` — require current password and set a new one
pub fn default_password_change_journey(
    rng: &mut (dyn rand_core::RngCore + Send),
) -> (JourneyDefinition, Vec<JourneyStageBinding>) {
    let now = Utc::now();
    let journey_id = new_id(now, rng);

    let journey = JourneyDefinition {
        id: journey_id,
        slug: "default-password-change".into(),
        title: "Default Password Change".into(),
        designation: JourneyDesignation::PasswordChange,
        enabled: true,
        template_override: None,
        created_at: now,
        updated_at: now,
    };

    let bindings = vec![JourneyStageBinding {
        id: new_id(now, rng),
        journey_id,
        stage: StageKind::PasswordWrite {
            require_current: true,
        },
        order: 10,
        evaluate_on_plan: false,
        policy_expression: None,
        created_at: now,
    }];

    (journey, bindings)
}

/// Create the default authentication journey:
/// 1. `Identification` — accept username or email with an inline password field
pub fn default_authentication_journey(
    rng: &mut (dyn rand_core::RngCore + Send),
) -> (JourneyDefinition, Vec<JourneyStageBinding>) {
    let now = Utc::now();
    let journey_id = new_id(now, rng);

    let journey = JourneyDefinition {
        id: journey_id,
        slug: "default-authentication".into(),
        title: "Default Authentication".into(),
        designation: JourneyDesignation::Authentication,
        enabled: true,
        template_override: None,
        created_at: now,
        updated_at: now,
    };

    let bindings = vec![JourneyStageBinding {
        id: new_id(now, rng),
        journey_id,
        stage: StageKind::Identification {
            user_fields: vec![IdentificationField::Username, IdentificationField::Email],
            password_stage: true,
        },
        order: 10,
        evaluate_on_plan: false,
        policy_expression: None,
        created_at: now,
    }];

    (journey, bindings)
}

/// Create the default authorization consent journey:
/// 1. `Consent` — show scope and client, get user approval
pub fn default_authorization_journey(
    rng: &mut (dyn rand_core::RngCore + Send),
) -> (JourneyDefinition, Vec<JourneyStageBinding>) {
    let now = Utc::now();
    let journey_id = new_id(now, rng);

    let journey = JourneyDefinition {
        id: journey_id,
        slug: "default-authorization".into(),
        title: "Authorization Consent".into(),
        designation: JourneyDesignation::Authorization,
        enabled: true,
        template_override: None,
        created_at: now,
        updated_at: now,
    };

    let bindings = vec![JourneyStageBinding {
        id: new_id(now, rng),
        journey_id,
        stage: StageKind::Consent,
        order: 10,
        evaluate_on_plan: false,
        policy_expression: None,
        created_at: now,
    }];

    (journey, bindings)
}

/// Create the default enrollment journey (invitation-based registration):
/// 1. `EnrollmentToken` — validate an invitation token
/// 2. `UserWrite` — collect username / display name
/// 3. `EmailVerification` — verify the user's email address
pub fn default_enrollment_journey(
    rng: &mut (dyn rand_core::RngCore + Send),
) -> (JourneyDefinition, Vec<JourneyStageBinding>) {
    let now = Utc::now();
    let journey_id = new_id(now, rng);

    let journey = JourneyDefinition {
        id: journey_id,
        slug: "default-enrollment".into(),
        title: "Invitation Registration".into(),
        designation: JourneyDesignation::Enrollment,
        enabled: true,
        template_override: None,
        created_at: now,
        updated_at: now,
    };

    let bindings = vec![
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::EnrollmentToken { required: true },
            order: 10,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::UserWrite {
                create_users_as_inactive: false,
            },
            order: 20,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
        JourneyStageBinding {
            id: new_id(now, rng),
            journey_id,
            stage: StageKind::EmailVerification {
                purpose: "registration".into(),
                template_key: "verification".into(),
                code_expiry_seconds: 300,
                max_attempts: 5,
            },
            order: 30,
            evaluate_on_plan: false,
            policy_expression: None,
            created_at: now,
        },
    ];

    (journey, bindings)
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;

    fn test_rng() -> rand_chacha::ChaCha8Rng {
        rand_chacha::ChaCha8Rng::seed_from_u64(42)
    }

    #[test]
    fn registration_journey_has_correct_designation_and_stages() {
        let mut rng = test_rng();
        let (journey, bindings) = default_registration_journey(&mut rng);

        assert_eq!(journey.slug, "default-registration");
        assert_eq!(journey.designation, JourneyDesignation::Registration);
        assert!(journey.enabled);
        assert_eq!(bindings.len(), 2);

        assert!(matches!(bindings[0].stage, StageKind::UserWrite { .. }));
        assert!(matches!(
            bindings[1].stage,
            StageKind::EmailVerification { .. }
        ));

        assert!(bindings[0].order < bindings[1].order);
        assert!(bindings.iter().all(|b| b.journey_id == journey.id));
    }

    #[test]
    fn recovery_journey_has_correct_designation_and_stages() {
        let mut rng = test_rng();
        let (journey, bindings) = default_recovery_journey(&mut rng);

        assert_eq!(journey.slug, "default-recovery");
        assert_eq!(journey.designation, JourneyDesignation::Recovery);
        assert!(journey.enabled);
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

        // Recovery password-write should NOT require the current password.
        if let StageKind::PasswordWrite { require_current } = &bindings[2].stage {
            assert!(!require_current);
        }

        assert!(bindings.windows(2).all(|w| w[0].order < w[1].order));
        assert!(bindings.iter().all(|b| b.journey_id == journey.id));
    }

    #[test]
    fn password_change_journey_has_correct_designation_and_stages() {
        let mut rng = test_rng();
        let (journey, bindings) = default_password_change_journey(&mut rng);

        assert_eq!(journey.slug, "default-password-change");
        assert_eq!(journey.designation, JourneyDesignation::PasswordChange);
        assert!(journey.enabled);
        assert_eq!(bindings.len(), 1);

        if let StageKind::PasswordWrite { require_current } = &bindings[0].stage {
            assert!(require_current);
        } else {
            panic!("expected PasswordWrite stage");
        }

        assert_eq!(bindings[0].journey_id, journey.id);
    }

    #[test]
    fn authentication_journey_has_correct_designation_and_stages() {
        let mut rng = test_rng();
        let (journey, bindings) = default_authentication_journey(&mut rng);

        assert_eq!(journey.slug, "default-authentication");
        assert_eq!(journey.designation, JourneyDesignation::Authentication);
        assert!(journey.enabled);
        assert_eq!(bindings.len(), 1);

        if let StageKind::Identification {
            user_fields,
            password_stage,
        } = &bindings[0].stage
        {
            assert!(user_fields.contains(&IdentificationField::Username));
            assert!(user_fields.contains(&IdentificationField::Email));
            assert!(password_stage);
        } else {
            panic!("expected Identification stage");
        }

        assert_eq!(bindings[0].journey_id, journey.id);
    }

    #[test]
    fn authorization_journey_has_correct_designation_and_stages() {
        let mut rng = test_rng();
        let (journey, bindings) = default_authorization_journey(&mut rng);

        assert_eq!(journey.slug, "default-authorization");
        assert_eq!(journey.designation, JourneyDesignation::Authorization);
        assert!(journey.enabled);
        assert_eq!(bindings.len(), 1);

        assert!(matches!(bindings[0].stage, StageKind::Consent));
        assert_eq!(bindings[0].journey_id, journey.id);
    }

    #[test]
    fn enrollment_journey_has_correct_designation_and_stages() {
        let mut rng = test_rng();
        let (journey, bindings) = default_enrollment_journey(&mut rng);

        assert_eq!(journey.slug, "default-enrollment");
        assert_eq!(journey.designation, JourneyDesignation::Enrollment);
        assert!(journey.enabled);
        assert_eq!(bindings.len(), 3);

        if let StageKind::EnrollmentToken { required } = &bindings[0].stage {
            assert!(required);
        } else {
            panic!("expected EnrollmentToken stage");
        }

        assert!(matches!(bindings[1].stage, StageKind::UserWrite { .. }));
        assert!(matches!(
            bindings[2].stage,
            StageKind::EmailVerification { .. }
        ));

        assert!(bindings.windows(2).all(|w| w[0].order < w[1].order));
        assert!(bindings.iter().all(|b| b.journey_id == journey.id));
    }

    #[test]
    fn all_ids_are_unique() {
        let mut rng = test_rng();
        let (f1, b1) = default_registration_journey(&mut rng);
        let (f2, b2) = default_recovery_journey(&mut rng);
        let (f3, b3) = default_password_change_journey(&mut rng);
        let (f4, b4) = default_authentication_journey(&mut rng);
        let (f5, b5) = default_authorization_journey(&mut rng);
        let (f6, b6) = default_enrollment_journey(&mut rng);

        let mut ids = vec![f1.id, f2.id, f3.id, f4.id, f5.id, f6.id];
        for b in b1
            .iter()
            .chain(&b2)
            .chain(&b3)
            .chain(&b4)
            .chain(&b5)
            .chain(&b6)
        {
            ids.push(b.id);
        }

        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "all generated IDs must be unique");
    }
}
