use chrono::Duration;
use coauth_data::UserRegistration;

use super::{
    RegistrationProgress, RegistrationWorkflowDeadline, RegistrationWorkflowDeadlineKind,
    RegistrationWorkflowEvent, RegistrationWorkflowEventKind, RegistrationWorkflowSnapshot,
    RegistrationWorkflowState,
};

impl RegistrationProgress {
    #[must_use]
    pub fn workflow_state(&self) -> RegistrationWorkflowState {
        if self.registration.completed_at.is_some() {
            return RegistrationWorkflowState::Completed;
        }

        if self.registration.email_authentication_id.is_some() && !self.email_verified() {
            return RegistrationWorkflowState::PendingEmailVerification;
        }

        if self.registration.phone_authentication_id.is_some() && !self.phone_verified() {
            return RegistrationWorkflowState::PendingPhoneVerification;
        }

        if self.registration.display_name.is_none() {
            return RegistrationWorkflowState::PendingDisplayName;
        }

        RegistrationWorkflowState::ReadyToFinish
    }

    #[must_use]
    pub fn email_verified(&self) -> bool {
        self.email_authentication.as_ref().map_or(
            self.registration.email_authentication_id.is_none(),
            |auth| auth.completed_at.is_some(),
        )
    }

    #[must_use]
    pub fn phone_verified(&self) -> bool {
        self.phone_authentication.as_ref().map_or(
            self.registration.phone_authentication_id.is_none(),
            |auth| auth.completed_at.is_some(),
        )
    }

    #[must_use]
    pub fn next_step(&self) -> &'static str {
        next_registration_step(
            &self.registration,
            self.email_verified(),
            self.phone_verified(),
        )
    }

    #[must_use]
    pub fn completed_steps(&self) -> Vec<&'static str> {
        completed_registration_steps(
            &self.registration,
            self.email_verified(),
            self.phone_verified(),
        )
    }

    #[must_use]
    pub fn workflow_events(&self) -> Vec<RegistrationWorkflowEvent> {
        let mut events = vec![RegistrationWorkflowEvent {
            kind: RegistrationWorkflowEventKind::Started,
            occurred_at: self.registration.created_at,
        }];

        if let Some(email_authentication) = &self.email_authentication {
            events.push(RegistrationWorkflowEvent {
                kind: RegistrationWorkflowEventKind::EmailVerificationRequested,
                occurred_at: email_authentication.created_at,
            });

            if let Some(completed_at) = email_authentication.completed_at {
                events.push(RegistrationWorkflowEvent {
                    kind: RegistrationWorkflowEventKind::EmailVerified,
                    occurred_at: completed_at,
                });
            }
        }

        if let Some(phone_authentication) = &self.phone_authentication {
            events.push(RegistrationWorkflowEvent {
                kind: RegistrationWorkflowEventKind::PhoneVerificationRequested,
                occurred_at: phone_authentication.created_at,
            });

            if let Some(completed_at) = phone_authentication.completed_at {
                events.push(RegistrationWorkflowEvent {
                    kind: RegistrationWorkflowEventKind::PhoneVerified,
                    occurred_at: completed_at,
                });
            }
        }

        if let Some(completed_at) = self.registration.completed_at {
            events.push(RegistrationWorkflowEvent {
                kind: RegistrationWorkflowEventKind::Completed,
                occurred_at: completed_at,
            });
        }

        events.sort_by_key(|event| event.occurred_at);
        events
    }

    #[must_use]
    pub fn workflow_deadlines(&self) -> Vec<RegistrationWorkflowDeadline> {
        if self.registration.completed_at.is_some() {
            return Vec::new();
        }

        vec![RegistrationWorkflowDeadline {
            kind: RegistrationWorkflowDeadlineKind::RegistrationExpiresAt,
            due_at: self.registration.created_at + Duration::hours(1),
        }]
    }

    #[must_use]
    pub fn workflow_snapshot(&self) -> RegistrationWorkflowSnapshot {
        let state = self.workflow_state();
        let next_step = match state {
            RegistrationWorkflowState::Completed => None,
            _ => Some(self.next_step()),
        };

        RegistrationWorkflowSnapshot {
            state,
            next_step,
            completed_steps: self.completed_steps(),
            events: self.workflow_events(),
            deadlines: self.workflow_deadlines(),
        }
    }
}

#[must_use]
pub fn next_registration_step(
    registration: &UserRegistration,
    email_verified: bool,
    phone_verified: bool,
) -> &'static str {
    if registration.email_authentication_id.is_some() && !email_verified {
        return "verify_email";
    }

    if registration.phone_authentication_id.is_some() && !phone_verified {
        return "verify_phone";
    }

    if registration.display_name.is_none() {
        return "display_name";
    }

    "finish"
}

#[must_use]
pub fn completed_registration_steps(
    registration: &UserRegistration,
    email_verified: bool,
    phone_verified: bool,
) -> Vec<&'static str> {
    let mut steps = Vec::new();
    steps.push("register");

    if registration.email_authentication_id.is_some() && email_verified {
        steps.push("verify_email");
    }

    if registration.phone_authentication_id.is_some() && phone_verified {
        steps.push("verify_phone");
    }

    if registration.display_name.is_some() {
        steps.push("display_name");
    }

    if registration.completed_at.is_some() {
        steps.push("finish");
    }

    steps
}
