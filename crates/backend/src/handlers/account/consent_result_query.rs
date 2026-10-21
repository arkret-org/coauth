// Copyright 2026 Taidge Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

//! Coauth intake has no holder-private PCR read authority. A summary cannot
//! authorize delivery; the holder Station owns native invite admission.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteGateDecision {
    ConsentRequired,
    Quarantine,
}

/// Without a verified holder current, require Consent or defer to review.
#[must_use]
pub fn evaluate_invite_gate(consent_required: bool) -> InviteGateDecision {
    if consent_required {
        InviteGateDecision::ConsentRequired
    } else {
        InviteGateDecision::Quarantine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intake_without_holder_authority_never_authorizes_delivery() {
        assert_eq!(
            evaluate_invite_gate(true),
            InviteGateDecision::ConsentRequired
        );
        assert_eq!(evaluate_invite_gate(false), InviteGateDecision::Quarantine);
    }
}
