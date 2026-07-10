// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Round 4 (2026-05-20, spec a77b995) — `ak.cross_signing.publish`
//! issuance helper.
//!
//! Wire-breaking: the round-4 `ak.cross_signing.publish` envelope now
//! REQUIRES `expected_previous_generation` (CAS precondition) and the
//! cell_subject is the tuple `(principal_id, expected_previous_generation)`.
//! Reducers compare `expected_previous_generation == current_accepted`
//! and `generation == current_accepted + 1` **before** verifying any
//! signatures. Old `ak.cross_signing.publish` envelopes (no
//! `expected_previous_generation`) are rejected unconditionally.
//!
//! This module is the **issuance** side: when coauth needs to rotate
//! or initialise a principal's cross-signing keys it MUST:
//!   1. Read the principal's current accepted generation (from the principal-server
//!      `ak.self.account.query.describe` or local cache),
//!   2. Build a [`CrossSigningPublishContent`] with `expected_previous_generation =
//!      current_accepted` and `generation = current_accepted + 1`,
//!   3. Use [`cross_signing_publish_cell_subject(principal_id, expected_previous_generation)`] for
//!      the lattice cell key.
//!
//! Aggressive: there is no fallback path. Callers that don't know the
//! current generation MUST fetch it first; the engine returns
//! [`CrossSigningPublishError::GenerationUnknown`] rather than guess.

use chrono::{DateTime, Utc};
use arkret_crypto::{
    CrossSigningKeyRecord, CrossSigningPublishContent, SignedCrossSigningKey,
    cross_signing_publish_cell_subject,
};
use arkret_core::{Did, TypedTrustDomainId};
use thiserror::Error;

/// Errors raised by the cross-signing publish issuer.
#[derive(Debug, Error)]
pub enum CrossSigningPublishError {
    #[error("current cross-signing generation is unknown; fetch from principal server first")]
    GenerationUnknown,
    #[error("trust_domain is unset; configure ArkretConfig::trust_domain before publishing")]
    TrustDomainMissing,
    #[error("invalid principal_id: {0}")]
    InvalidPrincipal(String),
    #[error("SDK validation rejected the publish content: {0}")]
    SdkValidation(String),
}

/// Build a round-4 `CrossSigningPublishContent` with CAS bookkeeping
/// pre-filled. Callers supply the **currently accepted** generation
/// (`current_accepted_generation`); the helper sets
/// `expected_previous_generation = current` and
/// `generation = current + 1`. The pair is what the reducer's CAS check
/// will compare against.
///
/// On a reset path (key rotation), the new generation MUST strictly
/// equal `current + 1`. The reducer rejects any other delta with
/// `cas_conflict`.
#[allow(clippy::too_many_arguments)]
pub fn build_publish_content(
    principal_id: Did,
    trust_domain: TypedTrustDomainId,
    principal_signing_key: CrossSigningKeyRecord,
    self_signing_key: SignedCrossSigningKey,
    user_signing_key: SignedCrossSigningKey,
    current_accepted_generation: u64,
    issued_at: DateTime<Utc>,
) -> Result<CrossSigningPublishContent, CrossSigningPublishError> {
    let content = CrossSigningPublishContent {
        principal_id,
        trust_domain,
        principal_signing_key,
        self_signing_key,
        user_signing_key,
        expected_previous_generation: current_accepted_generation,
        generation: current_accepted_generation + 1,
        issued_at,
    };
    content
        .validate_structure()
        .map_err(|e| CrossSigningPublishError::SdkValidation(e.to_string()))?;
    Ok(content)
}

/// Build the cell_subject string the lattice uses to detect concurrent
/// publishes. Delegates to the SDK helper so coauth never drifts from
/// the canonical `<did>|<expected_previous_generation>` form.
#[must_use]
pub fn publish_cell_subject(principal_id: &Did, expected_previous_generation: u64) -> String {
    cross_signing_publish_cell_subject(principal_id, expected_previous_generation)
}

#[cfg(test)]
mod tests {
    use arkret_crypto::CrossSigningBinding;

    use super::*;

    fn principal() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn td() -> TypedTrustDomainId {
        TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap()
    }

    fn psk(kid: &str) -> CrossSigningKeyRecord {
        CrossSigningKeyRecord {
            kid: kid.to_owned(),
            alg: "Ed25519".to_owned(),
            public_key: format!("pubkey-{kid}"),
            key_format: "raw_base64url".to_owned(),
        }
    }

    fn ssk(kid: &str, psk_kid: &str, pub_suffix: &str) -> SignedCrossSigningKey {
        SignedCrossSigningKey {
            key: CrossSigningKeyRecord {
                kid: kid.to_owned(),
                alg: "Ed25519".to_owned(),
                public_key: format!("pubkey-{pub_suffix}"),
                key_format: "raw_base64url".to_owned(),
            },
            binding: CrossSigningBinding {
                verification_method: psk_kid.to_owned(),
                alg: "Ed25519".to_owned(),
                signature: "sig".to_owned(),
            },
        }
    }

    #[test]
    fn first_publish_sets_generation_to_one_and_expected_to_zero() {
        let now = Utc::now();
        let content = build_publish_content(
            principal(),
            td(),
            psk("psk-1"),
            ssk("ssk-1", "psk-1", "ssk-pub"),
            ssk("usk-1", "psk-1", "usk-pub"),
            0,
            now,
        )
        .unwrap();
        assert_eq!(content.expected_previous_generation, 0);
        assert_eq!(content.generation, 1);
    }

    #[test]
    fn subsequent_publish_strictly_increments_by_one() {
        let now = Utc::now();
        let content = build_publish_content(
            principal(),
            td(),
            psk("psk-2"),
            ssk("ssk-2", "psk-2", "ssk-pub-2"),
            ssk("usk-2", "psk-2", "usk-pub-2"),
            5,
            now,
        )
        .unwrap();
        assert_eq!(content.expected_previous_generation, 5);
        assert_eq!(content.generation, 6);
    }

    #[test]
    fn publish_cell_subject_matches_sdk_helper() {
        let s = publish_cell_subject(&principal(), 7);
        // Wire form per SDK: `<did>|<expected_previous_generation>`.
        assert_eq!(s, "did:web:alice.example|7");
    }
}
