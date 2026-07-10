// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! COA-ORG-02 — organization DID / PCR bootstrap authorization decision.
//!
//! Decides whether an organization Principal Control Realm (PCR) genesis is
//! authorized, per `identity-did.md` §7. There are exactly two acceptable
//! shapes:
//!
//! 1. **DID controller proof** — a verified proof of the organization DID method inception /
//!    controller key, bound to `principal_control_realm_id`, `fields.purpose = "principal_control"`
//!    and `ak.profile.principal_control_realm.v1`.
//! 2. **Delegated governance** — a delegation declared in the organization DID Document /
//!    governance profile to an Account Authority or `ArkretGovernanceService` whose delegation
//!    purpose covers `principal_control_realm_bootstrap`, recorded with the actual executor.
//!
//! Crucially, a human OIDC / passkey / password session is **never** one of
//! these. A logged-in admin can only ever appear as the `executed_by` executor
//! of a delegated bootstrap; their session alone carries no organization
//! control authority. This module returns a typed decision; persistence of the
//! resulting control row is the caller's job
//! ([`coauth_data::organization_control::OrganizationControlRepository::bootstrap`]).

use coauth_data::organization_control::{
    OrganizationBootstrapAuthorization, OrganizationDelegation,
};
use thiserror::Error;

/// Why a PCR bootstrap was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OrganizationBootstrapError {
    /// A human / service admin session was presented as if it were
    /// organization control. It is not.
    #[error(
        "an authenticated admin session is only an executor; organization PCR bootstrap requires a DID controller proof or a principal_control_realm_bootstrap delegation"
    )]
    SessionIsNotOrganizationControl,
    /// A delegated bootstrap was requested but no delegation reference was
    /// supplied.
    #[error("delegated bootstrap requires a delegation_ref")]
    MissingDelegationRef,
    /// The referenced delegation did not resolve.
    #[error("delegation_ref did not resolve to a known organization delegation")]
    DelegationNotFound,
    /// The referenced delegation is anchored to a different organization DID.
    #[error("delegation is anchored to a different organization DID")]
    DelegationOrgMismatch,
    /// The referenced delegation is expired or revoked.
    #[error("delegation is not live (expired or revoked)")]
    DelegationNotLive,
    /// The referenced delegation's purpose does not cover
    /// `principal_control_realm_bootstrap`.
    #[error("delegation purpose does not cover principal_control_realm_bootstrap")]
    DelegationPurposeNotCovered,
    /// A controller-proof bootstrap was requested without a verified controller
    /// proof.
    #[error("controller-proof bootstrap requires a verified DID controller proof")]
    MissingControllerProof,
}

/// What the caller is attempting to use to authorize the bootstrap.
pub enum BootstrapAttempt<'a> {
    /// A verified DID controller proof. The caller has already verified the
    /// proof crypto + the `principal_control` purpose / profile binding; this
    /// carries the opaque proof digest to record.
    ControllerProof { proof_digest: Option<String> },
    /// A delegated governance bootstrap referencing an organization delegation
    /// row loaded from `organization_delegations`.
    Delegated {
        delegation_ref: &'a str,
        delegation: Option<&'a OrganizationDelegation>,
    },
}

/// The authorized bootstrap outcome the caller persists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBootstrap {
    pub bootstrap_authorization: OrganizationBootstrapAuthorization,
    /// Present only for delegated bootstraps.
    pub bootstrap_delegation_ref: Option<String>,
    /// Opaque proof / governance-decision digest to record for audit.
    pub bootstrap_proof_digest: Option<String>,
}

/// Decide whether an organization PCR bootstrap is authorized.
///
/// `organization_did` is the organization principal whose PCR is being
/// bootstrapped. `has_admin_session` records that an authenticated admin /
/// service principal is the *executor*; it never authorizes the bootstrap by
/// itself, but a delegated bootstrap MUST have an executor present (the
/// `executed_by` boundary the spec requires).
pub fn authorize_bootstrap(
    organization_did: &str,
    has_admin_session: bool,
    attempt: BootstrapAttempt<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AuthorizedBootstrap, OrganizationBootstrapError> {
    match attempt {
        BootstrapAttempt::ControllerProof { proof_digest } => {
            // A controller proof stands on its own; an admin session, if any,
            // is irrelevant to the authority.
            if proof_digest
                .as_deref()
                .is_some_and(|d| !d.trim().is_empty())
            {
                Ok(AuthorizedBootstrap {
                    bootstrap_authorization: OrganizationBootstrapAuthorization::DidControllerProof,
                    bootstrap_delegation_ref: None,
                    bootstrap_proof_digest: proof_digest,
                })
            } else {
                Err(OrganizationBootstrapError::MissingControllerProof)
            }
        }
        BootstrapAttempt::Delegated {
            delegation_ref,
            delegation,
        } => {
            if delegation_ref.trim().is_empty() {
                return Err(OrganizationBootstrapError::MissingDelegationRef);
            }
            // The spec requires the actual executor be recorded. A delegated
            // bootstrap with no executing principal at all is rejected — the
            // organization principal can never "log itself in".
            if !has_admin_session {
                return Err(OrganizationBootstrapError::SessionIsNotOrganizationControl);
            }
            let delegation = delegation.ok_or(OrganizationBootstrapError::DelegationNotFound)?;
            if delegation.organization_did != organization_did {
                return Err(OrganizationBootstrapError::DelegationOrgMismatch);
            }
            if !delegation.is_live(now) {
                return Err(OrganizationBootstrapError::DelegationNotLive);
            }
            if !delegation.covers_pcr_bootstrap() {
                return Err(OrganizationBootstrapError::DelegationPurposeNotCovered);
            }
            Ok(AuthorizedBootstrap {
                bootstrap_authorization: OrganizationBootstrapAuthorization::DelegatedGovernance,
                bootstrap_delegation_ref: Some(delegation_ref.to_owned()),
                bootstrap_proof_digest: None,
            })
        }
    }
}

// ── COA-ORG-04 — session grant / organization control boundary ───
//
// A human/service session grant MAY carry an "acting on behalf of an
// organization" authorization context, but that context MUST reference an
// existing, live delegation anchored to the claimed organization DID. A bare
// session — no delegation, an expired/revoked delegation, or a delegation for a
// different organization — can NEVER be accepted as organization consent.

/// Why an "act on behalf of organization" context attached to a session grant
/// was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OrganizationActingContextError {
    /// The session presented no delegation reference for the claimed
    /// organization — a bare login is not organization consent.
    #[error("session grant cannot act for an organization without referencing a delegation")]
    NoDelegationReferenced,
    /// The referenced delegation did not resolve.
    #[error("referenced organization delegation did not resolve")]
    DelegationNotFound,
    /// The referenced delegation is anchored to a different organization DID
    /// than the one the session claims to act for (wrong-organization forgery).
    #[error("referenced delegation is anchored to a different organization DID")]
    DelegationOrgMismatch,
    /// The referenced delegation is expired or revoked.
    #[error("referenced organization delegation is not live (expired or revoked)")]
    DelegationNotLive,
    /// The session's claimed control scopes exceed what the delegation covers
    /// (scope forgery).
    #[error("session grant claims control scopes the delegation does not cover")]
    ScopesExceedDelegation,
}

/// Validate that a session grant may act on behalf of `organization_did` with
/// the requested `requested_scopes`.
///
/// `acting_delegation_ref` is the delegation the session grant claims to derive
/// its organization authority from; `delegation` is the row loaded for that
/// ref. Returns `Ok` only when the delegation resolves, matches the claimed
/// organization, is live, and covers every requested scope. This is the
/// fail-closed gate that keeps a plain OIDC/passkey/password login from ever
/// being accepted as organization consent.
pub fn validate_session_acting_for_organization(
    organization_did: &str,
    acting_delegation_ref: Option<&str>,
    delegation: Option<&OrganizationDelegation>,
    requested_scopes: &[arkret_core::models::RealmOrganizationControlScope],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), OrganizationActingContextError> {
    let reference = acting_delegation_ref
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
        .ok_or(OrganizationActingContextError::NoDelegationReferenced)?;
    let delegation = delegation.ok_or(OrganizationActingContextError::DelegationNotFound)?;
    if delegation.delegation_ref != reference {
        return Err(OrganizationActingContextError::DelegationNotFound);
    }
    if delegation.organization_did != organization_did {
        return Err(OrganizationActingContextError::DelegationOrgMismatch);
    }
    if !delegation.is_live(now) {
        return Err(OrganizationActingContextError::DelegationNotLive);
    }
    if !requested_scopes
        .iter()
        .all(|scope| delegation.covered_control_scopes.contains(scope))
    {
        return Err(OrganizationActingContextError::ScopesExceedDelegation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use coauth_data::organization_control::OrganizationDelegationStatus;
    use arkret_core::models::{
        RealmOrganizationControlScope, RealmOrganizationIssuerRole, RealmOrganizationRelationship,
    };

    use super::*;

    fn now() -> chrono::DateTime<chrono::Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn delegation(org: &str, covers_bootstrap: bool) -> OrganizationDelegation {
        OrganizationDelegation {
            id: "01J0".to_owned(),
            delegation_ref: "ak:grant:01904100-0000-7000-8000-000000000001".to_owned(),
            organization_did: org.to_owned(),
            delegate_did: "did:web:server.acme.example".to_owned(),
            issuer_role: RealmOrganizationIssuerRole::GovernanceService,
            purposes: if covers_bootstrap {
                vec!["principal_control_realm_bootstrap".to_owned()]
            } else {
                vec!["space_endorsement".to_owned()]
            },
            covered_relationships: vec![RealmOrganizationRelationship::Owner],
            covered_control_scopes: vec![RealmOrganizationControlScope::RealmAdmin],
            status: OrganizationDelegationStatus::Active,
            valid_from: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            valid_until: None,
            created_by: "did:web:admin.example".to_owned(),
            created_at: now(),
            updated_at: now(),
            revoked_at: None,
        }
    }

    #[test]
    fn controller_proof_authorizes_bootstrap() {
        let out = authorize_bootstrap(
            "did:web:org.example",
            false,
            BootstrapAttempt::ControllerProof {
                proof_digest: Some("sha256:abc".to_owned()),
            },
            now(),
        )
        .unwrap();
        assert_eq!(
            out.bootstrap_authorization,
            OrganizationBootstrapAuthorization::DidControllerProof
        );
        assert!(out.bootstrap_delegation_ref.is_none());
    }

    #[test]
    fn admin_session_alone_cannot_bootstrap() {
        // No controller proof and no delegation — just a logged-in admin. The
        // delegated path requires an actual delegation row.
        let err = authorize_bootstrap(
            "did:web:org.example",
            true,
            BootstrapAttempt::Delegated {
                delegation_ref: "ak:grant:01904100-0000-7000-8000-000000000001",
                delegation: None,
            },
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationBootstrapError::DelegationNotFound);
    }

    #[test]
    fn delegated_bootstrap_without_executor_is_rejected() {
        let d = delegation("did:web:org.example", true);
        let err = authorize_bootstrap(
            "did:web:org.example",
            false,
            BootstrapAttempt::Delegated {
                delegation_ref: &d.delegation_ref,
                delegation: Some(&d),
            },
            now(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            OrganizationBootstrapError::SessionIsNotOrganizationControl
        );
    }

    #[test]
    fn delegated_bootstrap_with_live_covering_delegation_succeeds() {
        let d = delegation("did:web:org.example", true);
        let out = authorize_bootstrap(
            "did:web:org.example",
            true,
            BootstrapAttempt::Delegated {
                delegation_ref: &d.delegation_ref,
                delegation: Some(&d),
            },
            now(),
        )
        .unwrap();
        assert_eq!(
            out.bootstrap_authorization,
            OrganizationBootstrapAuthorization::DelegatedGovernance
        );
        assert_eq!(
            out.bootstrap_delegation_ref.as_deref(),
            Some(d.delegation_ref.as_str())
        );
    }

    #[test]
    fn delegated_bootstrap_wrong_org_rejected() {
        let d = delegation("did:web:other.example", true);
        let err = authorize_bootstrap(
            "did:web:org.example",
            true,
            BootstrapAttempt::Delegated {
                delegation_ref: &d.delegation_ref,
                delegation: Some(&d),
            },
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationBootstrapError::DelegationOrgMismatch);
    }

    #[test]
    fn delegated_bootstrap_purpose_not_covered_rejected() {
        let d = delegation("did:web:org.example", false);
        let err = authorize_bootstrap(
            "did:web:org.example",
            true,
            BootstrapAttempt::Delegated {
                delegation_ref: &d.delegation_ref,
                delegation: Some(&d),
            },
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationBootstrapError::DelegationPurposeNotCovered);
    }

    #[test]
    fn delegated_bootstrap_revoked_delegation_rejected() {
        let mut d = delegation("did:web:org.example", true);
        d.status = OrganizationDelegationStatus::Revoked;
        d.revoked_at = Some(Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap());
        let err = authorize_bootstrap(
            "did:web:org.example",
            true,
            BootstrapAttempt::Delegated {
                delegation_ref: &d.delegation_ref,
                delegation: Some(&d),
            },
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationBootstrapError::DelegationNotLive);
    }

    // ── COA-ORG-04 session boundary negative tests ──────────────

    #[test]
    fn bare_session_cannot_act_for_organization() {
        let err = validate_session_acting_for_organization(
            "did:web:org.example",
            None,
            None,
            &[RealmOrganizationControlScope::RealmAdmin],
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationActingContextError::NoDelegationReferenced);
    }

    #[test]
    fn session_acting_with_wrong_organization_rejected() {
        let d = delegation("did:web:other.example", true);
        let err = validate_session_acting_for_organization(
            "did:web:org.example",
            Some(&d.delegation_ref),
            Some(&d),
            &[RealmOrganizationControlScope::RealmAdmin],
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationActingContextError::DelegationOrgMismatch);
    }

    #[test]
    fn session_acting_with_expired_delegation_rejected() {
        let mut d = delegation("did:web:org.example", true);
        d.valid_until = Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
        let err = validate_session_acting_for_organization(
            "did:web:org.example",
            Some(&d.delegation_ref),
            Some(&d),
            &[RealmOrganizationControlScope::RealmAdmin],
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationActingContextError::DelegationNotLive);
    }

    #[test]
    fn session_acting_with_forged_scope_rejected() {
        // Delegation covers only RealmAdmin; session claims NotaryControl too.
        let d = delegation("did:web:org.example", true);
        let err = validate_session_acting_for_organization(
            "did:web:org.example",
            Some(&d.delegation_ref),
            Some(&d),
            &[
                RealmOrganizationControlScope::RealmAdmin,
                RealmOrganizationControlScope::NotaryControl,
            ],
            now(),
        )
        .unwrap_err();
        assert_eq!(err, OrganizationActingContextError::ScopesExceedDelegation);
    }

    #[test]
    fn session_acting_with_live_covering_delegation_allowed() {
        let d = delegation("did:web:org.example", true);
        validate_session_acting_for_organization(
            "did:web:org.example",
            Some(&d.delegation_ref),
            Some(&d),
            &[RealmOrganizationControlScope::RealmAdmin],
            now(),
        )
        .unwrap();
    }
}
