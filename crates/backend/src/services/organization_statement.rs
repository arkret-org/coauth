// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! COA-ORG-03 — `ck.realm.organization` statement issuance + a repository-backed
//! delegation resolver for the SDK verifier.
//!
//! This module owns the organization-side authorization proof. It builds a
//! [`RealmOrganizationPayload`] (the SDK wire type — no locally-defined wire
//! struct), signs its canonical-JSON bytes with the coauth service signing key
//! (mirroring [`crate::services::policy_signer`]), and self-verifies the result
//! with the SDK [`verify_realm_organization_statement`] before returning so a
//! malformed statement never escapes coauth.
//!
//! It deliberately does **not** issue the Realm-side `ck.realm.admin`
//! authorization required to write the event into Realm history — that is
//! soland's job. coauth only produces the organization-side endorsement /
//! revocation proof.
//!
//! ## Boundary
//!
//! Issuing a delegated statement (`issuer_role` ∈ {governance_service,
//! account_authority}) requires a resolvable, live organization delegation. The
//! [`RepositoryDelegationResolver`] resolves `authorization.delegation_ref`
//! against the durable `organization_delegations` table, so a forged or expired
//! delegation fails closed exactly as soland's verifier would reject it.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use coauth_data::organization_control::OrganizationDelegation;
use coauth_jose::constraints::Constrainable as _;
use coauth_keystore::Keystore;
use cokret_core::canonical::canonical_json_bytes;
use cokret_core::models::{
    NoDelegationResolver, RealmOrganizationAuthorization, RealmOrganizationControlScope,
    RealmOrganizationDelegation, RealmOrganizationDelegationResolver, RealmOrganizationIssuerRole,
    RealmOrganizationPayload, RealmOrganizationRelationship, RealmOrganizationStatus,
    SignatureMaterial, verify_realm_organization_statement,
};
use cokret_core::{Did, RealmId};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;
use serde::Serialize;
use signature::RandomizedSigner as _;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OrganizationStatementError {
    #[error("no usable service signing key in keystore")]
    NoSigningKey,
    #[error("keystore signing key rejected the statement algorithm")]
    KeyAlgMismatch,
    #[error("canonical-JSON encoding of the organization statement failed: {0}")]
    Canonical(String),
    #[error("ed25519 / ecdsa signing of the organization statement failed")]
    Sign,
    #[error("delegated issuer_role requires a delegation_ref")]
    MissingDelegationRef,
    #[error("non-delegated issuer_role must not carry a delegation_ref")]
    UnexpectedDelegationRef,
    #[error("the issued statement failed self-verification: {0}")]
    SelfVerify(String),
}

/// Inputs needed to issue a `ck.realm.organization` statement. The caller has
/// already authorized the action; this struct carries the verified shape to
/// sign.
#[derive(Debug, Clone)]
pub struct OrganizationStatementRequest {
    pub statement_id: String,
    pub realm_id: RealmId,
    pub organization_id: Did,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_statement_id: Option<String>,
    pub revokes_statement_id: Option<String>,
    pub realm_frontier_digest: Option<cokret_core::Hash>,
    pub organization_policy_ref: Option<String>,
    pub issuer: Did,
    pub issuer_role: RealmOrganizationIssuerRole,
    /// REQUIRED for delegated issuer roles; MUST be absent otherwise. This is
    /// the same ref the [`RepositoryDelegationResolver`] resolves.
    pub delegation_ref: Option<String>,
    /// Human admin / service principal that initiated the decision. Recorded on
    /// the proof, never elevated to the organization principal.
    pub executed_by: Option<Did>,
}

/// Canonical bytes the proof signs over. We sign every field of the statement
/// except the inner `authorization.proof` (which is the signature itself), so a
/// verifier can rebuild the exact bytes from the wire statement. Optional
/// fields are omitted when absent so the bytes are stable.
#[derive(Debug, Serialize)]
struct OrganizationStatementTranscript<'a> {
    kind: &'a str,
    statement_id: &'a str,
    realm_id: &'a RealmId,
    organization_id: &'a Did,
    relationship: &'a RealmOrganizationRelationship,
    status: &'a RealmOrganizationStatus,
    control_scopes: &'a [RealmOrganizationControlScope],
    issued_at: &'a chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<&'a chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<&'a chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revokes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    realm_frontier_digest: Option<&'a cokret_core::Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_policy_ref: Option<&'a String>,
    issuer: &'a Did,
    issuer_role: &'a RealmOrganizationIssuerRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_ref: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_by: Option<&'a Did>,
}

const ORGANIZATION_STATEMENT_TRANSCRIPT_KIND: &str = "ck.realm.organization.statement.v1";

/// Issue a signed `ck.realm.organization` statement.
///
/// `service_did` is the coauth service DID used to construct the
/// `verification_method` DID-URL. `now` and `resolver` feed the SDK
/// self-verification step. The returned payload is structurally + semantically
/// valid per the SDK verifier; the cryptographic signature in
/// `authorization.proof` is a detached base64url signature over the canonical
/// transcript.
pub fn issue_organization_statement<R>(
    key_store: &Keystore,
    service_did: &str,
    request: OrganizationStatementRequest,
    now: chrono::DateTime<chrono::Utc>,
    resolver: &R,
) -> Result<RealmOrganizationPayload, OrganizationStatementError>
where
    R: RealmOrganizationDelegationResolver,
{
    // issuer-role / delegation_ref coupling, enforced here too so we never sign
    // an internally-inconsistent statement.
    match (
        request.issuer_role.requires_delegation_ref(),
        request.delegation_ref.is_some(),
    ) {
        (true, false) => return Err(OrganizationStatementError::MissingDelegationRef),
        (false, true) => return Err(OrganizationStatementError::UnexpectedDelegationRef),
        _ => {}
    }

    let transcript = OrganizationStatementTranscript {
        kind: ORGANIZATION_STATEMENT_TRANSCRIPT_KIND,
        statement_id: &request.statement_id,
        realm_id: &request.realm_id,
        organization_id: &request.organization_id,
        relationship: &request.relationship,
        status: &request.status,
        control_scopes: &request.control_scopes,
        issued_at: &request.issued_at,
        not_before: request.not_before.as_ref(),
        expires_at: request.expires_at.as_ref(),
        supersedes_statement_id: request.supersedes_statement_id.as_ref(),
        revokes_statement_id: request.revokes_statement_id.as_ref(),
        realm_frontier_digest: request.realm_frontier_digest.as_ref(),
        organization_policy_ref: request.organization_policy_ref.as_ref(),
        issuer: &request.issuer,
        issuer_role: &request.issuer_role,
        delegation_ref: request.delegation_ref.as_ref(),
        executed_by: request.executed_by.as_ref(),
    };

    let canonical = canonical_json_bytes(&transcript)
        .map_err(|e| OrganizationStatementError::Canonical(e.to_string()))?;

    let (alg, key) =
        preferred_service_signing_key(key_store).ok_or(OrganizationStatementError::NoSigningKey)?;
    let key_id = key.kid().ok_or(OrganizationStatementError::NoSigningKey)?;
    let signer = key_store
        .signer_for_algorithm(&alg)
        .map_err(|_| OrganizationStatementError::KeyAlgMismatch)?;
    let mut rng =
        ChaChaRng::from_rng(rand_core::OsRng).map_err(|_| OrganizationStatementError::Sign)?;
    let raw = signer
        .try_sign_with_rng(&mut rng, &canonical)
        .map_err(|_| OrganizationStatementError::Sign)?;
    let sig_bytes: Box<[u8]> = raw.into();
    let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
    let verification_method = format!("{service_did}#{key_id}");

    let payload = RealmOrganizationPayload {
        statement_id: request.statement_id,
        realm_id: request.realm_id.clone(),
        organization_id: request.organization_id,
        relationship: request.relationship,
        status: request.status,
        control_scopes: request.control_scopes,
        issued_at: request.issued_at,
        not_before: request.not_before,
        expires_at: request.expires_at,
        supersedes_statement_id: request.supersedes_statement_id,
        revokes_statement_id: request.revokes_statement_id,
        realm_frontier_digest: request.realm_frontier_digest,
        organization_policy_ref: request.organization_policy_ref,
        authorization: RealmOrganizationAuthorization {
            issuer: request.issuer,
            issuer_role: request.issuer_role,
            verification_method,
            delegation_ref: request.delegation_ref,
            executed_by: request.executed_by,
            signed_at: now,
            proof: SignatureMaterial::NonEmptyString(sig_b64),
        },
    };

    // COA-ORG-03 acceptance: the statement we sign is exactly the statement
    // soland's SDK verifier accepts. Self-verify before returning.
    let expected_realm_id = payload.realm_id.clone();
    verify_realm_organization_statement(&payload, &expected_realm_id, now, resolver)
        .map_err(|e| OrganizationStatementError::SelfVerify(e.to_string()))?;

    Ok(payload)
}

/// Resolver that maps a durable [`OrganizationDelegation`] (loaded by the
/// caller from `organization_delegations`) to the SDK
/// [`RealmOrganizationDelegation`] the verifier expects. Holds at most one
/// delegation — the one whose `delegation_ref` was requested — and returns it
/// only when the requested ref + organization match.
pub struct RepositoryDelegationResolver {
    delegation: Option<OrganizationDelegation>,
    now: chrono::DateTime<chrono::Utc>,
}

impl RepositoryDelegationResolver {
    /// Build from a (possibly absent) delegation row and the evaluation time.
    #[must_use]
    pub fn new(
        delegation: Option<OrganizationDelegation>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self { delegation, now }
    }
}

impl RealmOrganizationDelegationResolver for RepositoryDelegationResolver {
    fn resolve_delegation(
        &self,
        delegation_ref: &cokret_core::models::ObjectRef,
        organization_id: &Did,
    ) -> cokret_core::Result<Option<RealmOrganizationDelegation>> {
        let Some(delegation) = self.delegation.as_ref() else {
            return Ok(None);
        };
        // Fail closed when the loaded row does not match the requested ref or
        // is anchored to a different organization.
        if &delegation.delegation_ref != delegation_ref
            || delegation.organization_did != organization_id.as_str()
        {
            return Ok(None);
        }
        Ok(Some(RealmOrganizationDelegation {
            organization_id: organization_id.clone(),
            is_live: delegation.is_live(self.now),
            covered_relationships: delegation.covered_relationships.clone(),
            covered_control_scopes: delegation.covered_control_scopes.clone(),
        }))
    }
}

/// Convenience: a resolver that never resolves, for non-delegated statements.
#[must_use]
pub fn offline_resolver() -> NoDelegationResolver {
    NoDelegationResolver
}

/// Pick the preferred service signing key from the keystore — identical key
/// selection to [`crate::services::policy_signer`] and
/// `handlers::cokret::preferred_signing_key`, so coauth signs organization
/// statements with the same key it uses for every other service artefact.
fn preferred_service_signing_key(
    key_store: &Keystore,
) -> Option<(
    coauth_iana::jose::JsonWebSignatureAlg,
    &coauth_keystore::JsonWebKey<coauth_keystore::PrivateKey>,
)> {
    use coauth_iana::jose::JsonWebSignatureAlg;
    [
        JsonWebSignatureAlg::EdDsa,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps256,
    ]
    .into_iter()
    .find_map(|alg| {
        key_store
            .signing_key_for_algorithm(&alg)
            .map(|key| (alg, key))
    })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use coauth_data::organization_control::OrganizationDelegationStatus;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000010").unwrap()
    }

    fn org_did() -> Did {
        Did::new("did:webvh:example.test:orgs:org1".to_owned()).unwrap()
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn keystore() -> Keystore {
        use coauth_keystore::{JsonWebKey, JsonWebKeySet, PrivateKey};
        use rand_chacha::ChaChaRng;
        use rand_core::SeedableRng;

        let mut rng = ChaChaRng::seed_from_u64(42);
        let eddsa = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid("service-signing");
        Keystore::new(JsonWebKeySet::new(vec![eddsa]))
    }

    fn base_request() -> OrganizationStatementRequest {
        OrganizationStatementRequest {
            statement_id: "org-stmt-1".to_owned(),
            realm_id: realm_id(),
            organization_id: org_did(),
            relationship: RealmOrganizationRelationship::Owner,
            status: RealmOrganizationStatus::Active,
            control_scopes: vec![RealmOrganizationControlScope::RealmAdmin],
            issued_at: now(),
            not_before: None,
            expires_at: None,
            supersedes_statement_id: None,
            revokes_statement_id: None,
            realm_frontier_digest: None,
            organization_policy_ref: None,
            issuer: org_did(),
            issuer_role: RealmOrganizationIssuerRole::OrganizationDid,
            delegation_ref: None,
            executed_by: None,
        }
    }

    fn live_delegation(reference: &str) -> OrganizationDelegation {
        OrganizationDelegation {
            id: "01J0".to_owned(),
            delegation_ref: reference.to_owned(),
            organization_did: org_did().as_str().to_owned(),
            delegate_did: "did:web:server.acme.example".to_owned(),
            issuer_role: RealmOrganizationIssuerRole::GovernanceService,
            purposes: vec!["principal_control_realm_bootstrap".to_owned()],
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
    fn direct_organization_statement_self_verifies() {
        let payload = issue_organization_statement(
            &keystore(),
            "did:web:coauth.example",
            base_request(),
            now(),
            &offline_resolver(),
        )
        .unwrap();
        assert!(matches!(
            payload.authorization.proof,
            SignatureMaterial::NonEmptyString(ref s) if !s.is_empty()
        ));
        assert!(payload.authorization.verification_method.contains('#'));
    }

    #[test]
    fn delegated_statement_without_ref_is_rejected() {
        let mut request = base_request();
        request.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        let err = issue_organization_statement(
            &keystore(),
            "did:web:coauth.example",
            request,
            now(),
            &offline_resolver(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OrganizationStatementError::MissingDelegationRef
        ));
    }

    #[test]
    fn delegated_statement_with_live_delegation_self_verifies() {
        let reference = "ck:grant:01904100-0000-7000-8000-000000000001";
        let mut request = base_request();
        request.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        request.delegation_ref = Some(reference.to_owned());
        let resolver = RepositoryDelegationResolver::new(Some(live_delegation(reference)), now());
        let payload = issue_organization_statement(
            &keystore(),
            "did:web:coauth.example",
            request,
            now(),
            &resolver,
        )
        .unwrap();
        assert_eq!(
            payload.authorization.issuer_role,
            RealmOrganizationIssuerRole::GovernanceService
        );
    }

    #[test]
    fn delegated_statement_with_expired_delegation_fails_self_verify() {
        let reference = "ck:grant:01904100-0000-7000-8000-000000000002";
        let mut request = base_request();
        request.issuer_role = RealmOrganizationIssuerRole::AccountAuthority;
        request.delegation_ref = Some(reference.to_owned());
        let mut delegation = live_delegation(reference);
        delegation.valid_until = Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
        let resolver = RepositoryDelegationResolver::new(Some(delegation), now());
        let err = issue_organization_statement(
            &keystore(),
            "did:web:coauth.example",
            request,
            now(),
            &resolver,
        )
        .unwrap_err();
        assert!(matches!(err, OrganizationStatementError::SelfVerify(_)));
    }

    #[test]
    fn delegated_statement_with_wrong_org_fails_self_verify() {
        let reference = "ck:grant:01904100-0000-7000-8000-000000000003";
        let mut request = base_request();
        request.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        request.delegation_ref = Some(reference.to_owned());
        let mut delegation = live_delegation(reference);
        delegation.organization_did = "did:web:other.example".to_owned();
        let resolver = RepositoryDelegationResolver::new(Some(delegation), now());
        let err = issue_organization_statement(
            &keystore(),
            "did:web:coauth.example",
            request,
            now(),
            &resolver,
        )
        .unwrap_err();
        assert!(matches!(err, OrganizationStatementError::SelfVerify(_)));
    }
}
