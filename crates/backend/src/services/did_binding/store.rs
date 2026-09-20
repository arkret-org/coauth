// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Durable, PostgreSQL-backed [`VerifiedDidBindingStore`]
//! (`did-usage-and-verification.md` §5).
//!
//! # A synchronous trait over an asynchronous repository
//!
//! The SDK's [`VerifiedDidBindingStore`] is **synchronous**; every coauth
//! repository is `async` and needs a `&mut BoxRepository`. That is the same
//! mismatch [`super::resolve_and_accept_binding`] already has with the SDK's
//! synchronous `DidResolver`, and it is resolved the same way: the durable
//! operations are inherent **`async` twins** of the trait methods, and the
//! synchronous trait itself is served by a bounded in-process **mirror**.
//!
//! | trait method (sync, mirror) | durable twin (async, PostgreSQL) |
//! | --- | --- |
//! | [`VerifiedDidBindingStore::get`] | [`DurableVerifiedDidBindingStore::load`] |
//! | [`VerifiedDidBindingStore::accept`] | [`DurableVerifiedDidBindingStore::persist`] |
//! | [`VerifiedDidBindingStore::invalidate`] | [`DurableVerifiedDidBindingStore::invalidate_durable`] |
//!
//! **The mirror is never authoritative.** `load` does not consult it — it
//! always reads the row — and then makes the mirror agree with what the
//! database just said (writing the decoded acceptance on a hit, dropping the
//! mirrored entry on a miss). So a synchronous `get` performed after a `load`
//! in the same request observes exactly the durable state, and a second coauth
//! instance's invalidation is visible to this one on its next `load` rather
//! than only after `expires_at`. A database round trip per authority lookup is
//! not a DID resolution: the property `did-usage-and-verification.md` §4 is
//! about — zero incremental *resolver* calls — is unaffected.
//!
//! # Rows are re-validated, never trusted
//!
//! A row is decoded through [`AcceptedDidBinding`]'s `Deserialize`, which
//! routes through `AcceptedDidBinding::new` and therefore recomputes the pinned
//! document's canonical digest, re-checks `document.id == binding.did` and
//! re-digests the retained evidence receipt. On top of that, [`decode_row`]
//! requires the row's five key columns to equal the decoded binding's own key,
//! so a row cannot be *moved* to another purpose, trust domain or policy digest
//! by editing the columns either.
//!
//! A row that fails any of these checks is **discarded**, not surfaced: the
//! acceptance simply does not exist, so an authority path resolves again and an
//! ordinary read returns not-found. Both are fail-safe. What the digest cannot
//! protect is the binding's own metadata inside the payload (`status`,
//! `expires_at`): write access to this table is a trust boundary, exactly as it
//! is for every other credential table in this schema.

use arkret_identity::{
    AcceptedDidBinding, BindingInvalidation, InMemoryVerifiedDidBindingStore,
    VerifiedDidBindingKey, VerifiedDidBindingStore,
};
use chrono::{DateTime, Utc};
use coauth_data::BoxRepository;
use coauth_data::RepositoryError;
use coauth_data::did_binding::{
    VerifiedDidBindingInvalidation, VerifiedDidBindingKeyColumns, VerifiedDidBindingRepository,
    VerifiedDidBindingRow,
};

use super::DidBindingError;

/// Column projection of an SDK store key.
#[must_use]
pub fn key_columns(key: &VerifiedDidBindingKey) -> VerifiedDidBindingKeyColumns {
    VerifiedDidBindingKeyColumns {
        did: key.did.as_str().to_owned(),
        trust_domain: key.trust_domain.as_str().to_owned(),
        purpose: key.purpose.as_str().to_owned(),
        policy_digest: key.policy_digest.as_str().to_owned(),
        verification_method: key
            .verification_method
            .as_ref()
            .map(|method| method.as_str().to_owned()),
    }
}

/// Column projection of an SDK invalidation selector.
///
/// The conjunctive semantics are preserved verbatim, including "an empty
/// selector matches nothing".
#[must_use]
pub fn invalidation_columns(selector: &BindingInvalidation) -> VerifiedDidBindingInvalidation {
    VerifiedDidBindingInvalidation {
        did: selector.did.as_ref().map(|did| did.as_str().to_owned()),
        verification_method: selector
            .verification_method
            .as_ref()
            .map(|method| method.as_str().to_owned()),
        history_head: selector.history_head.clone(),
        trust_domain: selector
            .trust_domain
            .as_ref()
            .map(|domain| domain.as_str().to_owned()),
        purpose: selector.purpose.map(|purpose| purpose.as_str().to_owned()),
        policy_digest: selector
            .policy_digest
            .as_ref()
            .map(|digest| digest.as_str().to_owned()),
    }
}

/// Encode an acceptance into its durable row.
///
/// # Errors
///
/// Returns [`DidBindingError::Store`] when the acceptance cannot be serialized.
pub fn encode_row(accepted: &AcceptedDidBinding) -> Result<VerifiedDidBindingRow, DidBindingError> {
    let binding = accepted.binding();
    Ok(VerifiedDidBindingRow {
        key: key_columns(&binding.key()),
        history_head: binding.history_head().map(ToOwned::to_owned),
        expires_at: binding.expires_at(),
        accepted: serde_json::to_value(accepted)
            .map_err(|error| DidBindingError::Store(error.to_string()))?,
    })
}

/// Decode a durable row back into an acceptance, or discard it.
///
/// Returns `None` — never a partially trusted value — when
///
/// 1. the payload does not deserialize (`AcceptedDidBinding`'s `Deserialize` recomputes the pinned
///    document's canonical digest and re-checks `document.id`, so an edited document lands here);
/// 2. the decoded binding's own key is not the key the row was filed under (an edited key column
///    trying to relocate an acceptance); or
/// 3. the requested key is not that key either.
///
/// The discard is logged at `warn` because a failure here is either a schema
/// migration artefact or tampering — both worth seeing — but it is never
/// escalated into a request error: a missing acceptance already has a defined,
/// fail-safe meaning everywhere it is consumed.
#[must_use]
pub fn decode_row(
    requested: &VerifiedDidBindingKey,
    row: VerifiedDidBindingRow,
) -> Option<AcceptedDidBinding> {
    let filed_under = row.key;
    let accepted = match serde_json::from_value::<AcceptedDidBinding>(row.accepted) {
        Ok(accepted) => accepted,
        Err(error) => {
            tracing::warn!(
                did = %filed_under.did,
                purpose = %filed_under.purpose,
                %error,
                "discarding a stored DID binding whose pinned document failed re-validation"
            );
            return None;
        }
    };
    let decoded_key = accepted.binding().key();
    if key_columns(&decoded_key) != filed_under {
        tracing::warn!(
            did = %filed_under.did,
            purpose = %filed_under.purpose,
            "discarding a stored DID binding whose key columns disagree with its payload"
        );
        return None;
    }
    if &decoded_key != requested {
        tracing::warn!(
            did = %filed_under.did,
            purpose = %filed_under.purpose,
            "discarding a stored DID binding that does not answer the requested key"
        );
        return None;
    }
    Some(accepted)
}

/// PostgreSQL-backed accepted-binding store. See the module documentation for
/// the synchronous-trait / asynchronous-repository split.
#[derive(Debug)]
pub struct DurableVerifiedDidBindingStore {
    mirror: InMemoryVerifiedDidBindingStore,
}

impl DurableVerifiedDidBindingStore {
    /// Create a store whose in-process mirror holds at most `capacity`
    /// entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            mirror: InMemoryVerifiedDidBindingStore::new(capacity),
        }
    }

    /// The in-process mirror. Exposed for tests and for the synchronous trait
    /// methods; production code should use the durable twins.
    #[must_use]
    pub fn mirror(&self) -> &InMemoryVerifiedDidBindingStore {
        &self.mirror
    }

    /// Durable twin of [`VerifiedDidBindingStore::get`].
    ///
    /// Reads the row (hard expiry enforced in the query), re-validates it, and
    /// leaves the mirror agreeing with the database for this key.
    ///
    /// # Errors
    ///
    /// Returns [`DidBindingError::Store`] when the repository fails. A row that
    /// fails re-validation is **not** an error — it is a miss.
    pub async fn load(
        &self,
        repo: &mut BoxRepository,
        key: &VerifiedDidBindingKey,
        now: DateTime<Utc>,
    ) -> Result<Option<AcceptedDidBinding>, DidBindingError> {
        let mut repository = repo.verified_did_binding();
        self.load_from_repository(repository.as_mut(), key, now)
            .await
    }

    /// Load through the durable repository port.
    ///
    /// This is the production implementation behind [`Self::load`], exposed
    /// so cross-repository conformance tests can execute the same get → current
    /// admission → exact purge contract without requiring a live PostgreSQL
    /// server. A row rejected by today's formal policy is deleted exactly,
    /// removed from the mirror, and returned as a terminal error; it is never
    /// converted into a miss that could fall through to a weaker resolver.
    pub async fn load_from_repository(
        &self,
        repository: &mut dyn VerifiedDidBindingRepository<Error = RepositoryError>,
        key: &VerifiedDidBindingKey,
        now: DateTime<Utc>,
    ) -> Result<Option<AcceptedDidBinding>, DidBindingError> {
        let row = repository
            .get(&key_columns(key), now)
            .await
            .map_err(|error| DidBindingError::Store(error.to_string()))?;
        let accepted = row.and_then(|row| decode_row(key, row));
        match &accepted {
            Some(accepted) => {
                if let Err(error) = super::enforce_formal_accepted_binding_admission(accepted) {
                    self.forget_mirrored(key);
                    repository
                        .delete_exact(&key_columns(key))
                        .await
                        .map_err(|error| DidBindingError::Store(error.to_string()))?;
                    return Err(error);
                }
                // Overwrites any mirrored entry under the same key.
                self.mirror
                    .accept(accepted.clone())
                    .map_err(|error| DidBindingError::Store(error.to_string()))?;
            }
            None => self.forget_mirrored(key),
        }
        Ok(accepted)
    }

    /// Durable twin of [`VerifiedDidBindingStore::accept`].
    ///
    /// # Errors
    ///
    /// Returns [`DidBindingError::Store`] when the acceptance cannot be
    /// serialized or the repository fails.
    pub async fn persist(
        &self,
        repo: &mut BoxRepository,
        accepted: &AcceptedDidBinding,
        now: DateTime<Utc>,
    ) -> Result<(), DidBindingError> {
        let row = encode_row(accepted)?;
        repo.verified_did_binding()
            .upsert(row, now)
            .await
            .map_err(|error| DidBindingError::Store(error.to_string()))?;
        self.mirror
            .accept(accepted.clone())
            .map_err(|error| DidBindingError::Store(error.to_string()))
    }

    /// Durable twin of [`VerifiedDidBindingStore::invalidate`]: removes the
    /// matching rows **and** the matching mirrored entries. Returns the number
    /// of rows removed.
    ///
    /// # Errors
    ///
    /// Returns [`DidBindingError::Store`] when the repository fails.
    pub async fn invalidate_durable(
        &self,
        repo: &mut BoxRepository,
        selector: &BindingInvalidation,
    ) -> Result<usize, DidBindingError> {
        self.mirror.invalidate(selector);
        repo.verified_did_binding()
            .invalidate(&invalidation_columns(selector))
            .await
            .map_err(|error| DidBindingError::Store(error.to_string()))
    }

    /// Drop every mirrored entry that could answer `key`.
    ///
    /// [`BindingInvalidation`] cannot express "this exact key" — a `None`
    /// verification method there means *unconstrained* rather than *absent*.
    /// The selector below is therefore
    /// deliberately **wider** than the key: it clears every mirrored purpose-
    /// and policy-matched entry for the DID in this trust domain. Over-clearing
    /// the mirror is free (the next `load` re-reads the row); under-clearing it
    /// would leave a stale acceptance readable through the synchronous face.
    fn forget_mirrored(&self, key: &VerifiedDidBindingKey) {
        self.mirror.invalidate(
            &BindingInvalidation::for_did(key.did.clone())
                .with_trust_domain(key.trust_domain.clone())
                .with_purpose(key.purpose)
                .with_policy_digest(key.policy_digest.clone()),
        );
    }
}

impl Default for DurableVerifiedDidBindingStore {
    fn default() -> Self {
        Self::new(super::BINDING_STORE_CAPACITY)
    }
}

/// Synchronous face of the store: the in-process mirror.
///
/// Every method here is mirror-only by construction — the trait has nowhere to
/// put a `&mut BoxRepository`. Callers that must reach the database use the
/// `async` twins above.
impl VerifiedDidBindingStore for DurableVerifiedDidBindingStore {
    fn get_with_freshness(
        &self,
        key: &VerifiedDidBindingKey,
        now: DateTime<Utc>,
    ) -> (
        Option<AcceptedDidBinding>,
        arkret_identity::BindingFreshness,
    ) {
        self.mirror.get_with_freshness(key, now)
    }

    fn accept(
        &self,
        accepted: AcceptedDidBinding,
    ) -> Result<(), arkret_identity::BindingStoreError> {
        self.mirror.accept(accepted)
    }

    fn invalidate(&self, selector: &BindingInvalidation) -> usize {
        self.mirror.invalidate(selector)
    }

    fn snapshot(&self) -> Vec<AcceptedDidBinding> {
        self.mirror.snapshot()
    }
}
