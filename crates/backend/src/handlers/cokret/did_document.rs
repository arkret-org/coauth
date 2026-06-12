//! Wire types for DID documents coauth *consumes* as a resolver client
//! (external `did:web` / `did:plc` / delegated-registry documents).
//!
//! coauth deliberately provides NO DID-document hosting: the former
//! `/.well-known/did.json`, `/did.json`, and `/users/{id}/did.json` routes
//! and their user-document builders were removed. DID hosting is the
//! principal server's job (soland embedded webvh / external starid); coauth
//! artefacts are verified via introspection + OAuth JWKS instead.

use coauth_jose::jwk::PublicJsonWebKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,

    #[serde(rename = "alsoKnownAs")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,

    #[serde(rename = "verificationMethod")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,

    #[serde(rename = "assertionMethod")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidService>,

    /// R3.2 (DID-COAUTH-1) — holder-preference metadata block carrying
    /// `primary_handle` (spec identity-handles.md §3.2.1
    /// `holder_primary_handle_at_as_of`). Always emitted for the current
    /// version of a coauth-controlled document (defaulting to `null`
    /// `primary_handle` until the holder records a preference); omitted
    /// when empty so external `did:web` / `did:plc` documents that lack a
    /// metadata block still round-trip unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<DidDocumentMetadata>,
}

/// R3.2 — DID Document `metadata` block.
///
/// Per identity-handles.md §3.2.1 the only field coauth populates is
/// `primary_handle`: a *holder preference pointer* indicating which of the
/// holder's verified handle claims they'd prefer surfaced as the canonical
/// display handle. It is explicitly **NOT** a handle declaration channel —
/// a verifier MUST still construct the `claim_set_snapshot` from signed
/// `ck.schema.handle_claim.v1` evidence and MUST ignore this field if the
/// pointed-at handle is not backed by such a claim. Default is `null`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DidDocumentMetadata {
    /// Canonical `<localpart>:<domain>` handle the holder prefers as their
    /// primary display handle, or `null` when no preference is recorded.
    #[serde(default)]
    pub primary_handle: Option<String>,
}

impl DidDocumentMetadata {
    /// Build the metadata block for a coauth-controlled DID Document's
    /// *current* version.
    ///
    /// The caller supplies the already-resolved preference because current
    /// DID document handlers read it from the database while pure builders
    /// used in unit tests can still pass `None`.
    #[must_use]
    pub fn current_for_holder(primary_handle: Option<String>) -> Self {
        Self { primary_handle }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: String,

    pub controller: String,

    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicJsonWebKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: String,

    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}
