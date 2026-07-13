//! Wire types for DID documents coauth *consumes* as a resolver client
//! (external `did:web` / `did:plc` / delegated-registry documents).
//!
//! coauth deliberately provides NO DID-document hosting: the former
//! `/.well-known/did.json`, `/did.json`, and `/users/{id}/did.json` routes
//! and their user-document builders were removed. DID hosting is the
//! principal server's job (soland embedded webvh / external starid); coauth
//! artefacts are verified via introspection + OAuth JWKS instead.
//!
//! NOTE (CAU-DRY-02, kept by ruling): this is intentionally NOT the SDK
//! `arkret_core::identity::DidDocument`. The SDK type is a simplified product
//! contract (verification methods collapsed to a map); this one is the
//! full-document wire shape consumed from external resolvers (JWK and Multikey
//! verification methods, `service` entries, holder-preference metadata).
//! Reach for the SDK type for product contracts — do not grow this one into
//! a second general-purpose DID model.

use arkret_signatures::proof::PublicKeyMaterial;
use coauth_jose::jwk::{JsonWebKeyPublicParameters, PublicJsonWebKey};
use ed25519_dalek::VerifyingKey;
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
/// `ak.schema.handle_claim.v1` evidence and MUST ignore this field if the
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<PublicJsonWebKey>,

    #[serde(rename = "publicKeyMultibase")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

impl VerificationMethod {
    pub fn public_key_material(&self) -> Result<PublicKeyMaterial, String> {
        match (&self.public_key_jwk, &self.public_key_multibase) {
            (Some(jwk), None) => {
                let value = serde_json::to_value(jwk)
                    .map_err(|error| format!("publicKeyJwk is invalid: {error}"))?;
                Ok(PublicKeyMaterial::Jwk { value })
            }
            (None, Some(value)) => Ok(PublicKeyMaterial::Ed25519Multibase {
                value: value.clone(),
            }),
            (Some(_), Some(_)) => Err(
                "verification method must not contain both publicKeyJwk and publicKeyMultibase"
                    .to_owned(),
            ),
            (None, None) => Err(
                "verification method must contain publicKeyJwk or publicKeyMultibase".to_owned(),
            ),
        }
    }

    pub fn public_jwk(&self) -> Result<PublicJsonWebKey, String> {
        if let Some(jwk) = self.public_key_jwk.as_ref() {
            return Ok(jwk.clone());
        }
        let bytes = self
            .public_key_material()?
            .ed25519_bytes()
            .map_err(|error| format!("publicKeyMultibase is invalid: {error}"))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|error| format!("publicKeyMultibase is invalid: {error}"))?;
        Ok(PublicJsonWebKey::new(JsonWebKeyPublicParameters::from(
            &verifying_key,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: String,

    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn did_webvh_multikey_document_deserializes_and_converts_to_jwk() {
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let multibase = arkret_core::ed25519_pubkey_to_did_key_multibase(&public_key);
        let did = "did:webvh:ztest:local.host:webvh:alice";
        let document: DidDocument = serde_json::from_value(json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#device-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase,
            }],
            "authentication": [format!("{did}#device-1")],
            "assertionMethod": [format!("{did}#device-1")],
        }))
        .expect("soland did:webvh Multikey document should deserialize");

        let method = &document.verification_method[0];
        assert_eq!(
            method
                .public_key_material()
                .expect("Multikey material should be supported")
                .ed25519_bytes()
                .expect("Multikey should decode"),
            public_key
        );
        let jwk = serde_json::to_value(
            method
                .public_jwk()
                .expect("Multikey should convert to Ed25519 JWK"),
        )
        .expect("JWK should serialize");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["x"], arkret_core::base64url_encode(public_key));
    }

    #[test]
    fn invalid_ed25519_multikey_does_not_convert_to_jwk() {
        let invalid_public_key = [7u8; 32];
        let did = "did:webvh:ztest:local.host:webvh:alice";
        let method: VerificationMethod = serde_json::from_value(json!({
            "id": format!("{did}#device-1"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": arkret_core::ed25519_pubkey_to_did_key_multibase(
                &invalid_public_key
            ),
        }))
        .expect("wire document should parse before key validation");

        assert!(method.public_jwk().is_err());
    }

    #[test]
    fn verification_method_rejects_ambiguous_key_material() {
        let method: VerificationMethod = serde_json::from_value(json!({
            "id": "did:web:example.test#key-1",
            "type": "Multikey",
            "controller": "did:web:example.test",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": arkret_core::base64url_encode([7u8; 32]),
            },
            "publicKeyMultibase": arkret_core::ed25519_pubkey_to_did_key_multibase(&[7u8; 32]),
        }))
        .expect("wire document should parse before use-time validation");

        assert!(method.public_key_material().is_err());
    }
}
