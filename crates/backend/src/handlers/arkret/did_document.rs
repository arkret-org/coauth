//! Wire types for DID documents coauth *consumes* as a resolver client
//! (external `did:web` / `did:plc` / delegated-registry documents).
//!
//! coauth deliberately provides NO DID-document hosting: the former
//! `/.well-known/did.json`, `/did.json`, and `/users/{id}/did.json` routes
//! and their user-document builders were removed. DID hosting is the
//! Station's job (soland's embedded webvh provider); coauth
//! artefacts are verified via introspection + OAuth JWKS instead.
//!
//! NOTE (CAU-DRY-02, rechecked): this is intentionally not the SDK
//! `arkret_models_identity::DidDocument`. The SDK model now preserves unknown
//! properties losslessly, so conversion into accepted identity evidence no
//! longer drops fields. This resolver-bound type still provides operational
//! JOSE access to full JWK/Multikey verification methods and typed service and
//! holder-preference entries. Moving those generic DID/JOSE semantics into the
//! Arkret product model would invert the dependency boundary. The JSON
//! conversion in `services::did_binding` is therefore the explicit handoff,
//! not a second protocol model.

use arkret_identity::test_material::{
    FormalTestMaterialPolicyError, PublicKeyFingerprintInput, enforce_formal_test_material_policy,
};
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

/// Failure returned before resolved key material may become a formal
/// verification or trust-admission basis.
#[derive(Debug, thiserror::Error)]
pub enum FormalKeyAdmissionError {
    #[error("test_signing_material_denied")]
    TestSigningMaterialDenied,
    #[error("formal key admission input is invalid: {0}")]
    Invalid(String),
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

    /// Apply the SDK-owned public-test-material policy to this method.
    ///
    /// The fingerprint is computed from the algorithm-defined bytes, never
    /// from the JWK / multibase serialization. There is deliberately no
    /// configuration or test-mode argument on this formal-path API.
    pub fn enforce_formal_key_admission(
        &self,
        document_did: &str,
        trust_domain: Option<&arkret_wire::TrustDomainId>,
    ) -> Result<(), FormalKeyAdmissionError> {
        let did = arkret_wire::Did::new(document_did.to_owned())
            .map_err(|error| FormalKeyAdmissionError::Invalid(error.to_string()))?;
        let key_id = arkret_wire::DidUrl::new(self.id.clone())
            .map_err(|error| FormalKeyAdmissionError::Invalid(error.to_string()))?;

        let enforce = |key: Option<&PublicKeyFingerprintInput<'_>>| {
            enforce_formal_test_material_policy(key, Some(&did), Some(&key_id), trust_domain)
                .map_err(|error| match error {
                    FormalTestMaterialPolicyError::Denied(_) => {
                        FormalKeyAdmissionError::TestSigningMaterialDenied
                    }
                    FormalTestMaterialPolicyError::InvalidPublicKey(error) => {
                        FormalKeyAdmissionError::Invalid(error.to_string())
                    }
                })
        };

        if let Some(multibase) = self.public_key_multibase.as_ref() {
            let bytes = PublicKeyMaterial::Ed25519Multibase {
                value: multibase.clone(),
            }
            .ed25519_bytes()
            .map_err(|error| FormalKeyAdmissionError::Invalid(error.to_string()))?;
            return enforce(Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&bytes)));
        }

        let Some(jwk) = self.public_key_jwk.as_ref() else {
            return enforce(None);
        };
        let value = serde_json::to_value(jwk)
            .map_err(|error| FormalKeyAdmissionError::Invalid(error.to_string()))?;
        match (
            value.get("kty").and_then(serde_json::Value::as_str),
            value.get("crv").and_then(serde_json::Value::as_str),
        ) {
            (Some("OKP"), Some("Ed25519")) => {
                let bytes = self
                    .public_key_material()
                    .map_err(FormalKeyAdmissionError::Invalid)?
                    .ed25519_bytes()
                    .map_err(|error| FormalKeyAdmissionError::Invalid(error.to_string()))?;
                enforce(Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&bytes)))
            }
            (Some("EC"), Some("P-256")) => {
                let decode = |field: &str| {
                    value
                        .get(field)
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            FormalKeyAdmissionError::Invalid(format!(
                                "P-256 JWK is missing {field}"
                            ))
                        })
                        .and_then(|encoded| {
                            arkret_canonical::base64url::base64url_decode(encoded).map_err(
                                |error| FormalKeyAdmissionError::Invalid(error.to_string()),
                            )
                        })
                };
                let x = decode("x")?;
                let y = decode("y")?;
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                enforce(Some(&PublicKeyFingerprintInput::P256Sec1Uncompressed(
                    &point,
                )))
            }
            _ => enforce(None),
        }
    }
}

/// Reject reserved identifiers and published key material before a resolved
/// document is converted into a cached or durable accepted binding.
pub fn enforce_formal_document_admission(
    document: &DidDocument,
    trust_domain: &arkret_wire::TrustDomainId,
) -> Result<(), FormalKeyAdmissionError> {
    let did = arkret_wire::Did::new(document.id.clone())
        .map_err(|error| FormalKeyAdmissionError::Invalid(error.to_string()))?;
    enforce_formal_test_material_policy(None, Some(&did), None, Some(trust_domain)).map_err(
        |error| match error {
            FormalTestMaterialPolicyError::Denied(_) => {
                FormalKeyAdmissionError::TestSigningMaterialDenied
            }
            FormalTestMaterialPolicyError::InvalidPublicKey(error) => {
                FormalKeyAdmissionError::Invalid(error.to_string())
            }
        },
    )?;
    // Relationship references are themselves DID URLs and therefore part of
    // the formal identifier-admission boundary.  Check them independently of
    // `verificationMethod`: a malformed or incomplete document must not turn
    // a reserved test key id into a generic dangling-reference error later in
    // document conversion.
    for reference in document
        .authentication
        .iter()
        .chain(&document.assertion_method)
    {
        let key_id = arkret_wire::DidUrl::new(reference.clone())
            .map_err(|error| FormalKeyAdmissionError::Invalid(error.to_string()))?;
        enforce_formal_test_material_policy(None, Some(&did), Some(&key_id), Some(trust_domain))
            .map_err(|error| match error {
                FormalTestMaterialPolicyError::Denied(_) => {
                    FormalKeyAdmissionError::TestSigningMaterialDenied
                }
                FormalTestMaterialPolicyError::InvalidPublicKey(error) => {
                    FormalKeyAdmissionError::Invalid(error.to_string())
                }
            })?;
    }
    for method in &document.verification_method {
        method.enforce_formal_key_admission(&document.id, Some(trust_domain))?;
    }
    Ok(())
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::*;

    #[test]
    fn did_webvh_multikey_document_deserializes_and_converts_to_jwk() {
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public_key);
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
        assert_eq!(jwk["x"], arkret_canonical::base64url_encode(public_key));
    }

    #[test]
    fn invalid_ed25519_multikey_does_not_convert_to_jwk() {
        let invalid_public_key = [7u8; 32];
        let did = "did:webvh:ztest:local.host:webvh:alice";
        let method: VerificationMethod = serde_json::from_value(json!({
            "id": format!("{did}#device-1"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": arkret_canonical::ed25519_pubkey_to_did_key_multibase(
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
                "x": arkret_canonical::base64url_encode([7u8; 32]),
            },
            "publicKeyMultibase": arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7u8; 32]),
        }))
        .expect("wire document should parse before use-time validation");

        assert!(method.public_key_material().is_err());
    }

    fn spec_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec")
    }

    fn inventory_document(value: &str) -> DidDocument {
        let (did, key_id) = value
            .split_once('#')
            .map_or((value, format!("{value}#runtime-1")), |(did, _)| {
                (did, value.to_owned())
            });
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[93u8; 32])
            .verifying_key()
            .to_bytes();
        serde_json::from_value(json!({
            "id": did,
            "verificationMethod": [{
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": arkret_canonical::base64url_encode(public_key),
                },
            }],
            "authentication": [key_id],
            "assertionMethod": [key_id],
        }))
        .expect("inventory document should deserialize")
    }

    #[test]
    fn reserved_relationship_reference_is_denied_without_a_declared_method() {
        let did = "did:webvh:QmS1gUenXyfWpb5krKbJbiZ93L1yJ6wJFBrf8zNNste4v9:server.example";
        let reserved = format!("{did}#device-fixture");
        let document: DidDocument = serde_json::from_value(json!({
            "id": did,
            "authentication": [reserved],
        }))
        .expect("document should deserialize before formal admission");
        let trust_domain =
            arkret_wire::TrustDomainId::new("ak:trust_domain:coauth.production".to_owned())
                .expect("trust domain should be valid");

        assert!(matches!(
            enforce_formal_document_admission(&document, &trust_domain),
            Err(FormalKeyAdmissionError::TestSigningMaterialDenied)
        ));
    }

    /// Consume the formal closed inventory through Coauth's production
    /// document-admission API.  This pins the distinction between material
    /// that must be denied and deployment-like / fixture-derived identities
    /// that production profiles must continue to accept.
    #[test]
    fn formal_identity_inventory_roles_match_coauth_document_admission() {
        const ROLES: [&str; 3] = [
            "test_material",
            "deployment_like_example",
            "derived_positive",
        ];
        let root = spec_root();
        let registry: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("spec/v1/artifacts/registry/test-material-registry.json"))
                .expect("formal test-material registry should be readable"),
        )
        .expect("formal test-material registry should parse");
        let rows = registry["identity_examples"]
            .as_array()
            .expect("identity_examples should be an array");
        let trust_domain =
            arkret_wire::TrustDomainId::new("ak:trust_domain:coauth.production".to_owned())
                .expect("trust domain should be valid");
        let mut roles = BTreeMap::<&str, usize>::new();
        let mut values = BTreeSet::new();

        for row in rows {
            let value = row["value"]
                .as_str()
                .expect("inventory value should be a string");
            let role = row["role"]
                .as_str()
                .expect("inventory role should be a string");
            assert!(ROLES.contains(&role), "{value}: unknown role {role}");
            assert!(values.insert(value), "{value}: duplicate inventory value");
            *roles.entry(role).or_default() += 1;

            let document = inventory_document(value);
            // Inventory roles classify each concrete occurrence by its own
            // terminal: bare values exercise document-DID admission, while a
            // DID URL exercises key-id admission independently of the DID it
            // hangs under.  A deployment-like key-id may intentionally be
            // shown beneath a reserved prose DID, so feeding every URL through
            // whole-document admission would test two inventory rows at once.
            let result = if value.contains('#') {
                document.verification_method[0]
                    .enforce_formal_key_admission("did:web:coauth.production", Some(&trust_domain))
            } else {
                enforce_formal_document_admission(&document, &trust_domain)
            };
            if role == "test_material" {
                assert!(
                    matches!(
                        result,
                        Err(FormalKeyAdmissionError::TestSigningMaterialDenied)
                    ),
                    "{value}: registered test material must be denied"
                );
            } else {
                result.unwrap_or_else(|error| {
                    panic!("{value}: {role} must be admitted by production policy: {error}")
                });
            }

            if role == "derived_positive" {
                let reference = row["derivation_ref"]
                    .as_str()
                    .expect("derived_positive should carry derivation_ref");
                let (file, pointer) = reference
                    .split_once('#')
                    .expect("derivation_ref should contain a JSON pointer");
                let fixture: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(root.join(file)).expect("derivation fixture should be readable"),
                )
                .expect("derivation fixture should parse");
                assert_eq!(
                    fixture.pointer(pointer).and_then(serde_json::Value::as_str),
                    Some(value),
                    "{value}: derived identity must equal its formal fixture pointer"
                );
            }
        }

        assert_eq!(rows.len(), 122);
        assert_eq!(roles.get("test_material"), Some(&28));
        assert_eq!(roles.get("deployment_like_example"), Some(&90));
        assert_eq!(roles.get("derived_positive"), Some(&4));
    }
}
