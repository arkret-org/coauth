// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! IANA JOSE registry CSV parsers.
//!
//! Each struct maps to one IANA CSV file and implements [`EnumEntry`] so
//! the code-generator can turn them into Rust enums.

use serde::Deserialize;

use crate::{
    EnumEntry,
    traits::{Section, s},
};

// ── Shared helpers ───────────────────────────────────────────────────

/// Algorithm usage column values.
#[derive(Debug, Deserialize, PartialEq, Eq)]
enum AlgUsage {
    #[serde(rename = "alg")]
    Alg,
    #[serde(rename = "enc")]
    Enc,
    #[serde(rename = "JWK")]
    Jwk,
}

/// JOSE implementation-requirement levels (RFC 7518 §3).
#[derive(Debug, Deserialize)]
enum ImplRequirement {
    Required,
    #[serde(rename = "Recommended+")]
    RecommendedPlus,
    Recommended,
    #[serde(rename = "Recommended-")]
    RecommendedMinus,
    Optional,
    Prohibited,
    Deprecated,
}

// ── JWA: signature / encryption algorithms ───────────────────────────

/// Row from the IANA "JSON Web Signature and Encryption Algorithms"
/// registry.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebEncryptionSignatureAlgorithm {
    #[serde(rename = "Algorithm Name")]
    name: String,
    #[serde(rename = "Algorithm Description")]
    description: String,
    #[serde(rename = "Algorithm Usage Location(s)")]
    usage: AlgUsage,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: ImplRequirement,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
    #[serde(rename = "Algorithm Analysis Document(s)")]
    analysis: String,
}

impl EnumEntry for WebEncryptionSignatureAlgorithm {
    const URL: &'static str =
        "http://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv";

    const SECTIONS: &'static [Section] = &[
        s("JsonWebSignatureAlg", r#"JSON Web Signature "alg" parameter"#),
        s("JsonWebEncryptionAlg", r#"JSON Web Encryption "alg" parameter"#),
        s("JsonWebEncryptionEnc", r#"JSON Web Encryption "enc" parameter"#),
    ];

    fn key(&self) -> Option<&'static str> {
        match self.usage {
            AlgUsage::Enc => Some("JsonWebEncryptionEnc"),
            AlgUsage::Jwk => None,
            AlgUsage::Alg => self.classify_alg_by_reference(),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

impl WebEncryptionSignatureAlgorithm {
    /// Distinguish JWS vs JWE `alg` entries by looking at the Reference
    /// column.
    fn classify_alg_by_reference(&self) -> Option<&'static str> {
        let r = &self.reference;

        // Signature algorithms: RFC 7518 §3, RFC 8037 (EdDSA),
        // RFC 8812 (secp256k1), and Fully-Specified Algorithms §2.
        let is_signature = r.contains("RFC7518, Section 3")
            || r.contains("RFC8037")
            || r.contains("RFC8812")
            || (r.contains("RFC-ietf-jose-fully-specified-algorithms") && r.contains("Section 2"));

        if is_signature {
            return Some("JsonWebSignatureAlg");
        }

        // Encryption algorithms: RFC 7518 §4, WebCryptoAPI,
        // and Fully-Specified Algorithms §3.
        let is_encryption = r.contains("RFC7518, Section 4")
            || r.contains("WebCryptoAPI")
            || (r.contains("RFC-ietf-jose-fully-specified-algorithms") && r.contains("Section 3"));

        if is_encryption {
            return Some("JsonWebEncryptionAlg");
        }

        tracing::warn!(reference = %r, "unable to classify JWA algorithm");
        None
    }
}

// ── JWE compression ──────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebEncryptionCompressionAlgorithm {
    #[serde(rename = "Compression Algorithm Value")]
    value: String,
    #[serde(rename = "Compression Algorithm Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebEncryptionCompressionAlgorithm {
    const URL: &'static str =
        "http://www.iana.org/assignments/jose/web-encryption-compression-algorithms.csv";

    const SECTIONS: &'static [Section] = &[s(
        "JsonWebEncryptionCompressionAlgorithm",
        "JSON Web Encryption Compression Algorithm",
    )];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebEncryptionCompressionAlgorithm")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

// ── JWK key types ────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyType {
    #[serde(rename = "\"kty\" Parameter Value")]
    value: String,
    #[serde(rename = "Key Type Description")]
    description: String,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: ImplRequirement,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyType {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-types.csv";
    const SECTIONS: &'static [Section] = &[s("JsonWebKeyType", "JSON Web Key Type")];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyType")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

// ── JWK elliptic curves ──────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyEllipticCurve {
    #[serde(rename = "Curve Name")]
    name: String,
    #[serde(rename = "Curve Description")]
    description: String,
    #[serde(rename = "JOSE Implementation Requirements")]
    requirements: ImplRequirement,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyEllipticCurve {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-elliptic-curve.csv";

    const SECTIONS: &'static [Section] = &[
        s("JsonWebKeyEcEllipticCurve", "JSON Web Key EC Elliptic Curve"),
        s("JsonWebKeyOkpEllipticCurve", "JSON Web Key OKP Elliptic Curve"),
    ];

    fn key(&self) -> Option<&'static str> {
        // P-256, P-384, P-521, secp256k1 are NIST / Weierstrass curves (kty = EC).
        // Everything else (Ed25519, Ed448, X25519, X448) goes to OKP.
        if self.name.starts_with("P-") || self.name == "secp256k1" {
            Some("JsonWebKeyEcEllipticCurve")
        } else {
            Some("JsonWebKeyOkpEllipticCurve")
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

// ── JWK use ──────────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyUse {
    #[serde(rename = "Use Member Value")]
    value: String,
    #[serde(rename = "Use Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyUse {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-use.csv";
    const SECTIONS: &'static [Section] = &[s("JsonWebKeyUse", "JSON Web Key Use")];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyUse")
    }

    fn name(&self) -> &str {
        &self.value
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}

// ── JWK operations ───────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct WebKeyOperation {
    #[serde(rename = "Key Operation Value")]
    name: String,
    #[serde(rename = "Key Operation Description")]
    description: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for WebKeyOperation {
    const URL: &'static str = "http://www.iana.org/assignments/jose/web-key-operations.csv";
    const SECTIONS: &'static [Section] = &[s("JsonWebKeyOperation", "JSON Web Key Operation")];

    fn key(&self) -> Option<&'static str> {
        Some("JsonWebKeyOperation")
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.description)
    }
}
