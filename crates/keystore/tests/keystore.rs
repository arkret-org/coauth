// Integration tests for the coauth-keystore crate.
//
// Covers: loading keys from various PEM/DER formats (plain and encrypted),
// round-trip serialisation, key generation, JWT signing + verification via
// the Keystore / JWKS API, and thumbprint consistency.

use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::jwk::{ParametersInfo, Thumbprint};
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::{
    DEVICE_ENROLLMENT_KEY_ID, DeviceEnrollmentKeyError, JsonWebKey, JsonWebKeySet, Keystore,
    PrivateKey, SERVICE_IDENTITY_KEY_ID, ServiceIdentityKeyError,
};
use der::pem::LineEnding;
use rand_core::SeedableRng;

/// Shared password used for encrypted-key tests.
static TEST_PASSPHRASE: &str = "hunter2";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sign and verify a JWT for every algorithm the key supports.
fn sign_verify_all_algs(private: &PrivateKey) {
    let supported = private.possible_algs();
    assert!(
        !supported.is_empty(),
        "key should support at least one algorithm"
    );

    for alg in supported {
        let hdr = JsonWebSignatureHeader::new(alg.clone());
        let signing = private.signing_key_for_alg(alg).unwrap();
        let token = Jwt::sign(hdr, "hello", &signing).unwrap();
        let verifying = private.verifying_key_for_alg(alg).unwrap();
        token.verify(&verifying).unwrap();
    }
}

/// Macro that generates a sign/verify test from an unencrypted key fixture.
/// Delegates to the shared helper above.
macro_rules! plain_key_test {
    ($test_name:ident, $variant:ident, $fixture:literal) => {
        #[test]
        fn $test_name() {
            let data = include_bytes!(concat!("./keys/", $fixture));
            let pk = PrivateKey::load(data).unwrap();
            assert!(
                matches!(pk, PrivateKey::$variant(_)),
                "unexpected key variant"
            );
            sign_verify_all_algs(&pk);
        }
    };
}

/// Macro for encrypted-key tests.
macro_rules! encrypted_key_test {
    ($test_name:ident, $variant:ident, $fixture:literal) => {
        #[test]
        fn $test_name() {
            let data = include_bytes!(concat!("./keys/", $fixture));
            let pk = PrivateKey::load_encrypted(data, TEST_PASSPHRASE).unwrap();
            assert!(
                matches!(pk, PrivateKey::$variant(_)),
                "unexpected key variant"
            );
            sign_verify_all_algs(&pk);
        }
    };
}

/// PEM round-trip test: load PEM, re-encode, compare.
macro_rules! pem_roundtrip {
    ($test_name:ident, $fixture:literal) => {
        #[test]
        fn $test_name() {
            let original = include_str!(concat!("./keys/", $fixture, ".pem"));
            let pk = PrivateKey::load_pem(original).unwrap();
            let re_encoded = pk.to_pem(pem_rfc7468::LineEnding::LF).unwrap();
            assert_eq!(original.replace("\r\n", "\n"), re_encoded.as_str());
        }
    };
}

/// DER round-trip test: load DER, re-encode, compare.
macro_rules! der_roundtrip {
    ($test_name:ident, $fixture:literal) => {
        #[test]
        fn $test_name() {
            let original = include_bytes!(concat!("./keys/", $fixture, ".der"));
            let pk = PrivateKey::load_der(original).unwrap();
            let re_encoded = pk.to_der().unwrap();
            assert_eq!(original, re_encoded.as_slice());
        }
    };
}

// ---------------------------------------------------------------------------
// Plaintext key loading + sign/verify
// ---------------------------------------------------------------------------

plain_key_test!(plain_rsa_pkcs1_pem, Rsa, "rsa.pkcs1.pem");
plain_key_test!(plain_rsa_pkcs1_der, Rsa, "rsa.pkcs1.der");
plain_key_test!(plain_rsa_pkcs8_pem, Rsa, "rsa.pkcs8.pem");
plain_key_test!(plain_rsa_pkcs8_der, Rsa, "rsa.pkcs8.der");
plain_key_test!(plain_ec_p256_sec1_pem, EcP256, "ec-p256.sec1.pem");
plain_key_test!(plain_ec_p256_sec1_der, EcP256, "ec-p256.sec1.der");
plain_key_test!(plain_ec_p256_pkcs8_pem, EcP256, "ec-p256.pkcs8.pem");
plain_key_test!(plain_ec_p256_pkcs8_der, EcP256, "ec-p256.pkcs8.der");
plain_key_test!(plain_ec_p384_sec1_pem, EcP384, "ec-p384.sec1.pem");
plain_key_test!(plain_ec_p384_sec1_der, EcP384, "ec-p384.sec1.der");
plain_key_test!(plain_ec_p384_pkcs8_pem, EcP384, "ec-p384.pkcs8.pem");
plain_key_test!(plain_ec_p384_pkcs8_der, EcP384, "ec-p384.pkcs8.der");
plain_key_test!(plain_ec_k256_sec1_pem, EcK256, "ec-k256.sec1.pem");
plain_key_test!(plain_ec_k256_sec1_der, EcK256, "ec-k256.sec1.der");
plain_key_test!(plain_ec_k256_pkcs8_pem, EcK256, "ec-k256.pkcs8.pem");
plain_key_test!(plain_ec_k256_pkcs8_der, EcK256, "ec-k256.pkcs8.der");

// ---------------------------------------------------------------------------
// Encrypted key loading + sign/verify
// ---------------------------------------------------------------------------

encrypted_key_test!(enc_rsa_pkcs8_pem, Rsa, "rsa.pkcs8.encrypted.pem");
encrypted_key_test!(enc_rsa_pkcs8_der, Rsa, "rsa.pkcs8.encrypted.der");
encrypted_key_test!(enc_ec_p256_pkcs8_pem, EcP256, "ec-p256.pkcs8.encrypted.pem");
encrypted_key_test!(enc_ec_p256_pkcs8_der, EcP256, "ec-p256.pkcs8.encrypted.der");
encrypted_key_test!(enc_ec_p384_pkcs8_pem, EcP384, "ec-p384.pkcs8.encrypted.pem");
encrypted_key_test!(enc_ec_p384_pkcs8_der, EcP384, "ec-p384.pkcs8.encrypted.der");
encrypted_key_test!(enc_ec_k256_pkcs8_pem, EcK256, "ec-k256.pkcs8.encrypted.pem");
encrypted_key_test!(enc_ec_k256_pkcs8_der, EcK256, "ec-k256.pkcs8.encrypted.der");

// ---------------------------------------------------------------------------
// PEM / DER round-trip serialisation
// ---------------------------------------------------------------------------

pem_roundtrip!(serialize_rsa_pkcs1_pem, "rsa.pkcs1");
der_roundtrip!(serialize_rsa_pkcs1_der, "rsa.pkcs1");
pem_roundtrip!(serialize_ec_p256_sec1_pem, "ec-p256.sec1");
der_roundtrip!(serialize_ec_p256_sec1_der, "ec-p256.sec1");
pem_roundtrip!(serialize_ec_p384_sec1_pem, "ec-p384.sec1");
der_roundtrip!(serialize_ec_p384_sec1_der, "ec-p384.sec1");
pem_roundtrip!(serialize_ec_k256_sec1_pem, "ec-k256.sec1");
der_roundtrip!(serialize_ec_k256_sec1_der, "ec-k256.sec1");

// ---------------------------------------------------------------------------
// Key generation round-trips (P-521, Ed25519)
// ---------------------------------------------------------------------------

/// Helper: generate a key, serialise it to PEM / DER / PKCS8-DER, reload each
/// form, and sign-verify with every supported algorithm.
fn roundtrip_generated_key(key: &PrivateKey, expected_variant: &str) {
    // PEM round-trip
    let pem_str = key.to_pem(pem_rfc7468::LineEnding::LF).unwrap();
    let from_pem = PrivateKey::load_pem(&pem_str).unwrap();
    let dbg_pem = format!("{from_pem:?}");
    assert!(dbg_pem.starts_with(expected_variant), "PEM: {dbg_pem}");
    sign_verify_all_algs(&from_pem);

    // DER round-trip
    let der_bytes = key.to_der().unwrap();
    let from_der = PrivateKey::load_der(&der_bytes).unwrap();
    let dbg_der = format!("{from_der:?}");
    assert!(dbg_der.starts_with(expected_variant), "DER: {dbg_der}");
    sign_verify_all_algs(&from_der);

    // PKCS#8 DER round-trip
    let pkcs8_bytes = key.to_pkcs8_der().unwrap();
    let from_pkcs8 = PrivateKey::load_der(&pkcs8_bytes).unwrap();
    let dbg_p8 = format!("{from_pkcs8:?}");
    assert!(dbg_p8.starts_with(expected_variant), "PKCS8: {dbg_p8}");
    sign_verify_all_algs(&from_pkcs8);
}

#[test]
fn generated_ec_p521_roundtrip_sign_and_verify() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
    let p521 = PrivateKey::generate_ec_p521(&mut rng);
    roundtrip_generated_key(&p521, "EcP521");
}

#[test]
fn generated_ed25519_roundtrip_sign_and_verify() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(8);
    let ed = PrivateKey::generate_ed25519(&mut rng);
    roundtrip_generated_key(&ed, "OkpEd25519");
}

// ---------------------------------------------------------------------------
// Error cases: encrypted / unencrypted mismatch
// ---------------------------------------------------------------------------

#[test]
fn load_encrypted_as_unencrypted_error() {
    let pem_content = include_str!("./keys/rsa.pkcs8.encrypted.pem");
    assert!(
        PrivateKey::load_pem(pem_content)
            .unwrap_err()
            .is_encrypted()
    );

    let der_content = include_bytes!("./keys/rsa.pkcs8.encrypted.der");
    assert!(
        PrivateKey::load_der(der_content)
            .unwrap_err()
            .is_encrypted()
    );
}

#[test]
fn load_unencrypted_as_encrypted_error() {
    let pem_content = include_str!("./keys/rsa.pkcs8.pem");
    assert!(
        PrivateKey::load_encrypted_pem(pem_content, TEST_PASSPHRASE)
            .unwrap_err()
            .is_unencrypted()
    );

    let der_content = include_bytes!("./keys/rsa.pkcs8.der");
    assert!(
        PrivateKey::load_encrypted_der(der_content, TEST_PASSPHRASE)
            .unwrap_err()
            .is_unencrypted()
    );
}

// ---------------------------------------------------------------------------
// Full keystore: generate several key types, build a Keystore + JWKS, and
// sign/verify for every standard algorithm.
// ---------------------------------------------------------------------------

#[allow(clippy::similar_names)]
#[test]
fn generate_sign_and_verify() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

    // Generate one key of each flavour.
    let rsa_key = PrivateKey::generate_rsa(&mut rng).expect("RSA generation failed");
    insta::assert_snapshot!(&*rsa_key.to_pem(LineEnding::LF).unwrap());

    let p256_key = PrivateKey::generate_ec_p256(&mut rng);
    insta::assert_snapshot!(&*p256_key.to_pem(LineEnding::LF).unwrap());

    let p384_key = PrivateKey::generate_ec_p384(&mut rng);
    insta::assert_snapshot!(&*p384_key.to_pem(LineEnding::LF).unwrap());

    let k256_key = PrivateKey::generate_ec_k256(&mut rng);
    insta::assert_snapshot!(&*k256_key.to_pem(LineEnding::LF).unwrap());

    // Use a separate seed so that earlier key-gen changes don't cascade.
    let mut aux_rng = rand_chacha::ChaCha8Rng::seed_from_u64(1337);
    let p521_key = PrivateKey::generate_ec_p521(&mut aux_rng);
    let ed_key = PrivateKey::generate_ed25519(&mut aux_rng);

    // Assemble a Keystore from all six keys.
    let store = Keystore::new(JsonWebKeySet::new(vec![
        JsonWebKey::new(rsa_key),
        JsonWebKey::new(p256_key),
        JsonWebKey::new(p384_key),
        JsonWebKey::new(p521_key),
        JsonWebKey::new(k256_key),
        JsonWebKey::new(ed_key),
    ]));

    let public_jwks = store.public_jwks();
    insta::assert_yaml_snapshot!(public_jwks);

    // Sign a token for every supported algorithm and verify against the
    // public JWKS.
    let all_algs = [
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Ps256,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256K,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Ed25519,
    ];

    for alg in all_algs {
        let matched = store.signing_key_for_algorithm(&alg).unwrap();
        let signer = matched.params().signing_key_for_alg(&alg).unwrap();
        let hdr = JsonWebSignatureHeader::new(alg.clone());
        let token = Jwt::sign_with_rng(&mut rng, hdr, "", &signer).unwrap();
        insta::assert_snapshot!(format!("jwt_{alg}"), token.as_str());

        // Verify from the public side only.
        token.verify_with_jwks(&public_jwks).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Thumbprint consistency: private key thumbprint must match the public JWKS
// ---------------------------------------------------------------------------

#[test]
fn generated_private_key_thumbprints_match_public_jwks() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2026);

    // Check each generated key type individually.
    for private_key in [
        PrivateKey::generate_ec_p521(&mut rng),
        PrivateKey::generate_ed25519(&mut rng),
    ] {
        let expected = private_key.thumbprint_sha256_base64();
        let pub_jwks =
            Keystore::new(JsonWebKeySet::new(vec![JsonWebKey::new(private_key)])).public_jwks();

        assert_eq!(pub_jwks.len(), 1, "JWKS should contain exactly one key");
        assert_eq!(pub_jwks[0].thumbprint_sha256_base64(), expected);
    }
}

#[test]
fn service_identity_key_is_selected_by_reserved_kid() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2027);
    let unrelated = PrivateKey::generate_ed25519(&mut rng);
    let expected = PrivateKey::generate_ed25519(&mut rng);
    let expected_seed = match &expected {
        PrivateKey::OkpEd25519(key) => key.to_bytes(),
        _ => unreachable!(),
    };
    let store = Keystore::new(JsonWebKeySet::new(vec![
        JsonWebKey::new(unrelated).with_kid("unrelated-ed25519"),
        JsonWebKey::new(expected).with_kid(SERVICE_IDENTITY_KEY_ID),
    ]));

    assert_eq!(store.service_identity_seed().unwrap(), expected_seed);
}

#[test]
fn service_identity_key_rejects_missing_and_wrong_type() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2028);
    let missing = Keystore::new(JsonWebKeySet::new(vec![JsonWebKey::new(
        PrivateKey::generate_ed25519(&mut rng),
    )]));
    assert!(matches!(
        missing.service_identity_seed(),
        Err(ServiceIdentityKeyError::Missing)
    ));

    let wrong_type = Keystore::new(JsonWebKeySet::new(vec![
        JsonWebKey::new(PrivateKey::generate_ec_p256(&mut rng)).with_kid(SERVICE_IDENTITY_KEY_ID),
    ]));
    assert!(matches!(
        wrong_type.service_identity_seed(),
        Err(ServiceIdentityKeyError::WrongKeyType)
    ));
}

#[test]
fn device_enrollment_key_is_distinct_and_selected_by_reserved_kid() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2029);
    let service_identity = PrivateKey::generate_ed25519(&mut rng);
    let expected = PrivateKey::generate_ed25519(&mut rng);
    let expected_seed = match &expected {
        PrivateKey::OkpEd25519(key) => key.to_bytes(),
        _ => unreachable!(),
    };
    let store = Keystore::new(JsonWebKeySet::new(vec![
        JsonWebKey::new(service_identity).with_kid(SERVICE_IDENTITY_KEY_ID),
        JsonWebKey::new(expected).with_kid(DEVICE_ENROLLMENT_KEY_ID),
    ]));

    assert_eq!(store.device_enrollment_seed().unwrap(), expected_seed);
    assert_ne!(
        store.device_enrollment_seed().unwrap(),
        store.service_identity_seed().unwrap()
    );
}

#[test]
fn device_enrollment_key_rejects_missing_and_wrong_type() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2030);
    let missing = Keystore::new(JsonWebKeySet::new(vec![JsonWebKey::new(
        PrivateKey::generate_ed25519(&mut rng),
    )]));
    assert!(matches!(
        missing.device_enrollment_seed(),
        Err(DeviceEnrollmentKeyError::Missing)
    ));

    let wrong_type = Keystore::new(JsonWebKeySet::new(vec![
        JsonWebKey::new(PrivateKey::generate_ec_p256(&mut rng)).with_kid(DEVICE_ENROLLMENT_KEY_ID),
    ]));
    assert!(matches!(
        wrong_type.device_enrollment_seed(),
        Err(DeviceEnrollmentKeyError::WrongKeyType)
    ));
}
