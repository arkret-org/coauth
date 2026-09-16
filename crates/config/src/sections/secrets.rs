// Copyright (c) 2026 Arkret Authors. Licensed under the Apache License,
// Version 2.0; see LICENSE-APACHE for details.

//! Durable custody for Coauth's runtime cryptographic material.
//!
//! `arkret-keystore` owns persistence and at-rest protection. The resulting
//! [`Keyring`] and [`Encrypter`] remain process-local crypto objects.

mod generation;

use std::collections::BTreeSet;
use std::fmt;

use anyhow::{Context, bail, ensure};
use arkret_keystore::KeyStore;
use base64::Engine as _;
use camino::Utf8PathBuf;
use coauth_iana::jose::{JsonWebKeyUse, JsonWebSignatureAlg};
use coauth_jose::jwk::{JsonWebKey, JsonWebKeySet, Thumbprint};
use coauth_keyring::{Encrypter, Keyring, PrivateKey};
use rand_core::SeedableRng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use self::generation::{StoredKeyBundle, generate_key_bundle};
use super::ConfigurationSection;

/// Stable namespace passed to every `arkret-keystore` backend.
pub const KEYSTORE_APPLICATION_ID: &str = "coauth.runtime-keys";
/// The single atomic KeyStore item containing the complete v1 runtime key set.
pub const KEY_BUNDLE_ID: &str = "arkret:coauth:runtime-key-bundle:v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum KeyStoreBackend {
    /// Native operating-system credential storage for the current user.
    Platform,
    /// Authenticated encrypted file with a separately custodied master key.
    EncryptedFile,
}

/// Durable backend configuration. There is deliberately no memory or disabled
/// backend in the serialized production configuration.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyStoreConfig {
    backend: KeyStoreBackend,
    /// Encrypted KeyStore file; valid only with `encrypted_file`.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Utf8PathBuf>,
    /// Base64-encoded 32-byte master key. Prefer `master_key_file` in
    /// production so a config dump does not contain the wrapping key.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    master_key: Option<Zeroizing<String>>,
    /// File containing the base64-encoded 32-byte master key.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    master_key_file: Option<Utf8PathBuf>,
}

impl fmt::Debug for KeyStoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyStoreConfig")
            .field("backend", &self.backend)
            .field("path", &self.path)
            .field(
                "master_key",
                &self.master_key.as_ref().map(|_| "<redacted>"),
            )
            .field("master_key_file", &self.master_key_file)
            .finish()
    }
}

impl ConfigurationSection for KeyStoreConfig {
    const PATH: &'static str = "secrets";

    fn validate(
        &self,
        _figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.validate_backend()
            .map_err(anyhow::Error::into_boxed_dyn_error)
    }
}

impl KeyStoreConfig {
    /// Production-safe generated default. It contains no private key material;
    /// the first server launch must explicitly provision the platform store.
    #[must_use]
    pub const fn platform() -> Self {
        Self {
            backend: KeyStoreBackend::Platform,
            path: None,
            master_key: None,
            master_key_file: None,
        }
    }

    /// Encrypted-file backend with a separately stored master key.
    ///
    /// This is the local-development and container-friendly durable shape;
    /// neither file is created or silently replaced by configuration loading.
    #[must_use]
    pub fn encrypted_file(
        path: impl Into<Utf8PathBuf>,
        master_key_file: impl Into<Utf8PathBuf>,
    ) -> Self {
        Self {
            backend: KeyStoreBackend::EncryptedFile,
            path: Some(path.into()),
            master_key: None,
            master_key_file: Some(master_key_file.into()),
        }
    }

    fn validate_backend(&self) -> anyhow::Result<()> {
        match self.backend {
            KeyStoreBackend::Platform => {
                ensure!(
                    self.path.is_none()
                        && self.master_key.is_none()
                        && self.master_key_file.is_none(),
                    "secrets.path and master-key settings are only valid with backend=encrypted_file"
                );
                Ok(())
            }
            KeyStoreBackend::EncryptedFile => {
                let path = self.path.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("secrets.path is required with backend=encrypted_file")
                })?;
                ensure!(
                    !path.as_str().trim().is_empty(),
                    "secrets.path must not be empty"
                );
                match (&self.master_key, &self.master_key_file) {
                    (Some(_), None) | (None, Some(_)) => {}
                    (None, None) => bail!(
                        "secrets.master_key or secrets.master_key_file is required with backend=encrypted_file"
                    ),
                    (Some(_), Some(_)) => {
                        bail!(
                            "secrets.master_key and secrets.master_key_file are mutually exclusive"
                        )
                    }
                }
                if let Some(master_key_file) = &self.master_key_file {
                    ensure!(
                        !paths_refer_to_same_file(master_key_file, path),
                        "secrets.master_key_file must be separate from secrets.path"
                    );
                }
                Ok(())
            }
        }
    }

    /// Open the configured durable backend. This never falls back to memory.
    async fn open(&self) -> anyhow::Result<Box<dyn KeyStore>> {
        self.validate_backend()?;
        match self.backend {
            KeyStoreBackend::Platform => {
                arkret_keystore::durable_platform_keystore(KEYSTORE_APPLICATION_ID)
                    .map_err(|error| anyhow::anyhow!("opening platform KeyStore failed: {error}"))
            }
            KeyStoreBackend::EncryptedFile => {
                let path = self.path.as_ref().expect("validated above");
                let raw = match (&self.master_key, &self.master_key_file) {
                    (Some(value), None) => value.clone(),
                    (None, Some(path)) => Zeroizing::new(
                        tokio::fs::read_to_string(path)
                            .await
                            .with_context(|| format!("reading KeyStore master-key file {path}"))?,
                    ),
                    _ => unreachable!("validated above"),
                };
                let mut decoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD
                        .decode(raw.trim().as_bytes())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(raw.trim().as_bytes())
                        })
                        .context("KeyStore master key must be base64")?,
                );
                ensure!(
                    decoded.len() == 32,
                    "KeyStore master key must decode to exactly 32 bytes (got {})",
                    decoded.len()
                );
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                decoded.zeroize();
                let store = arkret_keystore::EncryptedFileKeyStore::new(
                    path.as_std_path(),
                    KEYSTORE_APPLICATION_ID,
                    key,
                )
                .map_err(|error| {
                    anyhow::anyhow!("opening encrypted-file KeyStore failed: {error}")
                });
                key.zeroize();
                Ok(Box::new(store?) as Box<dyn KeyStore>)
            }
        }
    }

    /// Load the complete runtime secret set, optionally authorising one-time
    /// generation when the durable store is empty.
    pub async fn runtime(&self, first_provisioning: bool) -> anyhow::Result<RuntimeSecrets> {
        let store = self.open().await?;
        load_runtime_from_store(store.as_ref(), first_provisioning).await
    }
}

/// Process-local cryptographic objects built from one durable key bundle.
pub struct RuntimeSecrets {
    keyring: Keyring,
    encrypter: Encrypter,
    encryption_key: Zeroizing<[u8; 32]>,
}

impl RuntimeSecrets {
    #[must_use]
    pub fn keyring(&self) -> Keyring {
        self.keyring.clone()
    }

    #[must_use]
    pub fn encrypter(&self) -> Encrypter {
        self.encrypter.clone()
    }

    #[must_use]
    pub fn encryption_key(&self) -> &[u8; 32] {
        &self.encryption_key
    }
}

async fn load_runtime_from_store(
    store: &dyn KeyStore,
    first_provisioning: bool,
) -> anyhow::Result<RuntimeSecrets> {
    match store.load(KEY_BUNDLE_ID) {
        Ok(bytes) => build_runtime(StoredKeyBundle::decode(bytes.as_slice())?),
        Err(error) if error.is_not_found() && first_provisioning => {
            let mut rng = rand_chacha::ChaChaRng::from_entropy();
            let generated = generate_key_bundle(&mut rng).await?;
            let encoded = generated.encode()?;
            store
                .store(KEY_BUNDLE_ID, &encoded)
                .context("persisting generated Coauth runtime key bundle")?;

            // Use the backend's committed value, not the local candidate. This
            // also detects backends that acknowledged a write without making
            // the complete value readable.
            let persisted = store
                .load(KEY_BUNDLE_ID)
                .context("reloading provisioned Coauth runtime key bundle")?;
            build_runtime(StoredKeyBundle::decode(persisted.as_slice())?)
        }
        Err(error) if error.is_not_found() => bail!(
            "coauth_runtime_keys_first_provisioning_required: no runtime key bundle exists; run exactly one production server with --first-provisioning"
        ),
        Err(error) => Err(anyhow::Error::new(error).context("loading Coauth runtime key bundle")),
    }
}

fn build_runtime(bundle: StoredKeyBundle) -> anyhow::Result<RuntimeSecrets> {
    let mut jwks = Vec::with_capacity(bundle.keys.len());
    let mut key_ids = BTreeSet::new();
    for stored in bundle.keys {
        let private_key =
            PrivateKey::load(&stored.der).context("decoding stored JOSE private key")?;
        let kid = stored
            .kid
            .unwrap_or_else(|| private_key.thumbprint_sha256_base64());
        ensure!(
            key_ids.insert(kid.clone()),
            "stored key bundle contains duplicate kid {kid}"
        );
        jwks.push(
            JsonWebKey::new(private_key)
                .with_kid(kid)
                .with_use(JsonWebKeyUse::Sig),
        );
    }

    let keyring = Keyring::new(
        JsonWebKeySet::try_new(jwks).context("invalid JWK metadata in stored key bundle")?,
    );
    keyring
        .account_authority_seed()
        .context("invalid Account Authority key in stored key bundle")?;
    keyring
        .audit_signing_seed()
        .context("invalid audit signing key in stored key bundle")?;
    ensure!(
        keyring.session_grant_signing_key().is_some(),
        "stored key bundle has no usable session-grant signing key"
    );
    for algorithm in [
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es256K,
        JsonWebSignatureAlg::Ed25519,
    ] {
        keyring.signer_for_algorithm(&algorithm).with_context(|| {
            format!("stored key bundle cannot sign with required algorithm {algorithm}")
        })?;
    }

    let encrypter = Encrypter::new(&bundle.encryption_key);
    Ok(RuntimeSecrets {
        keyring,
        encrypter,
        encryption_key: bundle.encryption_key,
    })
}

fn paths_refer_to_same_file(left: &Utf8PathBuf, right: &Utf8PathBuf) -> bool {
    left == right
        || std::fs::canonicalize(left)
            .ok()
            .zip(std::fs::canonicalize(right).ok())
            .is_some_and(|(left, right)| left == right)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use arkret_keystore::{EncryptedFileKeyStore, KeyBytes, KeyStoreError};
    use tempfile::tempdir;

    use super::*;

    #[derive(Default)]
    struct TestKeyStore {
        keys: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl KeyStore for TestKeyStore {
        fn load(&self, id: &str) -> std::result::Result<KeyBytes, KeyStoreError> {
            self.keys
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .map(KeyBytes::new)
                .ok_or_else(|| KeyStoreError::not_found(id))
        }

        fn store(&self, id: &str, key: &[u8]) -> std::result::Result<(), KeyStoreError> {
            arkret_keystore::validate_id(id)?;
            self.keys
                .lock()
                .unwrap()
                .insert(id.to_owned(), key.to_vec());
            Ok(())
        }

        fn list(&self) -> std::result::Result<Vec<String>, KeyStoreError> {
            Ok(self.keys.lock().unwrap().keys().cloned().collect())
        }

        fn delete(&self, id: &str) -> std::result::Result<(), KeyStoreError> {
            arkret_keystore::validate_id(id)?;
            self.keys.lock().unwrap().remove(id);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_store_provisions_once_and_reloads_same_jwks() {
        let store = TestKeyStore::default();
        let first = load_runtime_from_store(&store, true).await.unwrap();
        let repeated_provisioning = load_runtime_from_store(&store, true).await.unwrap();
        let read_only = load_runtime_from_store(&store, false).await.unwrap();

        assert_eq!(
            serde_json::to_value(first.keyring().public_jwks()).unwrap(),
            serde_json::to_value(repeated_provisioning.keyring().public_jwks()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(first.keyring().public_jwks()).unwrap(),
            serde_json::to_value(read_only.keyring().public_jwks()).unwrap()
        );
        let ciphertext = first.encrypter().encrypt_to_string(b"persistent").unwrap();
        assert_eq!(
            read_only.encrypter().decrypt_string(&ciphertext).unwrap(),
            b"persistent"
        );
    }

    #[tokio::test]
    async fn missing_bundle_fails_without_first_provisioning() {
        let error = load_runtime_from_store(&TestKeyStore::default(), false)
            .await
            .err()
            .expect("missing bundle must fail");
        assert!(
            error
                .to_string()
                .contains("coauth_runtime_keys_first_provisioning_required")
        );
    }

    #[tokio::test]
    async fn encrypted_file_reopens_with_same_keys_and_encryption_secret() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("coauth-runtime-keys.v1");
        let master_key = [0xA7; 32];

        let first_store =
            EncryptedFileKeyStore::new(&path, KEYSTORE_APPLICATION_ID, master_key).unwrap();
        let first = load_runtime_from_store(&first_store, true).await.unwrap();
        let expected_jwks = serde_json::to_value(first.keyring().public_jwks()).unwrap();
        let ciphertext = first
            .encrypter()
            .encrypt_to_string(b"after restart")
            .unwrap();
        drop(first);
        drop(first_store);

        let reopened_store =
            EncryptedFileKeyStore::new(&path, KEYSTORE_APPLICATION_ID, master_key).unwrap();
        let reopened = load_runtime_from_store(&reopened_store, false)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(reopened.keyring().public_jwks()).unwrap(),
            expected_jwks
        );
        assert_eq!(
            reopened.encrypter().decrypt_string(&ciphertext).unwrap(),
            b"after restart"
        );
    }

    #[test]
    fn encrypted_file_requires_exactly_one_master_key_source() {
        let no_key = KeyStoreConfig {
            backend: KeyStoreBackend::EncryptedFile,
            path: Some("keys.v1".into()),
            master_key: None,
            master_key_file: None,
        };
        assert!(no_key.validate_backend().is_err());

        let two_keys = KeyStoreConfig {
            backend: KeyStoreBackend::EncryptedFile,
            path: Some("keys.v1".into()),
            master_key: Some(Zeroizing::new("unused".to_owned())),
            master_key_file: Some("master.key".into()),
        };
        assert!(two_keys.validate_backend().is_err());
    }

    #[test]
    fn debug_redacts_inline_master_key() {
        let config = KeyStoreConfig {
            backend: KeyStoreBackend::EncryptedFile,
            path: Some("keys.v1".into()),
            master_key: Some(Zeroizing::new("must-not-appear".to_owned())),
            master_key_file: None,
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("must-not-appear"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn serialized_config_rejects_unsupported_inline_key_fields() {
        let unsupported = serde_json::json!({
            "backend": "platform",
            "encryption": "00",
            "keys": []
        });
        assert!(serde_json::from_value::<KeyStoreConfig>(unsupported).is_err());
    }

    #[test]
    fn platform_backend_round_trips_without_key_material() {
        let encoded = serde_json::to_value(KeyStoreConfig::platform()).unwrap();
        assert_eq!(encoded, serde_json::json!({"backend": "platform"}));
        assert!(serde_json::from_value::<KeyStoreConfig>(encoded).is_ok());
    }
}
