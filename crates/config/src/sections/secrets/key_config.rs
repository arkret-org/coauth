// ── Key and Password Configuration ──
//
// Types for representing cryptographic keys and passwords that can be
// specified either inline or via file references.

use std::borrow::Cow;

use anyhow::{Context, bail};
use camino::Utf8PathBuf;
use coauth_jose::jwk::{JsonWebKey, Thumbprint};
use coauth_keystore::PrivateKey;
use futures_util::future::try_join;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

// ── Password Representation ──

/// A password that can be specified as a literal string or read from a file
#[derive(Clone, Debug)]
pub enum Password {
    /// Load the password from this file path
    File(Utf8PathBuf),
    /// Use this literal string as the password
    Value(String),
}

/// Wire format for serializing/deserializing password fields
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub(crate) struct PasswordRaw {
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    password_file: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

impl TryFrom<PasswordRaw> for Option<Password> {
    type Error = anyhow::Error;

    fn try_from(raw: PasswordRaw) -> Result<Self, Self::Error> {
        match (raw.password, raw.password_file) {
            (None, None) => Ok(None),
            (Some(pw), None) => Ok(Some(Password::Value(pw))),
            (None, Some(path)) => Ok(Some(Password::File(path))),
            (Some(_), Some(_)) => bail!("Cannot specify both `password` and `password_file`"),
        }
    }
}

impl From<Option<Password>> for PasswordRaw {
    fn from(opt: Option<Password>) -> Self {
        match opt {
            None => PasswordRaw {
                password: None,
                password_file: None,
            },
            Some(Password::Value(pw)) => PasswordRaw {
                password: Some(pw),
                password_file: None,
            },
            Some(Password::File(path)) => PasswordRaw {
                password: None,
                password_file: Some(path),
            },
        }
    }
}

// ── Key Representation ──

/// A cryptographic key that can be given inline or loaded from a file
#[derive(Clone, Debug)]
pub enum Key {
    /// Load the key material from this file path
    File(Utf8PathBuf),
    /// Use this literal PEM/DER string as the key
    Value(String),
}

/// Wire format for serializing/deserializing key fields
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub(crate) struct KeyRaw {
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    key_file: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

impl TryFrom<KeyRaw> for Key {
    type Error = anyhow::Error;

    fn try_from(raw: KeyRaw) -> Result<Key, Self::Error> {
        match (raw.key, raw.key_file) {
            (None, None) => bail!("Missing `key` or `key_file`"),
            (Some(k), None) => Ok(Key::Value(k)),
            (None, Some(path)) => Ok(Key::File(path)),
            (Some(_), Some(_)) => bail!("Cannot specify both `key` and `key_file`"),
        }
    }
}

impl From<Key> for KeyRaw {
    fn from(k: Key) -> Self {
        match k {
            Key::Value(val) => KeyRaw {
                key: Some(val),
                key_file: None,
            },
            Key::File(path) => KeyRaw {
                key: None,
                key_file: Some(path),
            },
        }
    }
}

// ── Single Key Entry ──

/// A single signing/encryption key entry, optionally protected by a password
#[serde_as]
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub struct KeyConfig {
    /// The key ID (`kid`) as used in JWK headers.
    ///
    /// When omitted, the kid is derived as the key's RFC 7638 JWK Thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<String>,

    #[schemars(with = "PasswordRaw")]
    #[serde_as(as = "serde_with::TryFromInto<PasswordRaw>")]
    #[serde(flatten)]
    pub(crate) password: Option<Password>,

    #[schemars(with = "KeyRaw")]
    #[serde_as(as = "serde_with::TryFromInto<KeyRaw>")]
    #[serde(flatten)]
    pub(crate) key: Key,
}

impl KeyConfig {
    pub(crate) fn source_description(&self) -> String {
        let source = match &self.key {
            Key::File(path) => format!("secrets key file {path}"),
            Key::Value(_) => "inline secrets key".to_owned(),
        };

        match self.kid.as_deref() {
            Some(kid) => format!("{source} (kid={kid})"),
            None => source,
        }
    }

    /// Reads the password bytes, fetching from disk when stored as a file path
    async fn resolve_password(&self) -> anyhow::Result<Option<Cow<'_, [u8]>>> {
        match &self.password {
            None => Ok(None),
            Some(Password::Value(pw)) => Ok(Some(Cow::Borrowed(pw.as_bytes()))),
            Some(Password::File(path)) => {
                let bytes = tokio::fs::read(path)
                    .await
                    .with_context(|| format!("reading secrets key password file {path}"))?;
                Ok(Some(Cow::Owned(bytes)))
            }
        }
    }

    /// Reads the key bytes, fetching from disk when stored as a file path
    async fn resolve_key(&self) -> anyhow::Result<Cow<'_, [u8]>> {
        match &self.key {
            Key::Value(val) => Ok(Cow::Borrowed(val.as_bytes())),
            Key::File(path) => {
                let bytes = tokio::fs::read(path)
                    .await
                    .with_context(|| format!("reading secrets key file {path}"))?;
                Ok(Cow::Owned(bytes))
            }
        }
    }

    /// Derives a [`JsonWebKey`] by loading and parsing the underlying key
    /// material
    pub(crate) async fn to_json_web_key(
        &self,
    ) -> anyhow::Result<JsonWebKey<coauth_keystore::PrivateKey>> {
        let (key_data, password_data) =
            try_join(self.resolve_key(), self.resolve_password()).await?;

        let private_key = match password_data {
            Some(pw) => PrivateKey::load_encrypted(&key_data, pw)?,
            None => PrivateKey::load(&key_data)?,
        };

        let kid = self
            .kid
            .clone()
            .unwrap_or_else(|| private_key.thumbprint_sha256_base64());

        Ok(JsonWebKey::new(private_key)
            .with_kid(kid)
            .with_use(coauth_iana::jose::JsonWebKeyUse::Sig))
    }
}

// ── Directory Scanner ──

/// Scans every regular file in `dir` and returns a [`KeyConfig`] for each one
pub(crate) async fn enumerate_keys_in_directory(
    dir: &Utf8PathBuf,
) -> anyhow::Result<Vec<KeyConfig>> {
    let mut configs = vec![];
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("reading key directory {dir}"))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .with_context(|| format!("iterating key directory {dir}"))?
    {
        let path = entry.path();
        if !entry
            .file_type()
            .await
            .with_context(|| format!("reading file type for key path {}", path.display()))?
            .is_file()
        {
            continue;
        }
        configs.push(KeyConfig {
            kid: None,
            password: None,
            key: Key::File(path.try_into()?),
        });
    }

    Ok(configs)
}
