// ── Encryption Key Configuration ──
//
// The 32-byte symmetric key used for encrypting secure cookies and
// other application-level secrets.

use anyhow::{Context, bail};
use camino::Utf8PathBuf;
use coauth_keystore::Encrypter;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

// ── Encryption Key ──

/// A 32-byte encryption key, either given as a hex literal or loaded from a
/// file
#[derive(Debug, Clone)]
pub enum EncryptionKey {
    /// Read the hex-encoded key from this file path
    File(Utf8PathBuf),
    /// Use these raw bytes directly
    Value([u8; 32]),
}

/// Wire format for serializing/deserializing encryption key fields
#[serde_as]
#[derive(JsonSchema, Serialize, Deserialize, Debug, Clone)]
pub(crate) struct EncryptionKeyRaw {
    /// File containing the hex-encoded encryption key for secure cookies.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_file: Option<Utf8PathBuf>,

    /// Hex-encoded encryption key for secure cookies (64 hex characters = 32
    /// bytes).
    #[schemars(
        with = "Option<String>",
        regex(pattern = r"[0-9a-fA-F]{64}"),
        example = &"0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
    )]
    #[serde_as(as = "Option<serde_with::hex::Hex>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<[u8; 32]>,
}

impl TryFrom<EncryptionKeyRaw> for EncryptionKey {
    type Error = anyhow::Error;

    fn try_from(raw: EncryptionKeyRaw) -> Result<EncryptionKey, Self::Error> {
        match (raw.encryption, raw.encryption_file) {
            (None, None) => bail!("Missing `encryption` or `encryption_file`"),
            (Some(val), None) => Ok(EncryptionKey::Value(val)),
            (None, Some(path)) => Ok(EncryptionKey::File(path)),
            (Some(_), Some(_)) => {
                bail!("Cannot specify both `encryption` and `encryption_file`")
            }
        }
    }
}

impl From<EncryptionKey> for EncryptionKeyRaw {
    fn from(enc: EncryptionKey) -> Self {
        match enc {
            EncryptionKey::Value(val) => EncryptionKeyRaw {
                encryption: Some(val),
                encryption_file: None,
            },
            EncryptionKey::File(path) => EncryptionKeyRaw {
                encryption: None,
                encryption_file: Some(path),
            },
        }
    }
}

impl EncryptionKey {
    /// Resolves the encryption key bytes.
    ///
    /// When stored as a file path, the file is read and hex-decoded at call
    /// time.
    pub(crate) async fn resolve(&self) -> anyhow::Result<[u8; 32]> {
        match self {
            Self::Value(bytes) => Ok(*bytes),
            Self::File(path) => {
                let content = tokio::fs::read(path).await?;
                let mut buf = [0u8; 32];
                hex::decode_to_slice(content, &mut buf).context(
                    "Content of `encryption_file` must contain hex characters \
                    encoding exactly 32 bytes",
                )?;
                Ok(buf)
            }
        }
    }

    /// Builds an [`Encrypter`] from this encryption key.
    pub(crate) async fn to_encrypter(&self) -> anyhow::Result<Encrypter> {
        let raw_key = self.resolve().await?;
        Ok(Encrypter::new(&raw_key))
    }
}
