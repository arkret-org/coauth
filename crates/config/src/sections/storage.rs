// Storage backend configuration for media/avatar files.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

/// Storage backend configuration.
///
/// Supports local filesystem or S3-compatible object storage.
///
/// ```yaml
/// storage:
///   backend: fs
///   root: ./data/media
/// ```
///
/// or:
///
/// ```yaml
/// storage:
///   backend: s3
///   bucket: my-bucket
///   region: us-east-1
///   endpoint: https://account.r2.cloudflarestorage.com
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum StorageConfig {
    /// Local filesystem storage.
    Fs {
        /// Root directory for stored files.
        #[serde(default = "default_fs_root")]
        root: String,
    },

    /// S3-compatible object storage (AWS S3, Cloudflare R2, `MinIO`, etc.).
    S3 {
        /// S3 bucket name.
        bucket: String,

        /// S3 region.
        #[serde(default = "default_s3_region")]
        region: String,

        /// S3 endpoint URL. Required for non-AWS services.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,

        /// S3 access key ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_key_id: Option<String>,

        /// S3 secret access key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_access_key: Option<String>,

        /// Object key prefix.
        #[serde(default = "default_s3_prefix")]
        prefix: String,

        /// Enable path-style access (required for `MinIO`).
        #[serde(default)]
        path_style: bool,

        /// Redirect downloads to presigned S3 URLs.
        #[serde(default = "default_redirect")]
        redirect: bool,

        /// Presigned URL expiry in seconds.
        #[serde(default = "default_presign_expiry")]
        presign_expiry: u64,
    },
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::Fs {
            root: default_fs_root(),
        }
    }
}

impl StorageConfig {
    /// Returns `true` if the configuration is the default value.
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Fs { root } if root == &default_fs_root())
    }
}

impl ConfigurationSection for StorageConfig {
    const PATH: &'static str = "storage";

    fn validate(
        &self,
        _figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self {
            Self::Fs { root } => {
                if root.is_empty() {
                    return Err("storage.root must not be empty".into());
                }
            }
            Self::S3 { bucket, .. } => {
                if bucket.is_empty() {
                    return Err("storage.bucket must not be empty".into());
                }
            }
        }
        Ok(())
    }
}

fn default_fs_root() -> String {
    "./data/media".to_owned()
}

fn default_s3_region() -> String {
    "us-east-1".to_owned()
}

fn default_s3_prefix() -> String {
    "media/".to_owned()
}

fn default_redirect() -> bool {
    true
}

fn default_presign_expiry() -> u64 {
    300
}
