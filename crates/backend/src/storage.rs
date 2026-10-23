//! Storage abstraction layer using `OpenDAL`.
//!
//! Provides a global storage operator that supports local filesystem
//! and S3-compatible object storage backends.

use std::sync::OnceLock;
use std::time::Duration;

use coauth_config::StorageConfig;
use opendal::Operator;
use opendal::layers::LoggingLayer;

static OPERATOR: OnceLock<Operator> = OnceLock::new();
static REDIRECT_CONFIG: OnceLock<Option<RedirectConfig>> = OnceLock::new();

struct RedirectConfig {
    presign_expiry: Duration,
}

/// Initialize the global storage operator from configuration.
/// Must be called once at startup.
pub fn init(config: &StorageConfig) -> anyhow::Result<()> {
    let op = build_operator(config)?;
    OPERATOR
        .set(op)
        .map_err(|_| anyhow::anyhow!("Storage operator already initialized"))?;

    let redirect = match config {
        StorageConfig::S3 {
            redirect,
            presign_expiry,
            ..
        } if *redirect => Some(RedirectConfig {
            presign_expiry: Duration::from_secs(*presign_expiry),
        }),
        _ => None,
    };
    REDIRECT_CONFIG
        .set(redirect)
        .map_err(|_| anyhow::anyhow!("Redirect config already initialized"))?;

    Ok(())
}

/// Get the global storage operator.
pub fn operator() -> &'static Operator {
    OPERATOR
        .get()
        .expect("Storage operator not initialized. Call storage::init() first.")
}

/// Generate a presigned URL for reading the given key.
/// Returns `None` if redirect is not enabled.
pub async fn presign_read(key: &str) -> anyhow::Result<Option<String>> {
    let Some(Some(config)) = REDIRECT_CONFIG.get() else {
        return Ok(None);
    };
    let presigned = operator().presign_read(key, config.presign_expiry).await?;
    Ok(Some(presigned.uri().to_string()))
}

/// Write bytes to storage.
pub async fn write(key: &str, data: &[u8]) -> anyhow::Result<()> {
    operator().write(key, data.to_vec()).await?;
    Ok(())
}

/// Read bytes from storage.
pub async fn read(key: &str) -> anyhow::Result<Vec<u8>> {
    let data = operator().read(key).await?;
    Ok(data.to_vec())
}

/// Check if an object exists in storage.
pub async fn exists(key: &str) -> anyhow::Result<bool> {
    Ok(operator().exists(key).await?)
}

/// Delete an object from storage.
pub async fn delete(key: &str) -> anyhow::Result<()> {
    operator().delete(key).await?;
    Ok(())
}

/// Build the storage key for an avatar file.
#[must_use]
pub fn avatar_key(user_id: &str) -> String {
    format!("avatars/{user_id}")
}

fn build_operator(config: &StorageConfig) -> anyhow::Result<Operator> {
    match config {
        StorageConfig::Fs { root } => build_fs_operator(root),
        StorageConfig::S3 {
            bucket,
            region,
            endpoint,
            access_key_id,
            secret_access_key,
            prefix,
            path_style,
            ..
        } => build_s3_operator(
            bucket,
            region,
            endpoint.as_deref(),
            access_key_id.as_deref(),
            secret_access_key.as_deref(),
            prefix,
            *path_style,
        ),
    }
}

fn build_fs_operator(root: &str) -> anyhow::Result<Operator> {
    let builder = opendal::services::Fs::default().root(root);
    let op = Operator::new(builder)?.layer(LoggingLayer::default());
    tracing::info!("Storage backend initialized: fs (root={})", root);
    Ok(op)
}

fn build_s3_operator(
    bucket: &str,
    region: &str,
    endpoint: Option<&str>,
    access_key_id: Option<&str>,
    secret_access_key: Option<&str>,
    prefix: &str,
    path_style: bool,
) -> anyhow::Result<Operator> {
    let mut builder = opendal::services::S3::default()
        .bucket(bucket)
        .region(region);

    if let Some(endpoint) = endpoint {
        builder = builder.endpoint(endpoint);
    }
    if let Some(access_key_id) = access_key_id {
        builder = builder.access_key_id(access_key_id);
    }
    if let Some(secret_access_key) = secret_access_key {
        builder = builder.secret_access_key(secret_access_key);
    }
    if !path_style {
        builder = builder.enable_virtual_host_style();
    }
    if !prefix.is_empty() {
        builder = builder.root(prefix);
    }

    let op = Operator::new(builder)?.layer(LoggingLayer::default());
    tracing::info!(
        "Storage backend initialized: s3 (bucket={}, region={})",
        bucket,
        region
    );
    Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn assert_s3_addressing(style_config: &str, expected_host: &str, expected_path: &str) {
        let config: StorageConfig = serde_saphyr::from_str(&format!(
            "backend: s3\n\
             bucket: avatar-bucket\n\
             region: us-east-1\n\
             endpoint: https://s3.example.com\n\
             access_key_id: test-access-key\n\
             secret_access_key: test-secret-key\n\
             prefix: media/\n\
             {style_config}"
        ))
        .unwrap();
        let operator = build_operator(&config).unwrap();
        let request = operator
            .presign_read("avatars/user.png", Duration::from_secs(300))
            .await
            .unwrap();
        let url = url::Url::parse(&request.uri().to_string()).unwrap();

        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some(expected_host));
        assert_eq!(url.path(), expected_path);
        assert!(url.query_pairs().any(|(key, value)| {
            key == "X-Amz-Credential" && value.starts_with("test-access-key/")
        }));
        assert!(
            url.query_pairs()
                .any(|(key, value)| key == "X-Amz-Expires" && value == "300")
        );
        assert!(
            url.query_pairs()
                .any(|(key, value)| key == "X-Amz-Signature" && !value.is_empty())
        );
    }

    #[tokio::test]
    async fn s3_path_style_places_bucket_in_path() {
        assert_s3_addressing(
            "path_style: true\n",
            "s3.example.com",
            "/avatar-bucket/media/avatars/user.png",
        )
        .await;
    }

    #[tokio::test]
    async fn s3_virtual_host_style_places_bucket_in_host() {
        assert_s3_addressing(
            "path_style: false\n",
            "avatar-bucket.s3.example.com",
            "/media/avatars/user.png",
        )
        .await;
    }

    #[tokio::test]
    async fn s3_defaults_to_virtual_host_style() {
        assert_s3_addressing(
            "",
            "avatar-bucket.s3.example.com",
            "/media/avatars/user.png",
        )
        .await;
    }
}
