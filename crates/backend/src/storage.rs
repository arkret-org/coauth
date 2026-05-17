//! Storage abstraction layer using `OpenDAL`.
//!
//! Provides a global storage operator that supports local filesystem
//! and S3-compatible object storage backends.

use std::{sync::OnceLock, time::Duration};

use coauth_config::StorageConfig;
use opendal::{Operator, layers::LoggingLayer};

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
    let op = Operator::new(builder)?
        .layer(LoggingLayer::default())
        .finish();
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
    if path_style {
        builder = builder.enable_virtual_host_style();
    }
    if !prefix.is_empty() {
        builder = builder.root(prefix);
    }

    let op = Operator::new(builder)?
        .layer(LoggingLayer::default())
        .finish();
    tracing::info!(
        "Storage backend initialized: s3 (bucket={}, region={})",
        bucket,
        region
    );
    Ok(op)
}
