use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::{
    QueryableByName,
    sql_types::{Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid},
};
use diesel_async::{
    AsyncPgConnection, RunQueryDsl as _, pooled_connection::deadpool::Pool as DieselPool,
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;
use uuid::Uuid;

pub type PrincipalCacheServiceHandle = Arc<dyn PrincipalCacheService>;

const DEFAULT_CACHE_KEY: &str = "default";

fn principal_recovery_cache_seed() -> Value {
    json!({
        "cache_mode": "process_memory_dev_fallback",
        "storage": {
            "kind": "process_memory",
            "durable": false,
            "fallback": true
        },
        "refresh_state": "idle",
        "refresh_count": 0,
        "failure_count": 0,
        "last_refresh_at": null,
        "last_failure_at": null,
        "last_failure_code": null,
        "last_reason": null,
        "last_invalidated_at": null,
        "etag": null,
        "contract_digest": null,
        "drift": {
            "state": "none",
            "last_detected_at": null
        },
        "in_flight_job": null,
        "queue": [],
        "failure_log": [],
        "last_upstream_probe_at": null,
        "last_upstream_probe_result": null,
        "upstream_binding": {
            "principal_base_url": null,
            "binding_state": "unbound",
            "discovery_mode": "static_path_scaffold"
        },
        "cached_snapshot": null
    })
}

static PRINCIPAL_RECOVERY_CACHE: LazyLock<Mutex<Value>> =
    LazyLock::new(|| Mutex::new(principal_recovery_cache_seed()));

#[async_trait]
pub trait PrincipalCacheService: Send + Sync {
    async fn snapshot(&self) -> Value;
    async fn store(&self, value: Value);
    fn body_string(&self, body: &Value, key: &str, default: &str) -> String;
    fn normalize_principal_base_url(&self, value: &str) -> Result<String, String>;
    async fn probe_recovery_surface(
        &self,
        client: &reqwest::Client,
        principal_base_url: &str,
        path: &str,
        expected_contract: &str,
        bearer_token: Option<&str>,
    ) -> Value;
}

#[derive(Default)]
pub struct InMemoryPrincipalCacheService;

#[async_trait]
impl PrincipalCacheService for InMemoryPrincipalCacheService {
    async fn snapshot(&self) -> Value {
        PRINCIPAL_RECOVERY_CACHE
            .lock()
            .expect("principal recovery cache lock")
            .clone()
    }

    async fn store(&self, value: Value) {
        *PRINCIPAL_RECOVERY_CACHE
            .lock()
            .expect("principal recovery cache lock") = annotate_memory_fallback(value, None);
    }

    fn body_string(&self, body: &Value, key: &str, default: &str) -> String {
        body.get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(default)
            .trim()
            .to_owned()
    }

    fn normalize_principal_base_url(&self, value: &str) -> Result<String, String> {
        normalize_principal_base_url(value)
    }

    async fn probe_recovery_surface(
        &self,
        client: &reqwest::Client,
        principal_base_url: &str,
        path: &str,
        expected_contract: &str,
        bearer_token: Option<&str>,
    ) -> Value {
        probe_recovery_surface(
            client,
            principal_base_url,
            path,
            expected_contract,
            bearer_token,
        )
        .await
    }
}

pub struct PgPrincipalCacheService {
    pool: DieselPool<AsyncPgConnection>,
    fallback: PrincipalCacheServiceHandle,
}

#[derive(Debug, QueryableByName)]
struct PrincipalCacheRow {
    #[diesel(sql_type = Jsonb)]
    cache_state: Value,
    #[diesel(sql_type = Nullable<Text>)]
    etag: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    contract_digest: Option<String>,
}

#[async_trait]
impl PrincipalCacheService for PgPrincipalCacheService {
    async fn snapshot(&self) -> Value {
        match self.load_row().await {
            Ok(Some(row)) => annotate_pg_snapshot(row.cache_state, row.etag, row.contract_digest),
            Ok(None) => {
                let seed = prepare_pg_snapshot(principal_recovery_cache_seed(), None);
                if let Err(error) = self.write_snapshot(seed.clone()).await {
                    tracing::warn!(
                        error = %error,
                        "failed to initialize durable recovery principal cache; using memory fallback"
                    );
                    return self.fallback_snapshot(Some(error.to_string())).await;
                }
                seed
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "failed to load durable recovery principal cache; using memory fallback"
                );
                self.fallback_snapshot(Some(error.to_string())).await
            }
        }
    }

    async fn store(&self, value: Value) {
        let fallback_value = value.clone();
        match self.write_snapshot(value).await {
            Ok(stored) => self.fallback.store(stored).await,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "failed to persist recovery principal cache; using memory fallback"
                );
                self.fallback
                    .store(annotate_memory_fallback(
                        fallback_value,
                        Some(error.to_string()),
                    ))
                    .await;
            }
        }
    }

    fn body_string(&self, body: &Value, key: &str, default: &str) -> String {
        self.fallback.body_string(body, key, default)
    }

    fn normalize_principal_base_url(&self, value: &str) -> Result<String, String> {
        normalize_principal_base_url(value)
    }

    async fn probe_recovery_surface(
        &self,
        client: &reqwest::Client,
        principal_base_url: &str,
        path: &str,
        expected_contract: &str,
        bearer_token: Option<&str>,
    ) -> Value {
        probe_recovery_surface(
            client,
            principal_base_url,
            path,
            expected_contract,
            bearer_token,
        )
        .await
    }
}

impl PgPrincipalCacheService {
    fn new(pool: DieselPool<AsyncPgConnection>) -> Self {
        Self {
            pool,
            fallback: default_principal_cache_service(),
        }
    }

    async fn fallback_snapshot(&self, reason: Option<String>) -> Value {
        annotate_memory_fallback(self.fallback.snapshot().await, reason)
    }

    async fn load_row(&self) -> anyhow::Result<Option<PrincipalCacheRow>> {
        let mut conn = self.pool.get().await?;
        let rows = diesel::sql_query(
            r#"
            SELECT cache_state, etag, contract_digest
            FROM recovery_principal_cache
            WHERE cache_key = $1
            LIMIT 1
            "#,
        )
        .bind::<Text, _>(DEFAULT_CACHE_KEY)
        .get_results::<PrincipalCacheRow>(&mut *conn)
        .await?;
        Ok(rows.into_iter().next())
    }

    async fn write_snapshot(&self, value: Value) -> anyhow::Result<Value> {
        let previous = self.load_row().await?;
        let mut value = prepare_pg_snapshot(value, previous.as_ref());
        let etag = extract_cache_etag(&value);
        let contract_digest = calculate_contract_digest(&value);

        if let Some(drift) = detect_drift(previous.as_ref(), etag.as_deref(), &contract_digest) {
            apply_drift(&mut value, drift.clone());
        }

        set_cache_metadata(&mut value, etag.as_deref(), &contract_digest);
        let failure_event = failure_event_to_record(previous.as_ref(), &value);

        let principal_base_url = value
            .pointer("/upstream_binding/principal_base_url")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        let audience = value
            .pointer("/upstream_binding/audience")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        let last_refresh_at = parse_timestamp(value.get("last_refresh_at"));
        let last_invalidated_at = parse_timestamp(value.get("last_invalidated_at"));

        let mut conn = self.pool.get().await?;
        diesel::sql_query(
            r#"
            INSERT INTO recovery_principal_cache (
                cache_key,
                principal_base_url,
                audience,
                cache_state,
                etag,
                contract_digest,
                last_refresh_at,
                last_invalidated_at,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
            ON CONFLICT (cache_key) DO UPDATE SET
                principal_base_url = EXCLUDED.principal_base_url,
                audience = EXCLUDED.audience,
                cache_state = EXCLUDED.cache_state,
                etag = EXCLUDED.etag,
                contract_digest = EXCLUDED.contract_digest,
                last_refresh_at = EXCLUDED.last_refresh_at,
                last_invalidated_at = EXCLUDED.last_invalidated_at,
                updated_at = NOW()
            "#,
        )
        .bind::<Text, _>(DEFAULT_CACHE_KEY)
        .bind::<Nullable<Text>, _>(principal_base_url)
        .bind::<Nullable<Text>, _>(audience)
        .bind::<Jsonb, _>(value.clone())
        .bind::<Nullable<Text>, _>(etag)
        .bind::<Nullable<Text>, _>(Some(contract_digest))
        .bind::<Nullable<Timestamptz>, _>(last_refresh_at)
        .bind::<Nullable<Timestamptz>, _>(last_invalidated_at)
        .execute(&mut *conn)
        .await?;

        if let Some((failure_code, reason, details)) = failure_event {
            self.record_failure(&failure_code, reason.as_deref(), details)
                .await?;
        }

        Ok(value)
    }

    async fn record_failure(
        &self,
        failure_code: &str,
        reason: Option<&str>,
        details: Value,
    ) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        diesel::sql_query(
            r#"
            INSERT INTO recovery_principal_cache_failure (
                id,
                cache_key,
                failure_code,
                reason,
                details,
                failed_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
        )
        .bind::<DieselUuid, _>(Uuid::now_v7())
        .bind::<Text, _>(DEFAULT_CACHE_KEY)
        .bind::<Text, _>(failure_code.to_owned())
        .bind::<Nullable<Text>, _>(reason.map(str::to_owned))
        .bind::<Jsonb, _>(details)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
}

fn normalize_principal_base_url(value: &str) -> Result<String, String> {
    let mut url = Url::parse(value).map_err(|_| "invalid_principal_base_url".to_owned())?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err("unsupported_principal_base_url_scheme".to_owned()),
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

async fn probe_recovery_surface(
    client: &reqwest::Client,
    principal_base_url: &str,
    path: &str,
    expected_contract: &str,
    bearer_token: Option<&str>,
) -> Value {
    let url = match Url::parse(principal_base_url)
        .and_then(|base| base.join(path.trim_start_matches('/')))
    {
        Ok(url) => url,
        Err(_) => {
            return json!({
                "path": path,
                "expected_contract": expected_contract,
                "state": "invalid_probe_url"
            });
        }
    };
    let mut request = client.get(url.clone());
    if let Some(token) = bearer_token.filter(|value| !value.trim().is_empty()) {
        request = request.bearer_auth(token);
    }
    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let etag = response
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned);
            let body = response.json::<Value>().await.unwrap_or(Value::Null);
            let actual_contract = body.get("contract").and_then(Value::as_str).unwrap_or("");
            let state = if status == 401 || status == 403 {
                "auth_required"
            } else if status >= 400 {
                "http_error"
            } else if actual_contract == expected_contract {
                "contract_ok"
            } else {
                "contract_mismatch"
            };
            json!({
                "path": path,
                "url": url.as_str(),
                "status": status,
                "state": state,
                "expected_contract": expected_contract,
                "actual_contract": actual_contract,
                "etag": etag,
                "body": body
            })
        }
        Err(error) => json!({
            "path": path,
            "url": url.as_str(),
            "state": "request_error",
            "expected_contract": expected_contract,
            "error": error.to_string()
        }),
    }
}

fn prepare_pg_snapshot(value: Value, previous: Option<&PrincipalCacheRow>) -> Value {
    let mut value = if value.is_null() {
        principal_recovery_cache_seed()
    } else {
        value
    };
    let etag = extract_cache_etag(&value).or_else(|| previous.and_then(|row| row.etag.clone()));
    let contract_digest = calculate_contract_digest(&value);
    set_cache_metadata(&mut value, etag.as_deref(), &contract_digest);
    let object = ensure_object(&mut value);
    object.insert(
        "cache_mode".to_owned(),
        Value::String("pg_recovery_principal_cache".to_owned()),
    );
    object.insert(
        "storage".to_owned(),
        json!({
            "kind": "pg",
            "table": "recovery_principal_cache",
            "failure_table": "recovery_principal_cache_failure",
            "durable": true,
            "fallback": false
        }),
    );
    value
}

fn annotate_pg_snapshot(
    mut value: Value,
    etag: Option<String>,
    contract_digest: Option<String>,
) -> Value {
    let digest = contract_digest.unwrap_or_else(|| calculate_contract_digest(&value));
    set_cache_metadata(&mut value, etag.as_deref(), &digest);
    let object = ensure_object(&mut value);
    object.insert(
        "cache_mode".to_owned(),
        Value::String("pg_recovery_principal_cache".to_owned()),
    );
    object.insert(
        "storage".to_owned(),
        json!({
            "kind": "pg",
            "table": "recovery_principal_cache",
            "failure_table": "recovery_principal_cache_failure",
            "durable": true,
            "fallback": false
        }),
    );
    value
}

fn annotate_memory_fallback(mut value: Value, reason: Option<String>) -> Value {
    if value.is_null() {
        value = principal_recovery_cache_seed();
    }
    let etag = extract_cache_etag(&value);
    let contract_digest = calculate_contract_digest(&value);
    set_cache_metadata(&mut value, etag.as_deref(), &contract_digest);
    let object = ensure_object(&mut value);
    object.insert(
        "cache_mode".to_owned(),
        Value::String("process_memory_dev_fallback".to_owned()),
    );
    object.insert(
        "storage".to_owned(),
        json!({
            "kind": "process_memory",
            "durable": false,
            "fallback": true,
            "fallback_reason": reason
        }),
    );
    value
}

fn ensure_object(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = json!({
            "cached_snapshot": value.clone()
        });
    }
    value.as_object_mut().expect("principal cache object")
}

fn set_cache_metadata(value: &mut Value, etag: Option<&str>, contract_digest: &str) {
    let object = ensure_object(value);
    object.insert(
        "etag".to_owned(),
        etag.map_or(Value::Null, |value| Value::String(value.to_owned())),
    );
    object.insert(
        "contract_digest".to_owned(),
        Value::String(contract_digest.to_owned()),
    );
    object.entry("drift".to_owned()).or_insert_with(|| {
        json!({
            "state": "none",
            "last_detected_at": null
        })
    });
}

fn detect_drift(
    previous: Option<&PrincipalCacheRow>,
    current_etag: Option<&str>,
    current_contract_digest: &str,
) -> Option<Value> {
    let previous = previous?;
    let previous_etag = previous.etag.as_deref();
    let etag_changed = previous_etag.zip(current_etag).is_some_and(|(a, b)| a != b);
    let empty_digest = empty_contract_digest();
    let digest_changed = previous.contract_digest.as_deref().is_some_and(|previous| {
        previous != empty_digest
            && current_contract_digest != empty_digest
            && previous != current_contract_digest
    });

    if !etag_changed && !digest_changed {
        return None;
    }

    let failure_code = if digest_changed {
        "contract_digest_drift"
    } else {
        "etag_drift"
    };
    Some(json!({
        "state": "detected",
        "failure_code": failure_code,
        "detected_at": Utc::now().to_rfc3339(),
        "previous_etag": previous_etag,
        "current_etag": current_etag,
        "previous_contract_digest": previous.contract_digest.clone(),
        "current_contract_digest": current_contract_digest
    }))
}

fn apply_drift(value: &mut Value, drift: Value) {
    let failure_code = drift
        .get("failure_code")
        .and_then(Value::as_str)
        .unwrap_or("principal_cache_drift")
        .to_owned();
    let detected_at = drift
        .get("detected_at")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let object = ensure_object(value);
    let failure_count = object
        .get("failure_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    object.insert("drift".to_owned(), drift.clone());
    object.insert(
        "refresh_state".to_owned(),
        Value::String("drift_detected".to_owned()),
    );
    object.insert("failure_count".to_owned(), json!(failure_count));
    object.insert(
        "last_failure_at".to_owned(),
        Value::String(detected_at.clone()),
    );
    object.insert(
        "last_failure_code".to_owned(),
        Value::String(failure_code.clone()),
    );
    object.insert(
        "last_reason".to_owned(),
        Value::String("principal_cache_drift_detected".to_owned()),
    );

    let failure_entry = json!({
        "failure_code": failure_code,
        "reason": "principal_cache_drift_detected",
        "failed_at": detected_at,
        "details": drift
    });
    match object.get_mut("failure_log").and_then(Value::as_array_mut) {
        Some(log) => log.push(failure_entry),
        None => {
            object.insert("failure_log".to_owned(), json!([failure_entry]));
        }
    }
}

fn failure_event_to_record(
    previous: Option<&PrincipalCacheRow>,
    value: &Value,
) -> Option<(String, Option<String>, Value)> {
    let failure_code = value.get("last_failure_code")?.as_str()?.to_owned();
    let failed_at = value
        .get("last_failure_at")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let previous_failure_code = previous
        .and_then(|row| row.cache_state.get("last_failure_code"))
        .and_then(Value::as_str);
    let previous_failed_at = previous
        .and_then(|row| row.cache_state.get("last_failure_at"))
        .and_then(Value::as_str);

    if previous_failure_code == Some(failure_code.as_str())
        && previous_failed_at == failed_at.as_deref()
    {
        return None;
    }

    let reason = value
        .get("last_reason")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let details = json!({
        "failed_at": failed_at,
        "drift": value.get("drift").cloned().unwrap_or(Value::Null),
        "last_upstream_probe_result": value
            .get("last_upstream_probe_result")
            .cloned()
            .unwrap_or(Value::Null)
    });
    Some((failure_code, reason, details))
}

fn parse_timestamp(value: Option<&Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn extract_cache_etag(value: &Value) -> Option<String> {
    let mut etags = Vec::new();
    if let Some(etag) = value.get("etag").and_then(Value::as_str) {
        etags.push(etag.to_owned());
    }
    collect_cache_observation_strings(
        value,
        &["etag", "http_etag", "upstream_etag", "principal_etag"],
        &mut etags,
    );
    etags.retain(|value| !value.trim().is_empty());
    etags.sort();
    etags.dedup();
    match etags.len() {
        0 => None,
        1 => etags.into_iter().next(),
        _ => Some(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(etags.join("\n").as_bytes()))
        )),
    }
}

fn calculate_contract_digest(value: &Value) -> String {
    let mut contracts = Vec::new();
    collect_cache_observation_strings(
        value,
        &[
            "contract",
            "snapshot_contract",
            "expected_contract",
            "actual_contract",
        ],
        &mut contracts,
    );
    contracts.retain(|value| !value.trim().is_empty());
    contracts.sort();
    contracts.dedup();
    let payload = serde_json::to_vec(&contracts).unwrap_or_default();
    hex::encode(Sha256::digest(payload))
}

fn empty_contract_digest() -> String {
    hex::encode(Sha256::digest(b"[]"))
}

fn collect_cache_observation_strings(value: &Value, names: &[&str], out: &mut Vec<String>) {
    let looks_like_cache =
        value.get("cache_mode").is_some() || value.get("upstream_binding").is_some();
    if let Some(snapshot) = value.get("cached_snapshot") {
        collect_named_strings(snapshot, names, out);
    }
    if let Some(probe_result) = value.get("last_upstream_probe_result") {
        collect_named_strings(probe_result, names, out);
    }
    if !looks_like_cache && out.is_empty() {
        collect_named_strings(value, names, out);
    }
}

fn collect_named_strings(value: &Value, names: &[&str], out: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if names.contains(&key.as_str())
                    && let Some(value) = value.as_str()
                {
                    out.push(value.to_owned());
                }
                collect_named_strings(value, names, out);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_named_strings(value, names, out);
            }
        }
        _ => {}
    }
}

pub fn default_principal_cache_service() -> PrincipalCacheServiceHandle {
    Arc::new(InMemoryPrincipalCacheService)
}

pub fn durable_principal_cache_service(
    pool: DieselPool<AsyncPgConnection>,
) -> PrincipalCacheServiceHandle {
    Arc::new(PgPrincipalCacheService::new(pool))
}
