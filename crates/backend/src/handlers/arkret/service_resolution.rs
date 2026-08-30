use arkret_identity::service_identity::DidCoreIdentityBundle;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, ServiceResolutionRecord,
    ServiceResolutionRecordCore,
};
use arkret_wire::{DidCoreId, DidUrl, Hash};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel_async::RunQueryDsl;
use salvo::oapi::extract::PathParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ArkretRouteError, service_id_for};
use crate::app_state::DepotExt as _;
use crate::handlers::common::DepotExt;

const RESOLUTION_REFRESH_SECONDS: i64 = 300;
const RESOLUTION_TTL_SECONDS: i64 = 600;
const MAX_RESOLUTION_CAS_ATTEMPTS: usize = 8;
const MAX_AUTHENTICATED_RESOLUTION_BYTES: usize = 1024 * 1024;
const STORED_RESOLUTION_SCHEMA: &str = "coauth.service_resolution.current.v1";

#[derive(QueryableByName)]
struct IdentityRow {
    #[diesel(sql_type = Jsonb)]
    identity: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCurrentResolution {
    schema: String,
    canonical_digest: Hash,
    record: ServiceResolutionRecord,
}

struct CanonicalAuthenticatedResolution(Vec<u8>);

impl Scribe for CanonicalAuthenticatedResolution {
    fn render(self, response: &mut Response) {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store, no-transform"),
        );
        if let Err(error) = response.write_body(self.0) {
            tracing::error!(%error, "failed to write canonical service-resolution response");
            response.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}

impl salvo::oapi::EndpointOutRegister for CanonicalAuthenticatedResolution {
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        use salvo::oapi::{Response as OapiResponse, ToSchema};

        operation.responses.insert(
            "200",
            OapiResponse::new("Authenticated current service resolution").add_content(
                "application/json",
                AuthenticatedServiceResolution::to_schema(components),
            ),
        );
    }
}

fn internal(message: impl Into<String>) -> ArkretRouteError {
    ArkretRouteError::Internal(Box::new(std::io::Error::other(message.into())))
}

fn canonical_digest(value: &impl Serialize) -> Result<Hash, ArkretRouteError> {
    Hash::new(
        arkret_canonical::canonical_sha256(value)
            .map_err(|error| internal(format!("canonical digest failed: {error}")))?,
    )
    .map_err(|error| internal(format!("canonical digest is invalid: {error}")))
}

fn canonical_base_url(description: &ServiceDescribe) -> Result<String, ArkretRouteError> {
    let binding = description
        .transport_bindings
        .iter()
        .find(|binding| binding.kind() == arkret_wire::BindingKind::HttpJson)
        .ok_or_else(|| internal("ServiceDescribe has no http_json binding"))?;
    let canonical = CanonicalServiceUrl::canonicalize(binding.base_url())
        .map_err(|error| internal(format!("ServiceDescribe base URL is invalid: {error}")))?;
    canonical
        .require_https()
        .map_err(|error| internal(format!("service-resolution base URL is not HTTPS: {error}")))?;
    Ok(canonical.to_string())
}

fn route_binding_digest(description: &ServiceDescribe) -> Result<Hash, ArkretRouteError> {
    arkret_models_identity::route_binding_describe_digest(
        &description.service_id,
        description.service_kind.as_str(),
        &description.service_resolution,
        &canonical_base_url(description)?,
    )
    .map_err(|error| internal(format!("ServiceDescribe route binding is invalid: {error}")))
}

fn current_record_url(base_url: &str, service_id: &DidCoreId) -> Result<String, ArkretRouteError> {
    let base = url::Url::parse(base_url)
        .map_err(|error| internal(format!("service base URL is invalid: {error}")))?;
    base.join(&arkret_models_identity::canonical_service_current_record_path(service_id))
        .map(|url| url.to_string())
        .map_err(|error| internal(format!("service current-record URL is invalid: {error}")))
}

fn webvh_resolution_event_ref(log_head_digest: &str) -> Result<String, ArkretRouteError> {
    let digest = log_head_digest
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| internal("durable WebVH head is not a sha256 digest"))?;
    Ok(format!(
        "did-webvh-entry-sha256:{}",
        digest.to_ascii_lowercase()
    ))
}

fn service_assertion_method(
    bundle: &DidCoreIdentityBundle,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<DidUrl, ArkretRouteError> {
    let expected = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key.verifying_key().as_bytes(),
    );
    let document = &bundle.identity.did_document;
    let method = document
        .verification_method
        .iter()
        .find(|method| {
            method.public_key_multibase == expected
                && document.assertion_method.iter().any(|id| id == &method.id)
        })
        .ok_or_else(|| internal("runtime signer is not a durable service assertion method"))?;
    DidUrl::new(method.id.clone())
        .map_err(|error| internal(format!("service assertion method is invalid: {error}")))
}

fn decode_current(identity: &Value) -> Result<Option<StoredCurrentResolution>, ArkretRouteError> {
    let Some(value) = identity.get("service_resolution") else {
        return Ok(None);
    };
    let stored: StoredCurrentResolution = serde_json::from_value(value.clone())
        .map_err(|error| internal(format!("durable service resolution is invalid: {error}")))?;
    if stored.schema != STORED_RESOLUTION_SCHEMA
        || canonical_digest(&stored.record)? != stored.canonical_digest
    {
        return Err(internal(
            "durable service resolution schema or digest is invalid",
        ));
    }
    Ok(Some(stored))
}

async fn load_current(
    pool: &diesel_async::pooled_connection::deadpool::Pool<diesel_async::AsyncPgConnection>,
) -> Result<Option<StoredCurrentResolution>, ArkretRouteError> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| internal(format!("service-resolution database unavailable: {error}")))?;
    let row = diesel::sql_query("SELECT identity FROM service_identity WHERE id = 1")
        .get_result::<IdentityRow>(&mut *connection)
        .await
        .map_err(|error| internal(format!("durable service identity lookup failed: {error}")))?;
    decode_current(&row.identity)
}

async fn compare_and_set_current(
    pool: &diesel_async::pooled_connection::deadpool::Pool<diesel_async::AsyncPgConnection>,
    predecessor: Option<&Hash>,
    record: &ServiceResolutionRecord,
) -> Result<bool, ArkretRouteError> {
    let stored = StoredCurrentResolution {
        schema: STORED_RESOLUTION_SCHEMA.to_owned(),
        canonical_digest: canonical_digest(record)?,
        record: record.clone(),
    };
    let value = serde_json::to_value(stored)
        .map_err(|error| internal(format!("service resolution encoding failed: {error}")))?;
    let predecessor = predecessor.map(|digest| digest.as_ref().to_owned());
    let mut connection = pool
        .get()
        .await
        .map_err(|error| internal(format!("service-resolution database unavailable: {error}")))?;
    let changed = diesel::sql_query(
        "UPDATE service_identity \
         SET identity = jsonb_set(identity, '{service_resolution}', $1, true), updated_at = now() \
         WHERE id = 1 AND (($2 IS NULL AND identity->'service_resolution' IS NULL) \
            OR identity->'service_resolution'->>'canonical_digest' = $2)",
    )
    .bind::<Jsonb, _>(value)
    .bind::<Nullable<Text>, _>(predecessor)
    .execute(&mut *connection)
    .await
    .map_err(|error| internal(format!("service resolution persist failed: {error}")))?;
    Ok(changed == 1)
}

async fn ensure_current_record(
    depot: &Depot,
    description: &ServiceDescribe,
    bundle: &DidCoreIdentityBundle,
) -> Result<ServiceResolutionRecord, ArkretRouteError> {
    let pool = depot
        .get_pg_pool()
        .ok_or_else(|| internal("PostgreSQL pool is unavailable"))?;
    let identity = &bundle.identity.identity;
    if description.service_kind != arkret_wire::ServiceKind::Station
        || description.service_id != identity.service_id
        || description.service_resolution.did != identity.did
        || description.service_resolution.version_id != identity.version_id
    {
        return Err(internal(
            "ServiceDescribe does not match the durable AuthServer identity",
        ));
    }
    let computed_history_head = canonical_digest(
        bundle
            .webvh_history_entries
            .last()
            .ok_or_else(|| internal("durable service WebVH history is empty"))?,
    )?;
    let history_head = &bundle.identity.registration_receipt.log_head_digest;
    if computed_history_head.as_ref() != history_head
        || description.service_resolution.method_history_head != *history_head
    {
        return Err(internal(
            "ServiceDescribe, durable WebVH history, and registration receipt do not share one head",
        ));
    }

    let base_url = canonical_base_url(description)?;
    if base_url != identity.registration_key.public_base_url().as_str() {
        return Err(internal(
            "ServiceDescribe base URL differs from the accepted service registration",
        ));
    }
    let record_url = current_record_url(&base_url, &identity.service_id)?;
    let describe_digest = route_binding_digest(description)?;
    let resolution_event_ref = webvh_resolution_event_ref(history_head)?;
    let signing_seed = depot
        .key_store()?
        .service_identity_seed()
        .map_err(|error| internal(format!("service identity key is unavailable: {error}")))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
    let verification_method = service_assertion_method(bundle, &signing_key)?;
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());

    for _ in 0..MAX_RESOLUTION_CAS_ATTEMPTS {
        let current = load_current(pool).await?;
        if let Some(current) = current.as_ref()
            && current.record.record.service_id == identity.service_id
            && current.record.record.did == identity.did
            && current.record.record.service_kind == arkret_wire::ServiceKind::Station.as_str()
            && current.record.record.method_history_head == *history_head
            && current.record.record.version_id == identity.version_id
            && current.record.record.resolution_event_ref == resolution_event_ref
            && current.record.record.current_record_url == record_url
            && current.record.record.base_url == base_url
            && current.record.record.describe_digest == describe_digest
            && current.record.record.refresh_after > now
            && current.record.record.expires_at > now
        {
            return Ok(current.record.clone());
        }
        if current.as_ref().is_some_and(|current| {
            current.record.record.service_id != identity.service_id
                || current.record.record.did != identity.did
        }) {
            return Err(internal(
                "durable service resolution belongs to another identity",
            ));
        }
        let predecessor = current.as_ref().map(|current| &current.canonical_digest);
        let record_sequence = current.as_ref().map_or(Ok(0), |current| {
            current
                .record
                .record
                .record_sequence
                .checked_add(1)
                .ok_or_else(|| internal("service resolution sequence is exhausted"))
        })?;
        let core = ServiceResolutionRecordCore {
            service_id: identity.service_id.clone(),
            service_kind: arkret_wire::ServiceKind::Station.as_str().to_owned(),
            did: identity.did.clone(),
            method_history_head: history_head.clone(),
            version_id: identity.version_id.clone(),
            resolution_event_ref: resolution_event_ref.clone(),
            record_sequence,
            previous_record_digest: predecessor.cloned(),
            current_record_url: record_url.clone(),
            base_url: base_url.clone(),
            describe_digest: describe_digest.clone(),
            issued_at: now,
            refresh_after: now + Duration::seconds(RESOLUTION_REFRESH_SECONDS),
            expires_at: now + Duration::seconds(RESOLUTION_TTL_SECONDS),
        };
        let record = arkret_signatures::service_resolution::sign_service_resolution_record(
            core,
            verification_method.clone(),
            &signing_key,
        )
        .map_err(|error| internal(format!("service resolution signing failed: {error}")))?;
        if compare_and_set_current(pool, predecessor, &record).await? {
            return Ok(record);
        }
    }
    Err(internal("service resolution changed concurrently"))
}

fn validate_requested_service_id(
    requested: &str,
    expected: &DidCoreId,
) -> Result<(), ArkretRouteError> {
    let requested = DidCoreId::new(requested.to_owned()).map_err(|_| ArkretRouteError::NotFound)?;
    if &requested != expected {
        return Err(ArkretRouteError::NotFound);
    }
    Ok(())
}

#[salvo::oapi::endpoint(operation_id = "ak.open.service.read.resolution.v1", tags("identity"))]
pub async fn open_service_resolution(
    service_id: PathParam<String>,
    depot: &Depot,
) -> Result<CanonicalAuthenticatedResolution, ArkretRouteError> {
    let arkret_config = depot.arkret_config()?;
    validate_requested_service_id(&service_id.into_inner(), &service_id_for(&arkret_config))?;
    let description = super::service_describe_from_depot(depot).await?;
    let pool = depot
        .get_pg_pool()
        .ok_or_else(|| internal("PostgreSQL pool is unavailable"))?;
    let bundle = crate::services::service_identity::load_durable_identity_bundle(pool)
        .await
        .map_err(|error| internal(format!("durable service identity unavailable: {error}")))?;
    let runtime = arkret_config
        .runtime_service_identity
        .state()
        .identity()
        .cloned()
        .ok_or_else(|| internal("runtime service identity is unavailable"))?;
    if runtime != bundle.identity.identity {
        return Err(internal(
            "runtime service identity differs from durable service identity",
        ));
    }
    let record = ensure_current_record(depot, &description, &bundle).await?;
    let normalized_document: DidDocument = serde_json::from_value(
        serde_json::to_value(&bundle.identity.did_document)
            .map_err(|error| internal(format!("service DID document encoding failed: {error}")))?,
    )
    .map_err(|error| {
        internal(format!(
            "service DID document normalization failed: {error}"
        ))
    })?;
    let log_entries = bundle
        .webvh_history_entries
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| internal(format!("service WebVH history encoding failed: {error}")))?;
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let authenticated: AuthenticatedServiceResolution =
        arkret_identity::build_authenticated_webvh_service_resolution(
            record,
            normalized_document,
            log_entries,
            Vec::new(),
            now,
        )
        .map_err(|error| {
            internal(format!(
                "authenticated service resolution is invalid: {error}"
            ))
        })?;
    let body = arkret_canonical::canonical_json_bytes(&authenticated)
        .map_err(|error| internal(format!("service resolution encoding failed: {error}")))?;
    if body.len() > MAX_AUTHENTICATED_RESOLUTION_BYTES {
        return Err(internal("authenticated service resolution exceeds 1 MiB"));
    }
    Ok(CanonicalAuthenticatedResolution(body))
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::service_identity::ServiceRegistrationKey;
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, prepare_service_registration_inception_with_did_key_seed,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn wrong_service_id_is_not_found() {
        let expected = DidCoreId::new("ak:did_core:webvh:zExpected").unwrap();
        assert!(matches!(
            validate_requested_service_id("ak:did_core:webvh:zOther", &expected),
            Err(ArkretRouteError::NotFound)
        ));
        assert!(matches!(
            validate_requested_service_id("not-a-service-id", &expected),
            Err(ArkretRouteError::NotFound)
        ));
    }

    #[test]
    fn canonical_operation_selector_matches_the_exact_route() {
        let operation = arkret_wire::ServiceOperationId::OpenServiceReadResolutionV1;
        assert!(super::super::supports_advertised_http_operation(operation));
        assert!(operation.matches_http_request(
            "GET",
            "/_arkret/open/services/ak%3Adid_core%3Awebvh%3AzExpected/resolution"
        ));
        assert!(!operation.matches_http_request(
            "POST",
            "/_arkret/open/services/ak%3Adid_core%3Awebvh%3AzExpected/resolution"
        ));
    }

    #[test]
    fn canonical_authenticated_body_verifies_from_retained_history() {
        let signing_seed = [7_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let registration_key = ServiceRegistrationKey::new(
            arkret_wire::ServiceKind::Station,
            CanonicalServiceUrl::canonicalize("https://auth.example/").unwrap(),
        )
        .unwrap();
        let mut rng = ChaCha20Rng::from_seed([3_u8; 32]);
        let prepared = prepare_service_registration_inception_with_did_key_seed(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.example/".parse().unwrap(),
                registration_key: &registration_key,
                also_known_as: &[],
                version_time: "2026-08-29T00:00:00Z".parse().unwrap(),
                did_key_fragment: Some("service-key"),
            },
            &signing_seed,
        )
        .unwrap();
        let operation = prepared.service_registration_operation().unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&operation.state.id).unwrap();
        let now: chrono::DateTime<Utc> = "2026-08-29T00:01:00Z".parse().unwrap();
        let head = operation.log_head_digest().unwrap();
        let core = ServiceResolutionRecordCore {
            service_id: service_id.clone(),
            service_kind: arkret_wire::ServiceKind::Station.as_str().to_owned(),
            did: operation.state.id.clone(),
            method_history_head: head.clone(),
            version_id: operation.version_id.clone(),
            resolution_event_ref: webvh_resolution_event_ref(&head).unwrap(),
            record_sequence: 0,
            previous_record_digest: None,
            current_record_url: format!(
                "https://auth.example{}",
                arkret_models_identity::canonical_service_current_record_path(&service_id)
            ),
            base_url: "https://auth.example/".to_owned(),
            describe_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            issued_at: now,
            refresh_after: now + Duration::seconds(300),
            expires_at: now + Duration::seconds(600),
        };
        let record = arkret_signatures::service_resolution::sign_service_resolution_record(
            core,
            DidUrl::new(format!("{}#service-key", operation.state.id)).unwrap(),
            &signing_key,
        )
        .unwrap();
        let normalized_document: DidDocument =
            serde_json::from_value(serde_json::to_value(&operation.state).unwrap()).unwrap();
        let authenticated = arkret_identity::build_authenticated_webvh_service_resolution(
            record,
            normalized_document,
            vec![serde_json::to_value(operation).unwrap()],
            Vec::new(),
            now,
        )
        .unwrap();
        let canonical = arkret_canonical::canonical_json_bytes(&authenticated).unwrap();
        let decoded: AuthenticatedServiceResolution = serde_json::from_slice(&canonical).unwrap();

        arkret_identity::verify_authenticated_service_resolution_history(
            &decoded,
            &service_id,
            now,
        )
        .unwrap();
        assert_eq!(
            canonical,
            arkret_canonical::canonical_json_bytes(&decoded).unwrap()
        );
    }
}
