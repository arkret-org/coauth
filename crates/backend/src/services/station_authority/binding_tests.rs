//! Storage components using public originals captured from actual native SUTs.
//! These tests never certify new native operation coverage.

use arkret_models_identity::{AuthenticatedServiceResolution, ResolutionMethodHistoryEvidence};
use coauth_config::{ArkretConfig, StationConfig};
use coauth_data::storage::station_trust::{NewStationTrustEnrollment, StationTrustSource};
use coauth_data::{RepositoryAccess as _, RepositoryFactory as _, SystemClock};
use coauth_storage_postgres::PgRepositoryFactory;

use super::pinned_repository::PinnedIssuerRepositoryFactory;
use crate::services::station_trust::native_delegation::bind_native_station_identity;

fn originals() -> Vec<AuthenticatedServiceResolution> {
    serde_json::from_str(include_str!(
        "../station_trust/fixtures/native_station_resolutions.json"
    ))
    .unwrap()
}

fn config_for(resolution: &AuthenticatedServiceResolution, name: &str) -> ArkretConfig {
    let projection = resolution.projection().unwrap();
    ArkretConfig {
        stations: vec![StationConfig {
            name: name.to_owned(),
            endpoint: url::Url::parse(&projection.base_url).unwrap(),
            internal_authority_shared_secret: None,
            embedded_webvh_registration_bearer: None,
            trust_domain: None,
        }],
        owning_station: Some(name.to_owned()),
        ..Default::default()
    }
}

#[tokio::test]
async fn genuine_native_method_advance_relocates_original_pin_and_rejects_rollback() {
    let database = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("isolated PostgreSQL is required");
    let factory = PgRepositoryFactory::new(database.clone());
    let originals: Vec<AuthenticatedServiceResolution> = serde_json::from_str(include_str!(
        "../station_trust/fixtures/native_station_continuity.json"
    ))
    .unwrap();
    let before = &originals[0];
    let after = &originals[1];
    assert_eq!(before.service_id, after.service_id);
    let old_config = config_for(before, "continuous-owner");
    let new_config = config_for(after, "continuous-owner");
    let initial = bind_native_station_identity(&factory, &old_config, &before.service_id, before)
        .await
        .unwrap();
    let advanced = bind_native_station_identity(&factory, &new_config, &after.service_id, after)
        .await
        .unwrap();
    assert_eq!(initial.enrolled_at, advanced.enrolled_at);
    assert_ne!(initial.did, advanced.did);
    assert_ne!(initial.canonical_endpoint, advanced.canonical_endpoint);
    assert_ne!(initial.method_history_head, advanced.method_history_head);
    assert_ne!(initial.version_id, advanced.version_id);
    assert!(
        bind_native_station_identity(&factory, &old_config, &before.service_id, before)
            .await
            .is_err()
    );
    let replay = bind_native_station_identity(&factory, &new_config, &after.service_id, after)
        .await
        .unwrap();
    assert_eq!(advanced.enrolled_at, replay.enrolled_at);
    assert_eq!(advanced.method_history_head, replay.method_history_head);
    let old_factory = PinnedIssuerRepositoryFactory::new(
        Box::new(PgRepositoryFactory::new(database.clone())),
        initial,
    );
    assert!(old_factory.read().await.is_err());
    assert!(old_factory.create().await.is_err());
    let current = PinnedIssuerRepositoryFactory::new(
        Box::new(PgRepositoryFactory::new(database.clone())),
        replay,
    );
    current.read().await.unwrap().cancel().await.unwrap();
    current.create().await.unwrap().cancel().await.unwrap();
}

#[tokio::test]
async fn original_native_pin_replays_and_rejects_identity_endpoint_and_history_conflicts() {
    let database = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("isolated PostgreSQL is required");
    let factory = PgRepositoryFactory::new(database.clone());
    let originals = originals();
    let original = &originals[0];
    let config = config_for(original, "native-owner");
    let first = bind_native_station_identity(&factory, &config, &original.service_id, original)
        .await
        .unwrap();
    let replay = bind_native_station_identity(&factory, &config, &original.service_id, original)
        .await
        .unwrap();
    assert_eq!(first.service_id, replay.service_id);
    assert_eq!(first.method_history_head, replay.method_history_head);
    assert_eq!(first.enrolled_at, replay.enrolled_at);
    assert_eq!(
        config
            .runtime_owning_station_identity
            .get()
            .unwrap()
            .station_id,
        original.service_id
    );

    let replacement = &originals[1];
    let changed_endpoint = config_for(replacement, "native-owner");
    assert!(
        bind_native_station_identity(
            &factory,
            &changed_endpoint,
            &replacement.service_id,
            replacement
        )
        .await
        .is_err()
    );
    let other_config = config_for(replacement, "other-owner");
    bind_native_station_identity(
        &factory,
        &other_config,
        &replacement.service_id,
        replacement,
    )
    .await
    .unwrap();
    assert!(
        bind_native_station_identity(
            &factory,
            &changed_endpoint,
            &replacement.service_id,
            replacement
        )
        .await
        .is_err()
    );

    // Rejected corruption is a negative input, never replacement authority.
    let mut missing = original.clone();
    let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
        &mut missing.method_history_evidence
    else {
        panic!("actual WebVH original")
    };
    log_entries.clear();
    assert!(
        bind_native_station_identity(&factory, &config, &original.service_id, &missing)
            .await
            .is_err()
    );
    let mut repo = factory.read().await.unwrap();
    let retained = repo
        .station_trust()
        .find_by_name("native-owner")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.service_id, first.service_id);
    assert_eq!(retained.method_history_head, first.method_history_head);
    assert_eq!(retained.version_id, first.version_id);
    assert_eq!(
        repo.station_trust()
            .list_audits("native-owner", 10)
            .await
            .unwrap()
            .len(),
        1
    );
    repo.cancel().await.unwrap();
}

#[tokio::test]
async fn issuer_pin_read_serializes_revocation_and_all_later_transactions_fail_closed() {
    let database = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("isolated PostgreSQL is required");
    let raw = PgRepositoryFactory::new(database.clone());
    let original = originals().remove(0);
    let config = config_for(&original, "native-owner");
    let binding = bind_native_station_identity(&raw, &config, &original.service_id, &original)
        .await
        .unwrap();
    let guarded = PinnedIssuerRepositoryFactory::new(Box::new(raw.clone()), binding);
    let held = guarded.read().await.unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let mut revoke = tokio::spawn(async move {
        let mut repo = raw.create().await.unwrap();
        started.send(()).unwrap();
        assert!(repo.station_trust().revoke("native-owner").await.unwrap());
        repo.save().await.unwrap();
    });
    ready.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), &mut revoke)
            .await
            .is_err(),
        "pin revocation must wait for the actual issuer transaction"
    );
    held.cancel().await.unwrap();
    revoke.await.unwrap();
    assert!(guarded.create().await.is_err());
    assert!(guarded.read().await.is_err());
}

#[tokio::test]
async fn issuer_rejects_an_operator_replacement_by_another_genuinely_accepted_station() {
    let database = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("isolated PostgreSQL is required");
    let raw = PgRepositoryFactory::new(database.clone());
    let originals = originals();
    let first = &originals[0];
    let config = config_for(first, "native-owner");
    let binding = bind_native_station_identity(&raw, &config, &first.service_id, first)
        .await
        .unwrap();
    let guarded = PinnedIssuerRepositoryFactory::new(Box::new(raw.clone()), binding);
    let next = &originals[1];
    arkret_identity::verify_authenticated_service_resolution_history(
        next,
        &next.service_id,
        chrono::Utc::now(),
    )
    .unwrap();
    let next = next.projection().unwrap();
    let mut repo = raw.create().await.unwrap();
    assert!(
        repo.station_trust()
            .replace(
                &SystemClock::default(),
                "native-owner",
                &first.service_id,
                NewStationTrustEnrollment {
                    name: "native-owner".to_owned(),
                    canonical_endpoint: next.base_url,
                    service_id: next.service_id,
                    did: next.did,
                    method_history_head: next.method_history_head,
                    version_id: next.version_id,
                    source: StationTrustSource::OperatorReplacement,
                }
            )
            .await
            .unwrap()
    );
    repo.save().await.unwrap();
    assert!(guarded.create().await.is_err());
    assert!(guarded.read().await.is_err());
}
