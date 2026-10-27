//! Bind original same-Station custody using its actual local method proof.

use arkret_models_identity::{AuthenticatedServiceResolution, ServiceMethodState};
use arkret_wire::{DidCoreId, ServiceKind};
use coauth_config::ArkretConfig;
use coauth_data::storage::station_trust::{
    NewStationTrustAudit, StationTrustAuditAction, StationTrustEnrollment, StationTrustSource,
    StationTrustVerificationInput,
};
use coauth_data::{RepositoryAccess as _, RepositoryFactory, SystemClock};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use super::{
    VerifiedStationIdentity, canonical_endpoint_key, delegate_owning_station_identity,
    enrollment_params, same_enrollment_tuple, shared,
};

/// Validate the owning Station against the original AA pin and persist only
/// method-native continuity. No listener, new pin table or private HTTP is used.
pub(crate) async fn bind_native_station_identity(
    factory: &(dyn RepositoryFactory + Send + Sync),
    config: &ArkretConfig,
    expected_id: &DidCoreId,
    resolution: &AuthenticatedServiceResolution,
) -> anyhow::Result<StationTrustEnrollment> {
    anyhow::ensure!(
        matches!(
            &resolution.method_history_evidence,
            arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog { .. }
        ),
        "native Station delegation requires complete WebVH method history"
    );
    let server = config
        .owning_station()
        .ok_or_else(|| anyhow::anyhow!("native issuer requires its owning Station"))?;
    let endpoint = canonical_endpoint_key(&server.endpoint)
        .ok_or_else(|| anyhow::anyhow!("native issuer Station endpoint is invalid"))?;
    let mut repo = factory.create().await?;
    // Use the same name/endpoint conflict rule as network preflight. These
    // reads do not lock: a later verification write uses the existing CAS,
    // avoiding concurrent SHARE-to-UPDATE lock upgrades during bootstrap.
    let by_name = repo.station_trust().find_by_name(&server.name).await?;
    let by_endpoint = repo.station_trust().find_by_endpoint(&endpoint).await?;
    let original = match (by_name, by_endpoint) {
        (None, None) => None,
        (Some(name), None) => Some(name),
        (Some(name), Some(at_endpoint)) if same_enrollment_tuple(&name, &at_endpoint) => Some(name),
        _ => anyhow::bail!("native issuer Station name and endpoint bind different enrollments"),
    };
    if let Some(original) = &original {
        anyhow::ensure!(
            &original.service_id == expected_id,
            "native issuer Station identity differs from the original AA enrollment"
        );
        verify_floor(resolution, original)?;
    } else {
        arkret_identity::verify_authenticated_service_resolution_history(
            resolution,
            expected_id,
            chrono::Utc::now(),
        )?;
    }
    let projection = resolution.projection()?;
    anyhow::ensure!(
        projection.service_id == *expected_id
            && projection.service_kind == ServiceKind::Station.as_str()
            && projection.base_url == endpoint,
        "native Station method proof does not bind the configured endpoint and role"
    );
    let verified = VerifiedStationIdentity {
        current_document: resolution.normalized_did_document.clone(),
        service_id: projection.service_id,
        did: projection.did,
        method_history_head: projection.method_history_head,
        version_id: projection.version_id,
        canonical_endpoint: endpoint.clone(),
    };
    let mut new_enrollment = false;
    let existing = if let Some(original) = original {
        Some(original)
    } else {
        let enrollment = repo
            .station_trust()
            .enroll(
                &SystemClock::default(),
                enrollment_params(server, &verified, StationTrustSource::AutomaticVerified),
            )
            .await?;
        match enrollment {
            Some(_) => {
                new_enrollment = true;
                None
            }
            None => {
                let name = repo
                    .station_trust()
                    .find_by_name(&server.name)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!("concurrent native issuer enrollment changed its name")
                    })?;
                let at_endpoint = repo
                    .station_trust()
                    .find_by_endpoint(&endpoint)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!("concurrent native issuer enrollment changed its endpoint")
                    })?;
                anyhow::ensure!(
                    same_enrollment_tuple(&name, &at_endpoint) && name.service_id == *expected_id,
                    "concurrent native issuer enrollment changed its Station identity"
                );
                verify_floor(resolution, &name)?;
                Some(name)
            }
        }
    };
    let relocated = existing
        .as_ref()
        .is_some_and(|old| old.canonical_endpoint != endpoint);
    if let Some(old) = &existing {
        let applied = if relocated {
            repo.station_trust()
                .relocate_verified(
                    &SystemClock::default(),
                    &server.name,
                    &old.service_id,
                    &old.canonical_endpoint,
                    &old.method_history_head,
                    enrollment_params(server, &verified, StationTrustSource::AutomaticVerified),
                )
                .await?
        } else {
            repo.station_trust()
                .record_verification(StationTrustVerificationInput {
                    clock: &SystemClock::default(),
                    name: &server.name,
                    canonical_endpoint: &endpoint,
                    expected_method_history_head: &old.method_history_head,
                    did: &verified.did,
                    method_history_head: &verified.method_history_head,
                    version_id: &verified.version_id,
                })
                .await?
        };
        anyhow::ensure!(
            applied,
            "native issuer original Station binding changed concurrently"
        );
    }
    if new_enrollment || relocated {
        repo.station_trust()
            .record_audit(
                &mut ChaCha20Rng::from_entropy(),
                &SystemClock::default(),
                NewStationTrustAudit {
                    enrollment_name: server.name.clone(),
                    action: if new_enrollment {
                        StationTrustAuditAction::Enrolled
                    } else {
                        StationTrustAuditAction::EndpointRelocated
                    },
                    service_id: Some(verified.service_id.clone()),
                    previous_service_id: None,
                    detail: format!("verified native same-Station method proof at {endpoint}"),
                },
            )
            .await?;
    }
    let bound = repo
        .station_trust()
        .find_by_name(&server.name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("native issuer Station enrollment disappeared"))?;
    repo.save().await?;
    shared().note_verified(&server.endpoint, verified.service_id.clone());
    delegate_owning_station_identity(config, server, verified.service_id, verified.did);
    Ok(bound)
}

fn verify_floor(
    resolution: &AuthenticatedServiceResolution,
    old: &StationTrustEnrollment,
) -> anyhow::Result<()> {
    arkret_identity::verify_service_resolution_floor(
        resolution,
        &ServiceMethodState {
            service_id: old.service_id.clone(),
            service_kind: ServiceKind::Station.as_str().to_owned(),
            did: old.did.clone(),
            method_history_head: old.method_history_head.clone(),
            version_id: old.version_id.clone(),
            verified_at: old.last_verified_at,
        },
    )?;
    Ok(())
}
