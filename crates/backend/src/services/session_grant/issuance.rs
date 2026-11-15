use arkret_canonical::format_timestamp_canonical;
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantCredentialClass, SessionGrantHolderBinding,
    SessionGrantMetadata, SessionGrantProofKind, SessionGrantScope,
};
use coauth_config::ArkretConfig;
use coauth_data::LocalAccountId;

use super::*;
use crate::services::station_trust::owning_station_id_for;

#[cfg(test)]
pub(crate) fn issue_session_grant(
    rng: &mut (dyn rand_core::CryptoRngCore + Send),
    clock: &dyn coauth_data::Clock,
    url_builder: &coauth_data::UrlBuilder,
    arkret_config: &ArkretConfig,
    input: TestGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    use arkret_identifiers::{DidCoreId, EventId};
    use arkret_models_identity::SessionGrantDeviceBinding;
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let seed = SessionGrantIssuanceSeed::allocate(
        rng,
        input.browser_session.id.to_string(),
        now,
        now + arkret_config.session_grant_ttl,
    )?;
    let canonical_key =
        CanonicalSessionPublicJwk::new(serde_json::to_string(&input.session_public_key)?)?;
    let device_binding = SessionGrantDeviceBinding {
        device_id: input.device_id.clone(),
        authorization_event_id: EventId::new(
            "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        )?,
        model_generation_ref: 1,
    };
    issue_session_grant_for_audience(
        &seed,
        arkret_config,
        HumanGrantIssuance {
            browser_session: input.browser_session,
            session_public_key: input.session_public_key,
            audience_id: DidCoreId::new(crate::services::station_trust::required_audience_for(
                url_builder,
                arkret_config,
            ))?,
            device_id: input.device_id,
            scopes: input.scopes,
            subject_override: Some(&DidCoreId::new(input.subject_id)?),
            account_id: input.account_id,
            dpop_jkt: canonical_key.thumbprint_sha256()?,
            device_binding,
            proof_kind: SessionGrantProofKind::AccountHandoff,
        },
    )
}

pub(crate) fn issue_session_grant_for_audience(
    seed: &SessionGrantIssuanceSeed,
    config: &ArkretConfig,
    input: HumanGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let subject_id = input
        .subject_override
        .cloned()
        .ok_or(SessionGrantError::PrincipalUnknown)?;
    if input.account_id.principal_id != subject_id
        || input.account_id.station_id != input.audience_id
    {
        return Err(SessionGrantError::PrincipalUnknown);
    }
    let mut scopes = input.scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let metadata = SessionGrantMetadata {
        id: seed.grant_id.clone(),
        issuer_id: owning_station_id_for(config),
        account_id: input.account_id.clone(),
        device_id: Some(input.device_id.clone()),
        audience_id: input.audience_id,
        scopes,
        not_before: seed.not_before,
        expires_at: seed.expires_at,
        session_id: seed.session_id.clone(),
        session_public_key: CanonicalSessionPublicJwk::new(serde_json::to_string(
            &input.session_public_key,
        )?)?,
        cnf_jkt: input.dpop_jkt,
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::HumanDevice {
            device_binding: input.device_id.to_string(),
        },
        device_binding: Some(input.device_binding),
        proof_kind: Some(input.proof_kind),
        scope_details: None,
    };
    material(
        seed,
        metadata,
        LocalAccountId::new(input.browser_session.user.id.to_string())?,
    )
}

pub(crate) fn issue_recovery_session_grant_for_audience(
    seed: &SessionGrantIssuanceSeed,
    config: &ArkretConfig,
    input: RecoveryGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    if &input.account_id.principal_id != input.subject_id
        || input.account_id.station_id != input.audience_id
    {
        return Err(SessionGrantError::PrincipalUnknown);
    }
    let mut scopes = input.scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let metadata = SessionGrantMetadata {
        id: seed.grant_id.clone(),
        issuer_id: owning_station_id_for(config),
        account_id: input.account_id.clone(),
        device_id: Some(input.device_id.clone()),
        audience_id: input.audience_id,
        scopes,
        not_before: seed.not_before,
        expires_at: seed.expires_at,
        session_id: seed.session_id.clone(),
        session_public_key: CanonicalSessionPublicJwk::new(serde_json::to_string(
            &input.session_public_key,
        )?)?,
        cnf_jkt: input.dpop_jkt,
        credential_class: SessionGrantCredentialClass::RecoverySession,
        holder_binding: SessionGrantHolderBinding::RecoveryCandidateDevice {
            device_id: input.device_id,
        },
        device_binding: None,
        proof_kind: Some(SessionGrantProofKind::AccountHandoff),
        scope_details: None,
    };
    material(seed, metadata, input.local_account_id)
}

/// Allocate no credential here: reservation already fixed the opaque bytes and record id.
pub(crate) fn mint_agent_session_grant(
    seed: &SessionGrantIssuanceSeed,
    config: &ArkretConfig,
    input: AgentGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let mut scopes = input.scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let mut scope = input.scope_details;
    for field in ["agent_id", "principal_id", "subject_id", "audience_id"] {
        scope.remove(field);
    }
    let scope: SessionGrantScope = serde_json::from_value(serde_json::Value::Object(scope))?;
    let metadata = SessionGrantMetadata {
        id: seed.grant_id.clone(),
        issuer_id: owning_station_id_for(config),
        account_id: arkret_wire::AccountId::new(input.agent_id.clone(), input.audience_id.clone()),
        device_id: None,
        audience_id: input.audience_id,
        scopes,
        not_before: seed.not_before,
        expires_at: seed.expires_at,
        session_id: seed.session_id.clone(),
        session_public_key: CanonicalSessionPublicJwk::new(input.session_public_key)?,
        cnf_jkt: input.dpop_jkt,
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::AgentRuntime {
            agent_id: input.agent_id.clone(),
            agent_key_authorization_ref: input.agent_key_authorization_ref,
            verification_method: input.verification_method,
        },
        device_binding: None,
        proof_kind: Some(SessionGrantProofKind::AgentKeyProof),
        scope_details: Some(scope),
    };
    material(seed, metadata, input.local_account_id)
}

fn material(
    seed: &SessionGrantIssuanceSeed,
    metadata: SessionGrantMetadata,
    local_account_id: LocalAccountId,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    metadata.validate()?;
    Ok(SessionGrantMaterial {
        grant_id: metadata.id.clone(),
        session_grant: seed.session_grant.clone(),
        session_public_key: metadata.session_public_key.as_str().to_owned(),
        credential_class: match metadata.credential_class {
            SessionGrantCredentialClass::Standard => "standard",
            SessionGrantCredentialClass::RecoverySession => "recovery_session",
        }
        .to_owned(),
        expires_at: format_timestamp_canonical(metadata.expires_at),
        expires_at_timestamp: metadata.expires_at,
        not_before_timestamp: metadata.not_before,
        issuer_id: metadata.issuer_id.clone(),
        account_id: metadata.account_id.clone(),
        subject_id: metadata.account_id.principal_id.clone(),
        local_account_id,
        device_id: metadata.device_id.as_ref().map(ToString::to_string),
        audience_id: metadata.audience_id.clone(),
        scopes: metadata.scopes.clone(),
        dpop_jkt: Some(metadata.cnf_jkt.clone()),
        session_id: metadata.session_id.clone(),
        metadata,
    })
}

#[cfg(test)]
mod opaque_tests {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;

    use super::*;

    #[test]
    fn reservation_seed_draws_independent_canonical_secrets_and_uuid_record_ids() {
        let now = "2026-11-14T12:00:00.000Z".parse().unwrap();
        let mut rng = ChaChaRng::seed_from_u64(17);
        let a = SessionGrantIssuanceSeed::allocate(
            &mut rng,
            "chain",
            now,
            now + chrono::Duration::minutes(5),
        )
        .unwrap();
        let b = SessionGrantIssuanceSeed::allocate(
            &mut rng,
            "chain",
            now,
            now + chrono::Duration::minutes(5),
        )
        .unwrap();
        assert_ne!(a.session_grant, b.session_grant);
        assert_ne!(a.grant_id, b.grant_id);
        assert_eq!(a.session_grant.as_str().len(), 43);
        assert!(!format!("{a:?}").contains(a.session_grant.as_str()));
        assert!(arkret_identifiers::SessionGrantId::try_from_uuid(a.grant_id.uuid()).is_ok());
    }
}
