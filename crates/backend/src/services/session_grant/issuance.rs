use arkret_canonical::format_timestamp_canonical;
#[cfg(test)]
use arkret_identifiers::{DidCoreId, EventId};
#[cfg(test)]
use arkret_models_identity::SessionGrantDeviceBinding;
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SESSION_GRANT_CREDENTIAL_KIND, SESSION_GRANT_ISSUANCE_SCHEMA,
    SessionGrantCredentialClass, SessionGrantHolderBinding, SessionGrantIssuancePreimage,
    SessionGrantProofKind, SignedSessionGrantClaims,
};
use coauth_config::ArkretConfig;
#[cfg(test)]
use coauth_data::Clock;
use coauth_data::LocalAccountId;
#[cfg(test)]
use coauth_data::UrlBuilder;
use coauth_jose::constraints::Constrainable as _;
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keyring::Keyring;
#[cfg(test)]
use rand_core::CryptoRngCore;

use super::*;
use crate::services::station_trust::owning_station_id_for;
#[cfg(test)]
use crate::services::station_trust::required_audience_for;

// Test-only convenience wrapper (re-exported under `#[cfg(test)]` from the
// session_grant module); production paths call the audience_id-explicit forms.
#[cfg(test)]
pub(crate) fn issue_session_grant(
    rng: &mut (dyn CryptoRngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    arkret_config: &ArkretConfig,
    keyring: &Keyring,
    input: TestGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let TestGrantIssuance {
        browser_session,
        session_public_key,
        subject_id,
        account_id,
        device_id,
        scopes,
    } = input;
    let now = arkret_canonical::normalize_timestamp_canonical(clock.now());
    let mut nonce = [0_u8; 32];
    rng.fill_bytes(&mut nonce);
    let (_, signing_key) = crate::services::preferred_service_signing_key(keyring)
        .ok_or(SessionGrantError::NoSigningKey)?;
    let signing_key_id = signing_key.kid().ok_or(SessionGrantError::NoSigningKey)?;
    let issuance_seed = SessionGrantIssuanceSeed::new(
        arkret_models_identity::SessionGrantIssuanceNonce::from_bytes(nonce).to_string(),
        browser_session.id.to_string(),
        now,
        now + arkret_config.session_grant_ttl,
        signing_key_id,
    )?;
    let device_binding = SessionGrantDeviceBinding {
        device_id: device_id.clone(),
        authorization_event_id: EventId::new(
            "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        )
        .expect("test authorization Event id"),
        model_generation_ref: 1,
    };
    issue_session_grant_for_audience(
        &issuance_seed,
        arkret_config,
        keyring,
        HumanGrantIssuance {
            browser_session,
            session_public_key,
            audience_id: DidCoreId::new(required_audience_for(url_builder, arkret_config))?,
            device_id,
            scopes,
            subject_override: Some(&DidCoreId::new(subject_id.to_owned())?),
            account_id,
            dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            device_binding,
            proof_kind: SessionGrantProofKind::AccountHandoff,
        },
    )
}

// `subject_override` binds the grant to the persisted principal DID verified
// for the target Station audience_id. Issuance never fabricates a
// service-local DID when that binding is absent.
pub(crate) fn issue_session_grant_for_audience(
    issuance_seed: &SessionGrantIssuanceSeed,
    arkret_config: &ArkretConfig,
    keyring: &Keyring,
    input: HumanGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let HumanGrantIssuance {
        browser_session,
        session_public_key,
        audience_id,
        device_id,
        scopes,
        subject_override,
        account_id,
        dpop_jkt,
        device_binding,
        proof_kind,
    } = input;
    let subject_id = subject_override
        .cloned()
        .ok_or(SessionGrantError::PrincipalUnknown)?;
    let session_public_key =
        CanonicalSessionPublicJwk::new(serde_json::to_string(&session_public_key)?)?;

    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    let issuer_id = owning_station_id_for(arkret_config);
    account_id.validate()?;
    if account_id.principal_id != subject_id || account_id.station_id != audience_id {
        return Err(SessionGrantError::PrincipalUnknown);
    }
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let session_id = issuance_seed.session_id.clone();
    let local_account_id = LocalAccountId::new(browser_session.user.id.to_string())?;
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer_id: issuer_id.clone(),
        issuance_nonce: issuance_nonce.clone(),
        account_id: account_id.clone(),
        session_public_key: session_public_key.clone(),
        audience_id: audience_id.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::HumanDevice {
            device_binding: device_id.to_string(),
        },
        device_binding: Some(device_binding),
        proof_kind: Some(proof_kind),
        scope_details: None,
    };
    let SignedIssuance {
        issuance_preimage,
        issuance_digest,
        grant_id,
        grant_jwt,
        key_id,
    } = sign_issuance_preimage(&preimage, keyring, &issuance_seed.signing_key_id)?;
    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key: session_public_key.into_string(),
        credential_class: "standard".to_owned(),
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer_id,
        account_id: preimage.account_id,
        subject_id,
        local_account_id,
        device_id: Some(device_id.to_string()),
        audience_id,
        scopes,
        dpop_jkt: Some(dpop_jkt),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
    })
}

pub(crate) fn issue_recovery_session_grant_for_audience(
    issuance_seed: &SessionGrantIssuanceSeed,
    arkret_config: &ArkretConfig,
    keyring: &Keyring,
    input: RecoveryGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let RecoveryGrantIssuance {
        session_public_key,
        audience_id,
        device_id,
        scopes,
        subject_id,
        local_account_id,
        account_id,
        dpop_jkt,
    } = input;
    let session_public_key =
        CanonicalSessionPublicJwk::new(serde_json::to_string(&session_public_key)?)?;
    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    if expires_at - now > chrono::Duration::minutes(15) {
        return Err(arkret_wire::WireError::Protocol(
            "recovery session grant TTL exceeds 15 minutes".to_owned(),
        )
        .into());
    }
    let issuer_id = owning_station_id_for(arkret_config);
    let subject_id = subject_id.clone();
    account_id.validate()?;
    if account_id.principal_id != subject_id || account_id.station_id != audience_id {
        return Err(SessionGrantError::PrincipalUnknown);
    }
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let session_id = issuance_seed.session_id.clone();
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer_id: issuer_id.clone(),
        issuance_nonce: issuance_nonce.clone(),
        account_id: account_id.clone(),
        session_public_key: session_public_key.clone(),
        audience_id: audience_id.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        credential_class: SessionGrantCredentialClass::RecoverySession,
        holder_binding: SessionGrantHolderBinding::RecoveryCandidateDevice {
            device_id: device_id.clone(),
        },
        device_binding: None,
        proof_kind: Some(SessionGrantProofKind::AccountHandoff),
        scope_details: None,
    };
    let SignedIssuance {
        issuance_preimage,
        issuance_digest,
        grant_id,
        grant_jwt,
        key_id,
    } = sign_issuance_preimage(&preimage, keyring, &issuance_seed.signing_key_id)?;
    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key: session_public_key.into_string(),
        credential_class: "recovery_session".to_owned(),
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer_id,
        account_id: preimage.account_id,
        subject_id,
        local_account_id,
        device_id: Some(device_id.to_string()),
        audience_id,
        scopes,
        dpop_jkt: Some(dpop_jkt),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
    })
}

/// Mint a signed agent `ak.session.grant` JWT bound to the agent principal as
/// subject_id and the runtime's DPoP key (`cnf.jkt`). No browser session is
/// involved; `session_id` retains the independently reserved refresh-chain id.
/// The canonical issuance preimage determines this credential's `grant_id`.
pub(crate) fn mint_agent_session_grant(
    issuance_seed: &SessionGrantIssuanceSeed,
    arkret_config: &ArkretConfig,
    keyring: &Keyring,
    input: AgentGrantIssuance<'_>,
) -> Result<SessionGrantMaterial, SessionGrantError> {
    let AgentGrantIssuance {
        agent_id,
        local_account_id,
        audience_id,
        scopes,
        dpop_jkt,
        session_public_key,
        scope_details,
        agent_key_authorization_ref,
        verification_method,
    } = input;
    let now = issuance_seed.not_before;
    let expires_at = issuance_seed.expires_at;
    let issuer_id = owning_station_id_for(arkret_config);
    let session_id = issuance_seed.session_id.clone();
    let scope_details = compact_agent_scope_details(scope_details);
    let session_public_key = CanonicalSessionPublicJwk::new(session_public_key)?;
    let issuance_nonce = issuance_seed.issuance_nonce.clone();
    let subject_id = agent_id.clone();
    let mut scopes = scopes;
    scopes.sort_unstable();
    scopes.dedup();
    let account_id = arkret_wire::AccountId::new(subject_id.clone(), audience_id.clone());
    let preimage = SessionGrantIssuancePreimage {
        schema: SESSION_GRANT_ISSUANCE_SCHEMA.to_owned(),
        issuer_id: issuer_id.clone(),
        issuance_nonce: issuance_nonce.clone(),
        account_id,
        session_public_key: session_public_key.clone(),
        audience_id: audience_id.clone(),
        scopes: scopes.clone(),
        not_before: now,
        expires_at,
        session_id: session_id.clone(),
        credential_class: SessionGrantCredentialClass::Standard,
        holder_binding: SessionGrantHolderBinding::AgentRuntime {
            agent_id: subject_id,
            agent_key_authorization_ref,
            verification_method,
        },
        device_binding: None,
        proof_kind: Some(SessionGrantProofKind::AgentKeyProof),
        scope_details: Some(scope_details),
    };
    let SignedIssuance {
        issuance_preimage,
        issuance_digest,
        grant_id,
        grant_jwt,
        key_id,
    } = sign_issuance_preimage(&preimage, keyring, &issuance_seed.signing_key_id)?;
    Ok(SessionGrantMaterial {
        grant_id,
        grant_jwt,
        session_public_key: session_public_key.into_string(),
        credential_class: "standard".to_owned(),
        expires_at: format_timestamp_canonical(expires_at),
        expires_at_timestamp: expires_at,
        not_before_timestamp: now,
        issuer_id,
        account_id: preimage.account_id,
        subject_id: agent_id.clone(),
        local_account_id,
        device_id: None,
        audience_id,
        scopes,
        dpop_jkt: Some(dpop_jkt),
        session_id,
        issuance_nonce: issuance_nonce.to_string(),
        issuance_preimage,
        issuance_digest,
        signing_key_id: key_id,
    })
}

struct SignedIssuance {
    issuance_preimage: Vec<u8>,
    issuance_digest: [u8; 32],
    grant_id: arkret_identifiers::SessionGrantId,
    grant_jwt: String,
    key_id: String,
}

fn sign_issuance_preimage(
    preimage: &SessionGrantIssuancePreimage,
    keyring: &Keyring,
    signing_key_id: &str,
) -> Result<SignedIssuance, SessionGrantError> {
    let issuance_preimage = preimage.canonical_bytes()?;
    let issuance_digest = preimage.issuance_digest()?;
    let grant_id = preimage.grant_id()?;
    let payload = SignedSessionGrantClaims {
        kind: SESSION_GRANT_CREDENTIAL_KIND.to_owned(),
        grant_id: grant_id.clone(),
        issuer_id: preimage.issuer_id.clone(),
        issuance_nonce: preimage.issuance_nonce.clone(),
        account_id: preimage.account_id.clone(),
        session_public_key: preimage.session_public_key.clone(),
        audience_id: preimage.audience_id.clone(),
        scopes: preimage.scopes.clone(),
        not_before: preimage.not_before,
        expires_at: preimage.expires_at,
        session_id: preimage.session_id.clone(),
        credential_class: preimage.credential_class,
        holder_binding: preimage.holder_binding.clone(),
        device_binding: preimage.device_binding.clone(),
        proof_kind: preimage.proof_kind,
        scope_details: preimage.scope_details.clone(),
    };
    payload.validate()?;

    let (alg, key) =
        reserved_signing_key(keyring, signing_key_id).ok_or(SessionGrantError::NoSigningKey)?;
    let key_id = signing_key_id.to_owned();
    let header = JsonWebSignatureHeader::new(alg.clone()).with_kid(key_id.clone());
    let signer = key.params().signing_key_for_alg(&alg)?;
    let grant_jwt = Jwt::sign(header, payload, &signer)?.into_string();

    Ok(SignedIssuance {
        issuance_preimage,
        issuance_digest,
        grant_id,
        grant_jwt,
        key_id,
    })
}

fn compact_agent_scope_details(
    mut scope_details: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    scope_details.remove("agent_id");
    scope_details.remove("principal_id");
    scope_details.remove("subject_id");
    scope_details.remove("audience_id");
    scope_details
}

fn reserved_signing_key<'a>(
    keyring: &'a Keyring,
    signing_key_id: &str,
) -> Option<(
    coauth_iana::jose::JsonWebSignatureAlg,
    &'a coauth_keyring::JsonWebKey<coauth_keyring::PrivateKey>,
)> {
    use coauth_iana::jose::JsonWebSignatureAlg;

    let key = keyring
        .iter()
        .find(|key| key.kid() == Some(signing_key_id))?;
    [
        JsonWebSignatureAlg::Ed25519,
        JsonWebSignatureAlg::Es512,
        JsonWebSignatureAlg::Es384,
        JsonWebSignatureAlg::Es256,
        JsonWebSignatureAlg::Rs512,
        JsonWebSignatureAlg::Rs384,
        JsonWebSignatureAlg::Rs256,
        JsonWebSignatureAlg::Ps512,
        JsonWebSignatureAlg::Ps384,
        JsonWebSignatureAlg::Ps256,
    ]
    .into_iter()
    .find(|alg| key.params().signing_key_for_alg(alg).is_ok())
    .map(|alg| (alg, key))
}

#[cfg(test)]
mod reserved_signing_key_tests {
    use coauth_jose::constraints::Constrainable as _;
    use coauth_keyring::{JsonWebKey, JsonWebKeySet, Keyring, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng as _;

    use super::reserved_signing_key;

    fn ed25519(seed: u64, kid: &str) -> JsonWebKey<PrivateKey> {
        JsonWebKey::new(PrivateKey::generate_ed25519(ChaChaRng::seed_from_u64(seed))).with_kid(kid)
    }

    #[test]
    fn reservation_lookup_uses_kid_before_algorithm() {
        let designated = coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID;
        for keys in [
            vec![ed25519(1, designated), ed25519(2, "later-ed25519")],
            vec![ed25519(2, "earlier-ed25519"), ed25519(1, designated)],
        ] {
            let keyring = Keyring::new(JsonWebKeySet::new(keys));
            let (algorithm, key) = reserved_signing_key(&keyring, designated)
                .expect("the reserved key is present and usable");
            assert_eq!(algorithm, coauth_iana::jose::JsonWebSignatureAlg::Ed25519);
            assert_eq!(key.kid(), Some(designated));
        }
    }
}
