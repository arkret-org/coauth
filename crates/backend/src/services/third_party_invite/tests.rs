//! Private custody tests. Accepted Device and governing Invite authorization
//! are separate Coland gates, and are not simulated by these storage tests.

use coauth_data::RepositoryFactory;
use coauth_storage_postgres::PgRepositoryFactory;
use rand_core::SeedableRng;

use super::*;

pub(super) fn request(
    mode: ThirdPartyInviteOobKind,
) -> (ThirdPartyInviteProvisionRequestBody, Did) {
    let principal = coauth_storage_postgres::test_utils::principal_registration_anchor_fixture(
        "ivs-private",
        [81; 32],
    );
    let did = match principal {
        arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
            normalized_did_document,
            ..
        } => normalized_did_document.id,
    };
    let core = arkret_identifiers::project_did_to_core_id(&did).unwrap();
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let request = ThirdPartyInviteProvisionRequestBody {
        request_id: arkret_wire::RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        realm_id: arkret_wire::RealmId::new(
            "ak:realm:AXXwKm5bWs7Plj3J5iRyqGeeNU99_oZCMnjtWom6sFeR",
        )
        .unwrap(),
        inviter_account_id: arkret_wire::AccountId {
            principal_id: core.clone(),
            station_id: core.clone(),
        },
        verification_id: core,
        oob_code_kind: mode,
        delivery_target_uri: ThirdPartyInviteDeliveryTargetUri::new(
            "mailto:private-recipient@example.com",
        )
        .unwrap(),
        expires_at: now + Duration::hours(2),
        signature: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
            verification_method: DidUrl::new(format!("{did}#device-fixture")).unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
            created_at: now,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        },
    };
    (request, did)
}

#[tokio::test]
async fn durable_original_intent_replays_without_replacing_private_material() {
    let db = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("real isolated PostgreSQL required");
    let factory = PgRepositoryFactory::new(db.clone());
    let encrypter = Encrypter::new(&[0x31; 32]);
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(933);
    for mode in [
        ThirdPartyInviteOobKind::OfflineToken,
        ThirdPartyInviteOobKind::Lookup,
    ] {
        let (request, did) = request(mode);
        let mut first = factory.create().await.unwrap();
        let outcome = provision_verified(
            &mut first,
            &encrypter,
            &mut rng,
            &request,
            &did,
            "transport-source",
            Utc::now(),
        )
        .await
        .unwrap();
        first.save().await.unwrap();
        let mut after = factory.create().await.unwrap();
        let original = after
            .third_party_invite()
            .find(&digest(outcome.provisioning_id.as_str()))
            .await
            .unwrap()
            .unwrap();
        let clear = decrypt(&original, &encrypter).unwrap();
        let secret = clear.secrets.as_ref().unwrap();
        assert!(!original.encrypted_record.contains(&secret.token));
        assert!(!original.encrypted_record.contains("private-recipient"));
        assert!(status(&clear).invite_id.is_none());
        assert!(status(&clear).delivery_state.is_none());
        after.cancel().await.unwrap();
        // A new repository (the restart boundary) observes exactly the same ledger.
        let mut restarted = factory.create().await.unwrap();
        let replay = provision_verified(
            &mut restarted,
            &encrypter,
            &mut rng,
            &request,
            &did,
            "transport-source",
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(replay, outcome);
        let replay_row = restarted
            .third_party_invite()
            .find(&original.handle_digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay_row.encrypted_record, original.encrypted_record);
        let mut altered = request.clone();
        altered.delivery_target_uri =
            ThirdPartyInviteDeliveryTargetUri::new("mailto:other@example.com").unwrap();
        assert!(matches!(
            provision_verified(
                &mut restarted,
                &encrypter,
                &mut rng,
                &altered,
                &did,
                "transport-source",
                Utc::now()
            )
            .await,
            Err(InviteError::DuplicateConflict)
        ));
        restarted.save().await.unwrap();
        let mut tampered = original;
        tampered.handle_digest = digest("another private credential");
        assert!(matches!(
            decrypt(&tampered, &encrypter),
            Err(InviteError::Internal)
        ));
    }
}

#[tokio::test]
async fn terminal_intent_replay_preserves_public_ledger_without_restoring_custody() {
    let db = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("real isolated PostgreSQL required");
    let factory = PgRepositoryFactory::new(db.clone());
    let encrypter = Encrypter::new(&[0x32; 32]);
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(934);
    for mode in [
        ThirdPartyInviteOobKind::OfflineToken,
        ThirdPartyInviteOobKind::Lookup,
    ] {
        let (request, did) = request(mode);
        let mut repo = factory.create().await.unwrap();
        let original = provision_verified(
            &mut repo,
            &encrypter,
            &mut rng,
            &request,
            &did,
            "terminal-source",
            Utc::now(),
        )
        .await
        .unwrap();
        repo.save().await.unwrap();
        for terminal in [
            ThirdPartyInviteProvisioningState::Expired,
            ThirdPartyInviteProvisioningState::Revoked,
            ThirdPartyInviteProvisioningState::Consumed,
        ] {
            let mut repo = factory.create().await.unwrap();
            let row = repo
                .third_party_invite()
                .find(&digest(original.provisioning_id.as_str()))
                .await
                .unwrap()
                .unwrap();
            let mut custody = decrypt(&row, &encrypter).unwrap();
            custody.state = terminal;
            custody.secrets = None;
            update(&mut repo, row, &custody, &encrypter).await.unwrap();
            repo.save().await.unwrap();
            let mut restored = factory.create().await.unwrap();
            let before = restored
                .third_party_invite()
                .find(&digest(original.provisioning_id.as_str()))
                .await
                .unwrap()
                .unwrap();
            let replay = provision_verified(
                &mut restored,
                &encrypter,
                &mut rng,
                &request,
                &did,
                "terminal-source",
                Utc::now(),
            )
            .await
            .unwrap();
            assert_eq!(replay, original);
            let after = restored
                .third_party_invite()
                .find(&before.handle_digest)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.encrypted_record, before.encrypted_record);
            assert!(after.token_selector.is_none());
            assert!(after.deliver_after.is_none());
            let still_terminal = decrypt(&after, &encrypter).unwrap();
            assert_eq!(still_terminal.state, terminal);
            assert!(still_terminal.secrets.is_none());
            restored.save().await.unwrap();
        }
    }
}

// Typed and SDK-signed carrier for the private ledger boundary only. This
// fixture does not represent an accepted governing Station or current Invite;
// those authority checks are exercised by the live four-operation suite.
pub(super) fn ledger_activation(
    public: &ThirdPartyInviteProvisionResponseBody,
    did: &Did,
    dot: u8,
) -> ThirdPartyInviteActivationRequestBody {
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [dot; 32]);
    let mut attestation = ThirdPartyInviteAcceptanceAttestation {
        station_id: public.inviter_account_id.station_id.clone(),
        verification_id: public.third_party_invite.verification_id.clone(),
        realm_id: public.realm_id.clone(),
        invite_id: arkret_wire::InviteId::from_event_id(&event_id),
        inviter_account_id: public.inviter_account_id.clone(),
        provisioning_id: public.provisioning_id.clone(),
        third_party_invite: public.third_party_invite.clone(),
        invite_expires_at: public.expires_at,
        invite_state: ThirdPartyInviteAttestedState::Pending,
        observed_at: at,
        expires_at: (at + Duration::seconds(60)).min(public.expires_at),
        signature: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
            verification_method: DidUrl::new(format!("{did}#ledger-fixture")).unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: at,
            domain: Some("ivs-private-ledger.example".to_owned()),
            audience: Some(arkret_wire::Audience::Single(
                public.third_party_invite.verification_id.to_string(),
            )),
            proof_purpose: None,
            jws: String::new(),
        },
    };
    attestation.signature.payload_digest = attestation.payload_digest().unwrap();
    let binding = attestation
        .unsigned_proof_binding_bytes(&attestation.signature.unsigned())
        .unwrap();
    attestation.signature.jws = arkret_signatures::proof::sign_ed25519_detached_jws(
        &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[83; 32]),
        &binding,
    )
    .unwrap();
    attestation.validate().unwrap();
    ThirdPartyInviteActivationRequestBody {
        provisioning_id: public.provisioning_id.clone(),
        acceptance_attestation: attestation,
    }
}

#[tokio::test]
async fn bound_activation_replay_and_rebind_rejection_preserve_durable_outcome() {
    let db = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("real isolated PostgreSQL required");
    let factory = PgRepositoryFactory::new(db.clone());
    let encrypter = Encrypter::new(&[0x34; 32]);
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(935);
    for mode in [
        ThirdPartyInviteOobKind::OfflineToken,
        ThirdPartyInviteOobKind::Lookup,
    ] {
        let (request, did) = request(mode);
        let mut repo = factory.create().await.unwrap();
        let public = provision_verified(
            &mut repo,
            &encrypter,
            &mut rng,
            &request,
            &did,
            "bound-ledger-source",
            Utc::now(),
        )
        .await
        .unwrap();
        repo.save().await.unwrap();
        let activation = ledger_activation(&public, &did, 93);
        let mut repo = factory.create().await.unwrap();
        let original = activate_verified(&mut repo, &encrypter, &activation, Utc::now())
            .await
            .unwrap();
        repo.save().await.unwrap();
        let mut repo = factory.create().await.unwrap();
        let before = repo
            .third_party_invite()
            .find(&digest(public.provisioning_id.as_str()))
            .await
            .unwrap()
            .unwrap();
        let different = ledger_activation(&public, &did, 94);
        assert!(matches!(
            activate_verified(&mut repo, &encrypter, &different, Utc::now()).await,
            Err(InviteError::AlreadyBound)
        ));
        let unchanged = repo
            .third_party_invite()
            .find(&before.handle_digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.encrypted_record, before.encrypted_record);
        let mut c = decrypt(&unchanged, &encrypter).unwrap();
        c.state = ThirdPartyInviteProvisioningState::Revoked;
        c.secrets = None;
        update(&mut repo, unchanged, &c, &encrypter).await.unwrap();
        repo.save().await.unwrap();
        let mut restarted = factory.create().await.unwrap();
        let before = restarted
            .third_party_invite()
            .find(&digest(public.provisioning_id.as_str()))
            .await
            .unwrap()
            .unwrap();
        // The original authenticated bytes name the durable outcome after
        // private expiry/revocation; they never recreate a delivery intent.
        let replay = activate_verified(
            &mut restarted,
            &encrypter,
            &activation,
            public.expires_at + Duration::seconds(1),
        )
        .await
        .unwrap();
        assert_eq!(replay, original);
        let after = restarted
            .third_party_invite()
            .find(&before.handle_digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.encrypted_record, before.encrypted_record);
        assert!(after.deliver_after.is_none());
        assert!(after.token_selector.is_none());
        let c = decrypt(&after, &encrypter).unwrap();
        assert_eq!(c.state, ThirdPartyInviteProvisioningState::Revoked);
        assert!(c.secrets.is_none());
        restarted.save().await.unwrap();
    }
}

#[tokio::test]
async fn mint_rollback_does_not_create_an_orphan_redeemable_record() {
    let db = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("real isolated PostgreSQL required");
    let factory = PgRepositoryFactory::new(db.clone());
    let encrypter = Encrypter::new(&[0x32; 32]);
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(934);
    let (request, did) = request(ThirdPartyInviteOobKind::Lookup);
    let mut aborted = factory.create().await.unwrap();
    let lost = provision_verified(
        &mut aborted,
        &encrypter,
        &mut rng,
        &request,
        &did,
        "source",
        Utc::now(),
    )
    .await
    .unwrap();
    aborted.cancel().await.unwrap();
    let mut retry = factory.create().await.unwrap();
    assert!(
        retry
            .third_party_invite()
            .find(&digest(lost.provisioning_id.as_str()))
            .await
            .unwrap()
            .is_none()
    );
    let outcome = provision_verified(
        &mut retry,
        &encrypter,
        &mut rng,
        &request,
        &did,
        "source",
        Utc::now(),
    )
    .await
    .unwrap();
    assert_ne!(outcome.provisioning_id, lost.provisioning_id);
    retry.save().await.unwrap();
}

#[test]
fn manual_delivery_preserves_mailbox_and_rejects_uri_header_injection() {
    assert_eq!(
        delivery_address("mailto:person+team@example.com")
            .unwrap()
            .to_string(),
        "person+team@example.com"
    );
    assert_eq!(
        delivery_address("mailto:person%2Bteam%40example.com")
            .unwrap()
            .to_string(),
        "person+team@example.com"
    );
    assert!(delivery_address("mailto:person@example.com?bcc=outsider@example.com").is_err());
    assert!(delivery_address("mailto:person@example.com%0D%0ABcc:outsider@example.com").is_err());
    assert!(matches!(
        delivery_address("tel:+15551234567"),
        Err(InviteError::UnsupportedFeature)
    ));
}

/// Calls the original mint path; no secret is supplied by this fixture.
#[tokio::test]
async fn mint_generates_independent_32_byte_salts_and_exact_token_commitments() {
    let db = coauth_storage_postgres::test_utils::setup_test_pool()
        .await
        .expect("real isolated PostgreSQL required");
    let factory = PgRepositoryFactory::new(db.clone());
    let encrypter = Encrypter::new(&[0x41; 32]);
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(93302);
    let mut previous_salts = Zeroizing::new(Vec::<[u8; 32]>::new());
    for mode in [
        ThirdPartyInviteOobKind::OfflineToken,
        ThirdPartyInviteOobKind::Lookup,
    ] {
        for _ in 0..2 {
            let (request, did) = request(mode);
            let mut repo = factory.create().await.unwrap();
            let outcome = provision_verified(
                &mut repo,
                &encrypter,
                &mut rng,
                &request,
                &did,
                "salt-source",
                Utc::now(),
            )
            .await
            .unwrap();
            repo.save().await.unwrap();
            let mut cold = factory.create().await.unwrap();
            let row = cold
                .third_party_invite()
                .find(&digest(outcome.provisioning_id.as_str()))
                .await
                .unwrap()
                .unwrap();
            let custody = decrypt(&row, &encrypter).unwrap();
            let secret = custody.secrets.as_ref().unwrap();
            // Boolean diagnostics avoid printing tokens, salts or private signing seeds.
            assert_eq!(secret.salt.len(), 32);
            assert!(secret.salt != [0; 32]);
            assert!(
                previous_salts
                    .iter()
                    .all(|previous| previous != &secret.salt)
            );
            assert!(secret.salt != secret.pepper && secret.salt != secret.signing_seed);
            let mut actual = Sha256::new();
            actual.update(secret.salt);
            actual.update(secret.token.as_bytes());
            let expected = Hash::new(format!("sha256:{:x}", actual.finalize())).unwrap();
            assert_eq!(
                custody.public.third_party_invite.token_commitment.as_ref(),
                Some(&expected)
            );
            previous_salts.push(secret.salt);
            cold.cancel().await.unwrap();
        }
    }
    assert_eq!(previous_salts.len(), 4);
}
