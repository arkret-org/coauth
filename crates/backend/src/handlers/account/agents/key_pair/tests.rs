use base64ct::Base64UrlUnpadded;
use chrono::DateTime;
use serde_json::json;

use super::*;

const AGENT: &str = "ak:did_core:web:agent.example";
const AGENT_FULL: &str = "did:web:agent.example";
const CONTROLLER: &str = "ak:did_core:web:controller.example";
const CONTROLLER_FULL: &str = "did:web:controller.example";
const CONTROLLER_VM: &str = "did:web:controller.example#key-1";
const VM: &str = "did:web:agent.example#runtime-key-1";
const AUDIENCE: &str = "ak:did_core:web:soland.local";
const PAIRING_REQUEST_ID: &str = "agent_pairing_request:01999999-0000-7000-8000-00000000feed";
/// Seed of the Agent runtime signing key these fixtures pair.
///
/// The fixture publishes the *verifying key* derived from this seed, never the
/// seed bytes as a public key. A raw 32-byte constant is a value nobody holds
/// the private half of, so no case built on one can produce the proof of
/// possession `pair_agent_key` verifies before it reaches the authorization
/// checks these tests cover.
const RUNTIME_KEY_SEED: [u8; 32] = [42u8; 32];

/// Seed of the controller signing key that authors the authorize Event.
const CONTROLLER_KEY_SEED: [u8; 32] = [43u8; 32];

fn runtime_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&RUNTIME_KEY_SEED)
}

fn runtime_public_key_b64() -> String {
    Base64UrlUnpadded::encode_string(runtime_signing_key().verifying_key().as_bytes())
}

fn controller_signer() -> arkret_signatures::Ed25519PayloadSigner {
    arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        CONTROLLER_KEY_SEED,
        arkret_wire::Did::new(CONTROLLER_FULL).expect("controller DID"),
        arkret_wire::DidUrl::new(CONTROLLER_VM).expect("controller verification method"),
    )
}

fn valid_public_key() -> Value {
    json!({
        "kty": "OKP",
        "kid": VM,
        "algorithm": "Ed25519",
        "key": runtime_public_key_b64(),
    })
}

fn valid_public_key_typed() -> arkret_models_collaboration::governance::agent_artifacts::PublicKey {
    serde_json::from_value(valid_public_key()).expect("valid Agent runtime public key")
}

fn test_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-07-06T00:05:00.000Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn authoritative_key_state() -> arkret_models_collaboration::agent_operations::KeyState {
    serde_json::from_value(json!({
        "agent_id": AGENT,
        "controller_account_id": {
            "principal_id": CONTROLLER,
            "station_id": AUDIENCE
        },
        "principal_control_realm_id": "ak:realm:Aa0HGvOq8Bsl1PLw19X-9sJ3Zdu6M7N-HDm-MebQoQcG",
        "controller_authorization_ref": format!("{AGENT_FULL}#managed-controller"),
        "requested_scope": {
            "actions": [
                "ak.self.events.stream.subscribe.v1",
                "ak.self.events.read.scan.v1",
                "ak.self.events.command.submit.v1",
                "ak.event.read"
            ],
            "resources": []
        },
        "active_authorizations": [],
    }))
    .unwrap()
}

fn valid_authorize_event_typed(pairing_request_id: &str) -> arkret_wire::Event {
    let event: arkret_wire::Event = serde_json::from_value(json!({
        "event_id": "ak:event:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
        "kind": "ak.agent.key.authorize",
        "realm_id": "ak:realm:Aa0HGvOq8Bsl1PLw19X-9sJ3Zdu6M7N-HDm-MebQoQcG",
        "scope_ref": {
            "kind": "realm",
            "realm_id": "ak:realm:Aa0HGvOq8Bsl1PLw19X-9sJ3Zdu6M7N-HDm-MebQoQcG"
        },
        "actor_id": {"kind": "account", "account_id": {
            "principal_id": AGENT,
            "station_id": AUDIENCE
        }},
        "executed_by": {"kind": "account", "account_id": {
            "principal_id": CONTROLLER,
            "station_id": AUDIENCE
        }},
        "authorization_ref": format!("{AGENT_FULL}#managed-controller"),
        "actor_seq": 1,
        "created_at": "2026-07-06T00:00:00.000Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "prev_refs": [],
        "payload": {
            "agent_id": AGENT,
            "key_id": "runtime-key-1",
            "verification_method": VM,
            "public_key": valid_public_key(),
            "accountable_principal_id": CONTROLLER,
            "agent_key_scope": {
                "actions": [
                    "ak.self.events.stream.subscribe.v1",
                    "ak.self.events.read.scan.v1",
                    "ak.self.events.command.submit.v1",
                    "ak.event.read"
                ],
                "resources": []
            },
            "audience": [AUDIENCE],
            "issued_at": "2026-07-06T00:00:00.000Z",
            "expires_at": "2026-07-06T00:10:00.000Z",
            "approval_evidence": {
                "kind": "pairing_request",
                "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "pairing_request_id": pairing_request_id,
                "approved_by": CONTROLLER
            }
        },
        "proofs": []
    }))
    .unwrap();
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("authorize fixture finalizes");
    arkret_signatures::sign_event(
        &mut authored,
        &controller_signer(),
        arkret_signatures::SignEventOptions::new().with_created_at(
            DateTime::parse_from_rfc3339("2026-07-06T00:01:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
    )
    .expect("controller signs the authorize Event");
    authored.into_event()
}

fn authorize_event_proof_transcript(event: &arkret_wire::Event) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(&event.digest_payload().expect("digest preimage"))
        .expect("canonical digest preimage")
}

fn controller_did_document(
    method_id: &str,
    published_key: &[u8; 32],
) -> arkret_models_identity::DidDocument {
    serde_json::from_value(json!({
        "id": CONTROLLER_FULL,
        "verificationMethod": [{
            "id": method_id,
            "type": "Multikey",
            "controller": CONTROLLER_FULL,
            "publicKeyMultibase":
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(published_key),
        }],
        "authentication": [method_id],
        "assertionMethod": [method_id],
    }))
    .expect("controller DID document")
}

fn controller_signing_keys() -> ControllerSigningKeys {
    ControllerSigningKeys {
        document: controller_did_document(
            CONTROLLER_VM,
            &controller_signer().verifying_key().to_bytes(),
        ),
        accepted_device_material: BTreeMap::new(),
    }
}

fn impostor_controller_signing_keys() -> ControllerSigningKeys {
    ControllerSigningKeys {
        document: controller_did_document(
            CONTROLLER_VM,
            &ed25519_dalek::SigningKey::from_bytes(&[44u8; 32])
                .verifying_key()
                .to_bytes(),
        ),
        accepted_device_material: BTreeMap::new(),
    }
}

fn tamper_jws_signature(jws: &str) -> String {
    let mut jws = jws.to_owned();
    let signature_start = jws.rfind('.').expect("compact JWS") + 1;
    let flipped = if jws.as_bytes()[signature_start] == b'A' {
        "B"
    } else {
        "A"
    };
    jws.replace_range(signature_start..=signature_start, flipped);
    jws
}

fn valid_authorize_event(pairing_request_id: &str) -> Value {
    serde_json::to_value(valid_authorize_event_typed(pairing_request_id)).unwrap()
}

fn authorize_event(value: Value) -> arkret_wire::Event {
    serde_json::from_value(value).expect("test authorize_event envelope is a wire Event")
}

#[test]
fn controller_station_for_pairing_uses_trusted_enrollment() {
    let station_id = arkret_identifiers::DidCoreId::new(AUDIENCE).unwrap();
    let mut config = coauth_config::ArkretConfig::default();
    config.stations.push(coauth_config::StationConfig {
        name: "controller".to_owned(),
        endpoint: "https://controller-station.example/".parse().unwrap(),
        internal_authority_shared_secret: None,
        embedded_webvh_registration_bearer: None,
        trust_domain: None,
    });
    let resolver = crate::services::station_trust::StationTrustResolver::new();
    assert!(controller_station_for_pairing(&config, &resolver, &station_id).is_err());
    resolver.insert_for_test(&config.stations[0].endpoint, AUDIENCE);
    assert_eq!(
        controller_station_for_pairing(&config, &resolver, &station_id)
            .unwrap()
            .name,
        "controller"
    );
    let other_id = arkret_identifiers::DidCoreId::new("ak:did_core:web:other.example").unwrap();
    assert!(controller_station_for_pairing(&config, &resolver, &other_id).is_err());
    resolver.insert_for_test(&config.stations[0].endpoint, other_id.to_string());
    assert!(controller_station_for_pairing(&config, &resolver, &station_id).is_err());
    assert!(controller_station_for_pairing(&config, &resolver, &other_id).is_ok());
}

#[test]
fn pairing_scope_precheck_returns_key_reason_before_queueing() {
    // The provision layer activates both interactive chat and E2EE, so the key
    // layer must independently carry every mandatory operation of both.
    let provision = [
        "ak.self.events.stream.subscribe.v1",
        "ak.self.events.read.scan.v1",
        "ak.self.events.command.submit.v1",
        "ak.self.keys.keypackages.upload.create.v1",
    ]
    .map(str::to_owned);
    let key_without_e2ee = [
        "ak.self.events.stream.subscribe.v1",
        "ak.self.events.read.scan.v1",
        "ak.self.events.command.submit.v1",
    ]
    .map(str::to_owned);

    let error = super::super::session_proof::validate_agent_runtime_key_scope_layers(
        &provision,
        &key_without_e2ee,
    )
    .expect_err("incomplete key ceiling must reject before queued authorization persistence");
    assert_eq!(
        error,
        AgentAuthRejection::AgentKeyScopeReauthorizationRequired
    );

    let provision_without_chat = ["ak.self.events.command.submit.v1".to_owned()];
    let unknown_key = ["ak.self.events.read.future_unregistered.v1".to_owned()];
    let error = super::super::session_proof::validate_agent_runtime_key_scope_layers(
        &provision_without_chat,
        &unknown_key,
    )
    .expect_err("provision deficiency must have priority over a lower-layer unknown action");
    assert_eq!(
        error,
        AgentAuthRejection::AgentProvisionScopeMigrationRequired
    );
}

#[test]
fn authorize_event_controller_proof_verifies_and_one_changed_byte_breaks_it() {
    let event = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    let proof = event.proofs[0].clone();
    let material = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
        bytes: controller_signer().verifying_key().to_bytes().to_vec(),
    };
    let transcript = authorize_event_proof_transcript(&event);
    arkret_signatures::proof::verify_ed25519_detached_jws_proof(
        &proof,
        &transcript,
        &event.actor_id,
        &material,
    )
    .expect("the controller proof on the fixture must really verify");

    let mut tampered = transcript.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof(
        &proof,
        &tampered,
        &event.actor_id,
        &material,
    )
    .expect_err("one changed transcript byte must invalidate the controller proof");
}

#[test]
fn runtime_public_key_requires_spec_okp_shape() {
    let verification_method = arkret_wire::DidUrl::new(VM).unwrap();
    arkret_signatures::agent::validate_agent_runtime_public_key(
        &valid_public_key_typed(),
        &verification_method,
    )
    .expect("SDK Agent runtime public_key profile accepts");

    let multibase_only = json!({
        "key_type": "Ed25519",
        "public_key_multibase": "z6Mki6bBq1N3X3G3sT2xLwSPrm5Tg7EwjZwJ4oXb9qQ7z1Uu",
    });
    let err = arkret_signatures::agent::validate_agent_runtime_public_key(
        &multibase_only,
        &verification_method,
    )
    .expect_err("a multibase-only pairing key shape must reject");
    assert!(err.to_string().contains("public_key"));
}

#[test]
fn authorize_event_identity_is_checked_before_idempotency_lookup() {
    let event = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    verify_authorize_event_identity(&event).expect("content-bound fixture identity");

    let mut changed = event;
    changed
        .payload
        .insert("key_id".to_owned(), json!("attacker-key"));
    let error = verify_authorize_event_identity(&changed)
        .expect_err("covered payload mutation must invalidate the carried Event id");
    assert_eq!(error.message(), "event_id_digest_mismatch");
}

#[test]
fn agent_key_pair_rejects_authorize_event_of_another_kind() {
    let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
    envelope["kind"] = json!("ak.agent.key.revoke");

    let err = validate_controller_authorize_event(
        &authorize_event(envelope),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("an Event of another kind must fail closed");

    assert!(err.message().contains("ak.agent.key.authorize"));
}

#[test]
fn agent_key_pair_rejects_unregistered_authorize_payload_field() {
    let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
    envelope["payload"]["unregistered_field"] = json!(true);

    let err = validate_controller_authorize_event(
        &authorize_event(envelope),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("the closed payload type must reject unregistered fields");

    assert!(err.message().contains("payload is invalid"));
}

#[test]
fn agent_key_pair_rejects_query_only_pairing_id() {
    let err = ensure_body_pairing_request_id_present("")
        .expect_err("body pairing_request_id is required");

    assert_eq!(err.message(), "pairing_request_id is required");
}

#[test]
fn authorize_event_binds_body_pairing_request_id() {
    validate_controller_authorize_event(
        &authorize_event(valid_authorize_event(PAIRING_REQUEST_ID)),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect("matching pairing_request_id accepts");

    let wrong_pairing_request_id = "agent_pairing_request:wrong";
    let err = validate_controller_authorize_event(
        &authorize_event(valid_authorize_event(wrong_pairing_request_id)),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("authorize_event pairing id mismatch must reject");

    assert!(err.message().contains("pairing_request_id"));
}

#[test]
fn authorize_event_rejects_same_controller_principal_at_another_station() {
    let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
    envelope["executed_by"]["account_id"]["station_id"] =
        json!("ak:did_core:web:other-station.example");

    let err = validate_controller_authorize_event(
        &authorize_event(envelope),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("same controller principal at another Station must fail exact AccountId binding");

    assert!(err.message().contains("controller account"));
}

#[test]
fn replacement_pairing_supersedes_same_key_authorization_dot() {
    let old_event = "ak:event:AQ4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4O";
    let mut key_state = authoritative_key_state();
    key_state.active_authorizations.push(
        serde_json::from_value(json!({
            "key_id": "runtime-key-1",
            "verification_method": VM,
            "authorized_event_ref": old_event,
        }))
        .unwrap(),
    );
    let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
    envelope["payload"]["supersedes"] = json!([{
        "key_id": "runtime-key-1",
        "authorized_event_ref": old_event,
    }]);

    validate_controller_authorize_event(
        &authorize_event(envelope),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &key_state,
        test_now(),
    )
    .expect("same key_id replacement must observe-remove the old authorization dot");
}

#[test]
fn replacement_pairing_rejects_omitted_same_key_authorization_dot() {
    let mut key_state = authoritative_key_state();
    key_state.active_authorizations.push(
        serde_json::from_value(json!({
            "key_id": "runtime-key-1",
            "verification_method": VM,
            "authorized_event_ref": "ak:event:AQ4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4O",
        }))
        .unwrap(),
    );

    let err = validate_controller_authorize_event(
        &authorize_event(valid_authorize_event(PAIRING_REQUEST_ID)),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &key_state,
        test_now(),
    )
    .expect_err("omitting the old same-key authorization dot must fail closed");

    assert_eq!(err.status(), http::StatusCode::CONFLICT);
    assert!(err.message().contains("active key set"));
}

#[test]
fn authorize_event_pairing_evidence_rejects_durable_ref() {
    let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
    event["payload"]["approval_evidence"]["evidence_ref"] =
        json!("ak:event:AQ4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4O");

    let err = validate_controller_authorize_event(
        &authorize_event(event),
        AGENT,
        VM,
        &valid_public_key_typed(),
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("pairing evidence must not masquerade as a durable object reference");

    assert!(err.message().contains("ref must be absent"));
}

#[test]
fn pairing_verifies_the_authorize_event_proof_against_the_resolved_controller_key() {
    let keys = controller_signing_keys();
    let event = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    verify_controller_authorize_event_proofs(&event, &keys)
        .expect("the controller Event proof must verify against the published controller key");

    let mut tampered = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    let proof = &mut tampered.proofs[0];
    proof.jws = tamper_jws_signature(&proof.jws);
    let err = verify_controller_authorize_event_proofs(&tampered, &keys)
        .expect_err("one changed signature byte must fail closed");
    assert_eq!(err.status(), http::StatusCode::UNAUTHORIZED);

    // The endpoint's own resolution decides the key. The very proof the
    // fixture just accepted is rejected once the controller document publishes
    // a different key under the method that proof names -- which is what stops
    // a caller submitting evidence signed by a key of its own.
    verify_controller_authorize_event_proofs(&event, &impostor_controller_signing_keys())
        .expect_err("a proof only verifies under the key the controller document publishes");

    // An unpublished method is a rejection, not a fallback to whatever key
    // material travelled with the request.
    let other_method = ControllerSigningKeys {
        document: controller_did_document(
            &format!("{CONTROLLER_FULL}#some-other-key"),
            &controller_signer().verifying_key().to_bytes(),
        ),
        accepted_device_material: BTreeMap::new(),
    };
    verify_controller_authorize_event_proofs(&event, &other_method)
        .expect_err("a verification method absent from the controller document must reject");
}

#[test]
fn authorize_event_key_is_the_only_runtime_key_authority() {
    let event = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    let key = arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
        &event,
    )
    .unwrap();
    assert_eq!(key.public_key.key.as_str(), runtime_public_key_b64());
    assert_eq!(
        key.public_key_digest.as_str(),
        arkret_canonical::sha256_digest(runtime_signing_key().verifying_key().as_bytes())
    );
    let mut changed = event;
    changed.payload.get_mut("public_key").unwrap()["key"] =
        json!(Base64UrlUnpadded::encode_string(&[7u8; 32]));
    assert!(verify_authorize_event_identity(&changed).is_err());
    assert!(
        verify_controller_authorize_event_proofs(&changed, &controller_signing_keys()).is_err()
    );
}

#[test]
fn authorize_event_rejects_raw_key_substitution_even_with_a_valid_controller_shape() {
    let event = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    let mut other_key = valid_public_key_typed();
    other_key.key =
        arkret_wire::Base64UrlString::new(Base64UrlUnpadded::encode_string(&[7u8; 32])).unwrap();
    assert!(
        validate_controller_authorize_event(
            &event,
            AGENT,
            VM,
            &other_key,
            PAIRING_REQUEST_ID,
            AUDIENCE,
            &authoritative_key_state(),
            test_now()
        )
        .is_err()
    );
}
