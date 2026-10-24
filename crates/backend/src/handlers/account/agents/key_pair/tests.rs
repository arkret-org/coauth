use base64ct::{Base64UrlUnpadded, Encoding as _};
use chrono::DateTime;
use serde_json::json;

use super::*;

const AGENT: &str = "ak:did_core:web:agent.example";
const AGENT_FULL: &str = "did:web:agent.example";
const CONTROLLER: &str = "ak:did_core:web:controller.example";
const CONTROLLER_FULL: &str = "did:web:controller.example";
const CONTROLLER_VM: &str = "did:web:controller.example#key-1";
const VM: &str = "did:web:agent.example#runtime-key-1";
const AUDIENCE: &str = "ak:did_core:web:coland.local";
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
                "ak.self.committed_event.stream.subscribe.v1",
                "ak.self.committed_event.read.scan.v1",
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
        "created_at": "2026-07-06T00:00:00.000Z",
        "payload": {
            "agent_id": AGENT,
            "key_id": "runtime-key-1",
            "verification_method": VM,
            "public_key": valid_public_key(),
            "accountable_principal_id": CONTROLLER,
            "agent_key_scope": {
                "actions": [
                    "ak.self.committed_event.stream.subscribe.v1",
                    "ak.self.committed_event.read.scan.v1",
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
        "producer_proof": null
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

#[test]
fn requested_scope_disclosure_uses_canonical_detached_jws_verifier() {
    let signer =
        arkret_signatures::Ed25519DetachedJwsSigner::from_seed(CONTROLLER_KEY_SEED, CONTROLLER_VM);
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: signer.verifying_key().to_bytes().to_vec(),
    };
    let transcript = b"requested-scope disclosure proof transcript";
    let jws = signer.sign_detached_jws(transcript);

    assert!(
        verify_requested_scope_disclosure_proof(&jws, transcript, CONTROLLER_VM, &material).is_ok()
    );
    assert!(
        verify_requested_scope_disclosure_proof(
            &jws,
            b"tampered requested-scope disclosure proof transcript",
            CONTROLLER_VM,
            &material,
        )
        .is_err()
    );

    let attached = jws.replacen("..", ".YXR0YWNoZWQ.", 1);
    assert!(
        verify_requested_scope_disclosure_proof(&attached, transcript, CONTROLLER_VM, &material,)
            .is_err()
    );
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
        "ak.self.committed_event.stream.subscribe.v1",
        "ak.self.committed_event.read.scan.v1",
        "ak.self.events.command.submit.v1",
        "ak.self.keys.keypackages.upload.create.v1",
    ]
    .map(str::to_owned);
    let key_without_e2ee = [
        "ak.self.committed_event.stream.subscribe.v1",
        "ak.self.committed_event.read.scan.v1",
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
    let proof = event
        .producer_proof
        .as_ref()
        .expect("producer proof")
        .clone();
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
    verify_controller_authorize_event_proof(&event, &keys)
        .expect("the controller Event proof must verify against the published controller key");

    let mut tampered = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    let proof = tampered.producer_proof.as_mut().expect("producer proof");
    proof.jws = tamper_jws_signature(&proof.jws);
    let err = verify_controller_authorize_event_proof(&tampered, &keys)
        .expect_err("one changed signature byte must fail closed");
    assert_eq!(err.status(), http::StatusCode::UNAUTHORIZED);

    // The endpoint's own resolution decides the key. The very proof the
    // fixture just accepted is rejected once the controller document publishes
    // a different key under the method that proof names -- which is what stops
    // a caller submitting evidence signed by a key of its own.
    verify_controller_authorize_event_proof(&event, &impostor_controller_signing_keys())
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
    verify_controller_authorize_event_proof(&event, &other_method)
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
    assert!(verify_controller_authorize_event_proof(&changed, &controller_signing_keys()).is_err());
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

/// Storage/consumer fixture only: it does not manufacture a Station acceptance.
fn custody_fixture() -> (
    coauth_data::agent_key::AgentKeyPairCustody,
    coauth_data::agent_key::AgentKeyAuthorization,
) {
    let mut event = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    let draft_scope = AgentKeyAuthorizePayload::try_from(&event)
        .unwrap()
        .agent_key_scope;
    let actions =
        arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(&draft_scope.actions)
            .unwrap();
    event.payload.get_mut("agent_key_scope").unwrap()["actions"] = json!(actions);
    event.payload.get_mut("agent_key_scope").unwrap()["resources"] = json!(
        actions
            .iter()
            .filter(|action| arkret_wire::ServiceOperationId::from_wire(action).is_some())
            .map(|action| json!({"kind":"operation","operation":action}))
            .collect::<Vec<_>>()
    );
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &controller_signer(),
        arkret_signatures::SignEventOptions::new().with_created_at(test_now()),
    )
    .unwrap();
    let event = authored.into_event();
    let payload = AgentKeyAuthorizePayload::try_from(&event).unwrap();
    let mut request: arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody =
        serde_json::from_value(json!({
            "pairing_request_id": PAIRING_REQUEST_ID,
            "approval_request_id": "agent_runtime_approval:01999999-0000-7000-8000-00000000feed",
            "requested_scope_disclosure": {
                "schema": "ak.schema.agent_requested_scope_disclosure.v1",
                "request_id": "ak:request:01999999-0000-7000-8000-00000000feed",
                "agent_id": AGENT, "controller_principal_id": CONTROLLER,
                "requested_scope": payload.agent_key_scope,
                "verifier_id": AUDIENCE,
                "audience": "ak.gate.account.command.pair_agent_key.v1",
                "challenge": PAIRING_REQUEST_ID,
                "issued_at": "2026-07-06T00:04:00.000Z",
                "expires_at": "2026-07-06T00:06:00.000Z",
                "proofs": []
            },
            "authorize_event": arkret_wire::EventAdmissionSubmission::new(event.clone())
        }))
        .unwrap();
    let disclosure = &mut request.requested_scope_disclosure;
    let mut proof = arkret_wire::PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: arkret_wire::DidUrl::new(CONTROLLER_VM).unwrap(),
        payload_digest: disclosure.payload_digest().unwrap(),
        created_at: disclosure.issued_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.jws =
        arkret_signatures::Ed25519DetachedJwsSigner::from_seed(CONTROLLER_KEY_SEED, CONTROLLER_VM)
            .sign_detached_jws(&disclosure.canonical_proof_binding_bytes(&proof).unwrap());
    disclosure.proofs.push(proof);
    disclosure.validate().unwrap();
    let digest = arkret_canonical::canonical_sha256(&request).unwrap();
    let custody = coauth_data::agent_key::AgentKeyPairCustody {
        request,
        station_id: AUDIENCE.parse().unwrap(),
        station_name: "owning".to_owned(),
        request_digest: digest.clone(),
        station_outcome: None,
    };
    let authorization = coauth_data::agent_key::AgentKeyAuthorization {
        id: coauth_data::Ulid::generate(),
        authorized_event_id: event.event_id.to_string(),
        agent_id: AGENT.to_owned(),
        key_id: payload.key_id.to_string(),
        verification_method: VM.to_owned(),
        public_key: valid_public_key(),
        accountable_principal_id: CONTROLLER.parse().unwrap(),
        agent_key_scope: serde_json::to_string(&payload.agent_key_scope).unwrap(),
        audience: vec![AUDIENCE.to_owned()],
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        pairing_request_id: PAIRING_REQUEST_ID.to_owned(),
        request_canonical_digest: payload
            .approval_evidence
            .request_canonical_digest
            .unwrap()
            .to_string(),
        revoked_at: None,
        revoked_reason: None,
        quarantined_at: None,
        quarantine_reason: None,
        raw_payload_digest: digest,
        coland_fanout_state: AccountabilityGrantFanoutState::Queued,
        coland_fanout_idempotency_key: event.event_id.to_string(),
        coland_fanout_payload: Value::Null,
        coland_fanout_attempt: 0,
        coland_fanout_next_retry_at: None,
        coland_fanout_dead_letter_reason: None,
        created_at: test_now(),
        updated_at: test_now(),
    };
    (custody, authorization)
}

#[test]
fn delegated_pairing_custody_encrypts_private_body_scope_and_actual_outcome() {
    let (mut custody, mut authorization) = custody_fixture();
    let encrypter = coauth_keyring::Encrypter::new(&[37; 32]);
    let sealed = custody.seal(&encrypter).unwrap();
    assert!(sealed.is_string());
    assert!(!sealed.as_str().unwrap().contains("requested_scope"));
    assert!(!sealed.as_str().unwrap().contains(CONTROLLER));
    authorization.coland_fanout_payload = sealed;
    authorization.agent_key_scope = custody.sealed_key_scope(&encrypter).unwrap();
    assert!(!authorization.agent_key_scope.contains("actions"));
    let reopened = coauth_data::agent_key::AgentKeyPairCustody::open(
        &authorization.coland_fanout_payload,
        &encrypter,
    )
    .unwrap();
    reopened
        .validate_for(&authorization, &custody.station_id, "owning")
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&reopened.request).unwrap(),
        arkret_canonical::canonical_json_bytes(&custody.request).unwrap()
    );
    assert!(
        reopened.station_outcome.is_none(),
        "pending intent is not acceptance evidence"
    );
    custody.station_outcome = Some(
        arkret_models_collaboration::agent_operations::AgentKeyPairResponseBody {
            activation_state:
                arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active,
            authorize_event_ref: custody.request.authorize_event.event.event_id.clone(),
        },
    );
    let active = coauth_data::agent_key::AgentKeyPairCustody::open(
        &custody.seal(&encrypter).unwrap(),
        &encrypter,
    )
    .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&active.station_outcome).unwrap(),
        arkret_canonical::canonical_json_bytes(&custody.station_outcome).unwrap()
    );
    // The internal durable job references custody; it never copies plaintext.
    let job = AgentKeyPairCommitJob::new(
        authorization.authorized_event_id.clone(),
        authorization.authorized_event_id.clone(),
        authorization.raw_payload_digest.clone(),
        "owning".to_owned(),
    );
    let job_value = serde_json::to_value(job).unwrap();
    assert!(job_value.get("body").is_none());
    assert!(!job_value.to_string().contains("requested_scope"));
}

#[test]
fn delegated_pairing_custody_rejects_wrong_key_plaintext_and_row_transplant() {
    let (custody, authorization) = custody_fixture();
    let encrypter = coauth_keyring::Encrypter::new(&[37; 32]);
    let sealed = custody.seal(&encrypter).unwrap();
    assert!(
        coauth_data::agent_key::AgentKeyPairCustody::open(
            &sealed,
            &coauth_keyring::Encrypter::new(&[38; 32])
        )
        .is_err()
    );
    assert!(
        coauth_data::agent_key::AgentKeyPairCustody::open(
            &serde_json::to_value(&custody).unwrap(),
            &encrypter
        )
        .is_err()
    );
    assert!(
        custody
            .validate_for(
                &authorization,
                &"ak:did_core:web:other.example".parse().unwrap(),
                "owning"
            )
            .is_err()
    );
    assert!(
        custody
            .validate_for(&authorization, &custody.station_id, "other")
            .is_err()
    );
    let mut moved = authorization.clone();
    moved.raw_payload_digest = format!("sha256:{}", "1".repeat(64));
    assert!(
        custody
            .validate_for(&moved, &custody.station_id, "owning")
            .is_err()
    );
    let mut moved = authorization.clone();
    moved.verification_method.push_str("-other");
    assert!(
        custody
            .validate_for(&moved, &custody.station_id, "owning")
            .is_err()
    );
    let mut changed = custody.clone();
    changed.request.requested_scope_disclosure.audience =
        arkret_wire::NonEmptyString::new("other-operation").unwrap();
    assert!(
        changed
            .validate_for(&authorization, &custody.station_id, "owning")
            .is_err()
    );
}

#[test]
fn delegated_session_consumption_requires_exact_active_result_and_current_signer_evidence() {
    use arkret_models_collaboration::agent_operations::{
        AgentKeyPairActivationState, AgentKeyPairResponseBody, AgentView,
        KeyStateCurrentSignerEvidence,
    };
    use arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey;
    let (mut custody, mut authorization) = custody_fixture();
    let encrypter = coauth_keyring::Encrypter::new(&[37; 32]);
    custody.station_outcome = Some(AgentKeyPairResponseBody {
        activation_state: AgentKeyPairActivationState::Active,
        authorize_event_ref: custody.request.authorize_event.event.event_id.clone(),
    });
    authorization.coland_fanout_payload = custody.seal(&encrypter).unwrap();
    authorization.agent_key_scope = custody.sealed_key_scope(&encrypter).unwrap();
    let key =
        AgentAuthorizedSigningKey::from_event(&custody.request.authorize_event.event).unwrap();
    let event = custody.request.authorize_event.event.clone();
    let mut commit: arkret_wire::RealmCommit = serde_json::from_value(json!({
        "commit_id": arkret_wire::RealmCommitId::from_digest([0;32]),
        "realm_id":event.realm_id,"stream_ref":{"kind":"realm","realm_id":event.realm_id},
        "stream_position":0,"previous_commit_ref":null,"event_ref":event.event_id,
        "governance_generation":"0","authority_ref":event.realm_id.event_id(),"committed_at":test_now(),
        "signature":{"context":"ak.realm_commit_signature.v1","signature_algorithm":"Ed25519",
            "verification_method":"did:web:coland.local#service-signing-key",
            "signed_digest":format!("sha256:{}","0".repeat(64)),"created_at":test_now(),"signature":"AA"}
    })).unwrap();
    let body =
        arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&body).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    let digest =
        arkret_signatures::detached_object::detached_object_signed_digest(&unsigned).unwrap();
    let bytes = arkret_signatures::detached_object::detached_object_signing_bytes(
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &commit.signature.verification_method,
        &digest,
        test_now(),
    )
    .unwrap();
    use ed25519_dalek::Signer as _;
    commit.signature.signed_digest = digest;
    commit.signature.signature =
        arkret_wire::Base64UrlString::new(Base64UrlUnpadded::encode_string(
            &ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                .sign(&bytes)
                .to_bytes(),
        ))
        .unwrap();
    let evidence = arkret_models_identity::build_agent_signer_evidence(
        AGENT.parse().unwrap(),
        arkret_wire::DidUrl::new(VM).unwrap(),
        serde_json::from_value(json!({
            "kty":"OKP", "crv":"Ed25519", "x":runtime_public_key_b64()
        }))
        .unwrap(),
        commit.commit_id.clone(),
        test_now(),
    )
    .unwrap();
    let evidence_ref = evidence.signer_evidence_ref().unwrap();
    let mut key_state = authoritative_key_state();
    key_state.requested_scope = custody
        .request
        .requested_scope_disclosure
        .requested_scope
        .clone();
    key_state.active_authorizations = vec![
        arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState {
            key_id: key.agent_key_id.clone(),
            verification_method: key.verification_method.clone(),
            authorized_event_ref: key.agent_key_authorize_event_id.clone(),
            expires_at: key.expires_at,
        },
    ];
    key_state.authorized_event_ref = Some(custody.request.authorize_event.event.event_id.clone());
    key_state.authorized_verification_method = Some(arkret_wire::DidUrl::new(VM).unwrap());
    key_state.authorized_public_key_digest = Some(key.public_key_digest);
    key_state.signer_resolution_evidence_ref = Some(evidence_ref.clone());
    key_state.current_signer_evidence = Some(KeyStateCurrentSignerEvidence {
        signer_resolution_evidence_ref: evidence_ref,
        authenticated_signer_evidence: evidence,
    });
    key_state.current_key_authorization = Some(Box::new(arkret_wire::CommittedEventView::Full(
        arkret_wire::CommittedEventFullView { commit, event },
    )));
    let view: AgentView = serde_json::from_value(json!({
        "agent": {"agent_id":AGENT,"slug":"fixture",
            "lifecycle":"active","readiness":{"state":"ready","blockers":[]},"presence":{"state":"unknown",
                "expires_at":"2026-07-06T00:06:00.000Z",
                "refresh_at":"2026-07-06T00:05:30.000Z"}},
        "grants":[], "key_state": key_state
    }))
    .unwrap();
    let config = coauth_config::ArkretConfig {
        runtime_owning_station_identity: coauth_config::RuntimeOwningStationIdentity::fixture(
            "did:web:coland.local",
        ),
        stations: vec![coauth_config::StationConfig {
            name: "owning".to_owned(),
            endpoint: "https://coland.local/".parse().unwrap(),
            internal_authority_shared_secret: None,
            embedded_webvh_registration_bearer: None,
            trust_domain: None,
        }],
        ..Default::default()
    };
    let scopes = custody
        .request
        .requested_scope_disclosure
        .requested_scope
        .actions
        .clone();
    let consume = |row: &coauth_data::agent_key::AgentKeyAuthorization, current: &AgentView| {
        super::super::session_proof::validate_authoritative_agent_session_evidence(
            row,
            current,
            &scopes,
            &encrypter,
            &config,
            test_now(),
        )
    };
    assert!(
        consume(&authorization, &view).is_ok(),
        "{:?}",
        consume(&authorization, &view).unwrap_err(),
    );
    assert!(
        super::super::session_proof::validate_authoritative_agent_session_evidence(
            &authorization,
            &view,
            &["ak.self.committed_event.read.scan.v1".to_owned()],
            &encrypter,
            &config,
            test_now(),
        )
        .is_err(),
        "an incomplete runtime session ceiling must still reject"
    );
    let mut changed = view.clone();
    changed.key_state.as_mut().unwrap().current_signer_evidence = None;
    assert!(consume(&authorization, &changed).is_err());
    let mut changed = view.clone();
    changed
        .key_state
        .as_mut()
        .unwrap()
        .current_signer_evidence
        .as_mut()
        .unwrap()
        .authenticated_signer_evidence
        .public_key_jwk =
        serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","x":"wrong-key"})).unwrap();
    assert!(consume(&authorization, &changed).is_err());
    let mut pending = custody.clone();
    pending.station_outcome = None;
    let mut pending_row = authorization.clone();
    pending_row.coland_fanout_payload = pending.seal(&encrypter).unwrap();
    assert!(
        consume(&pending_row, &view).is_err(),
        "ciphertext/digest alone are not active acceptance"
    );
    let mut changed = view.clone();
    changed
        .key_state
        .as_mut()
        .unwrap()
        .active_authorizations
        .clear();
    assert!(consume(&authorization, &changed).is_err());
    let mut changed = view.clone();
    changed
        .key_state
        .as_mut()
        .unwrap()
        .controller_account_id
        .station_id = "ak:did_core:web:other.example".parse().unwrap();
    assert!(consume(&authorization, &changed).is_err());
    let mut changed = view.clone();
    changed
        .key_state
        .as_mut()
        .unwrap()
        .principal_control_realm_id = "ak:realm:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
        .parse()
        .unwrap();
    assert!(consume(&authorization, &changed).is_err());
    let mut changed = view.clone();
    changed
        .key_state
        .as_mut()
        .unwrap()
        .controller_authorization_ref =
        arkret_wire::DidUrl::new("did:web:agent.example#different-controller").unwrap();
    assert!(consume(&authorization, &changed).is_err());
    let mut changed = view.clone();
    changed
        .key_state
        .as_mut()
        .unwrap()
        .requested_scope
        .resources
        .push(
            serde_json::from_value(json!({
                "kind":"realm",
                "realm_id":"ak:realm:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
            }))
            .unwrap(),
        );
    assert!(consume(&authorization, &changed).is_err());
    assert!(
        super::super::session_proof::reject_additional_session_disclosure(Some(
            &custody.request.requested_scope_disclosure
        ))
        .is_err()
    );
    assert!(super::super::session_proof::reject_additional_session_disclosure(None).is_ok());
}

#[test]
fn delegated_initial_refusal_requires_a_registered_nontransient_station_problem() {
    let classify = |status, problem: Option<arkret_wire::Problem>, ambiguous| {
        let refusal = coauth_principal::PrincipalAgentKeyPairRefusal::from_problem(
            status,
            problem.as_ref()?,
            ambiguous,
        )?;
        definitive_initial_pairing_refusal(
            &anyhow::Error::new(refusal).context("authenticated owning Station command"),
        )
    };
    let problem = arkret_wire::Problem::new("param_invalid", 400, "private detail");
    let refusal = classify(400, Some(problem.clone()), false).unwrap();
    assert!(matches!(
        refusal,
        ArkretRouteError::Coded {
            status: StatusCode::BAD_REQUEST,
            code: "param_invalid",
            ..
        }
    ));
    assert!(
        classify(400, Some(problem), true).is_none(),
        "a previous ambiguous attempt forbids rollback"
    );
    for (status, code) in [
        (503, "revision_unavailable"),
        (429, "rate_limited"),
        (400, "not_registered"),
    ] {
        assert!(
            classify(
                status,
                Some(arkret_wire::Problem::new(code, status, "private detail")),
                false
            )
            .is_none()
        );
    }
    assert!(classify(400, None, false).is_none());
    assert!(
        classify(
            400,
            Some(arkret_wire::Problem::new(
                "param_invalid",
                403,
                "private detail"
            )),
            false
        )
        .is_none()
    );
    let mut bare = arkret_wire::Problem::new("param_invalid", 400, "private detail");
    bare.problem_type = "param_invalid".to_owned();
    assert!(
        classify(400, Some(bare), false).is_none(),
        "bare code is not a registered Problem URI"
    );
    let transport = anyhow::Error::new(
        crate::services::peer_protocol_client::PeerProtocolClientError::Http(
            "response lost".to_owned(),
        ),
    );
    assert!(definitive_initial_pairing_refusal(&transport).is_none());
}
