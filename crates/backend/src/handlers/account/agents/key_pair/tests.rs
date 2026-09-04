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
/// Runtime-request digest domain: SHA-256 over RFC 8785 JCS of the request JWK
/// (`kty` / `kid` / `algorithm` / `key`).
const PUBLIC_KEY_DIGEST: &str =
    "sha256:8dd5dbdf14ce6690e0c83f42f568ec3d1f15c292039d6be24dad93115ec8fe64";
/// Authorization digest domain: SHA-256 over the raw 32-byte Ed25519 key.
const SIGNING_KEY_PUBLIC_KEY_DIGEST: &str =
    "sha256:b600306cfa76723fdec395e53a9b3d9fdb78b1e2d7a23c32fcbcd2dc6d0c4092";

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

#[test]
fn pairing_scope_precheck_returns_key_reason_before_queueing() {
    let provision = [
        "ak.self.events.stream.subscribe.v1",
        "ak.self.events.read.scan.v1",
        "ak.self.events.read.frontier.v1",
        "ak.self.seals.read.frontier.v1",
        "ak.self.events.command.submit.v1",
    ]
    .map(str::to_owned);
    let key_without_seal = [
        "ak.self.events.stream.subscribe.v1",
        "ak.self.events.read.scan.v1",
        "ak.self.events.read.frontier.v1",
        "ak.self.events.command.submit.v1",
    ]
    .map(str::to_owned);

    let error = super::super::session_proof::validate_agent_runtime_key_scope_layers(
        &provision,
        &key_without_seal,
    )
    .expect_err("incomplete key ceiling must reject before queued authorization persistence");
    assert_eq!(
        error,
        AgentAuthRejection::AgentKeyScopeReauthorizationRequired
    );

    let provision_without_seal = key_without_seal.clone();
    let unknown_key = ["ak.self.events.read.future_unregistered.v1".to_owned()];
    let error = super::super::session_proof::validate_agent_runtime_key_scope_layers(
        &provision_without_seal,
        &unknown_key,
    )
    .expect_err("provision deficiency must have priority over a lower-layer unknown action");
    assert_eq!(
        error,
        AgentAuthRejection::AgentProvisionScopeMigrationRequired
    );
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
                "ak.self.events.read.frontier.v1",
                "ak.self.seals.read.frontier.v1",
                "ak.self.events.command.submit.v1",
                "ak.event.read"
            ],
            "resources": []
        },
        "active_authorizations": [],
    }))
    .unwrap()
}

fn valid_signing_key_binding_core()
-> arkret_models_identity::agent_signer_evidence::AgentSigningKeyBindingCore {
    serde_json::from_value(json!({
        "schema": "ak.schema.agent_signing_key_binding.v1",
        "agent_id": AGENT,
        "agent_key_id": "runtime-key-1",
        "verification_method": VM,
        "public_key": {
            "kty": "OKP",
            "algorithm": "Ed25519",
            "key": runtime_public_key_b64()
        },
        "public_key_digest": SIGNING_KEY_PUBLIC_KEY_DIGEST,
        "issued_at": "2026-07-06T00:00:00.000Z",
        "expires_at": "2026-07-06T00:10:00.000Z",
        "controller_principal_id": CONTROLLER
    }))
    .unwrap()
}

fn valid_authorize_event_typed(pairing_request_id: &str) -> arkret_wire::Event {
    let binding_digest = arkret_signatures::agent_evidence::agent_signing_key_binding_core_digest(
        &valid_signing_key_binding_core(),
    )
    .unwrap();
    let event: arkret_wire::Event = serde_json::from_value(json!({
        "event_id": "ak:event:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
        "kind": "ak.agent.key.authorize",
        "realm_id": "ak:realm:Aa0HGvOq8Bsl1PLw19X-9sJ3Zdu6M7N-HDm-MebQoQcG",
        "scope_ref": {
            "kind": "realm",
            "realm_id": "ak:realm:Aa0HGvOq8Bsl1PLw19X-9sJ3Zdu6M7N-HDm-MebQoQcG"
        },
        "actor_id": {"kind": "service", "service_id": AGENT},
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
            "public_key_digest": SIGNING_KEY_PUBLIC_KEY_DIGEST,
            "signing_key_binding_digest": binding_digest,
            "accountable_principal_id": CONTROLLER,
            "agent_key_scope": {
                "actions": [
                    "ak.self.events.stream.subscribe.v1",
                    "ak.self.events.read.scan.v1",
                    "ak.self.events.read.frontier.v1",
                    "ak.self.seals.read.frontier.v1",
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
        &arkret_wire::DidUrl::new(CONTROLLER_VM).expect("controller verification method"),
        arkret_signatures::SignEventOptions::new().with_created_at(
            DateTime::parse_from_rfc3339("2026-07-06T00:01:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        ),
    )
    .expect("controller signs the authorize Event");
    authored.into_event()
}

/// The canonical Event digest preimage the controller proof binds.
fn authorize_event_proof_transcript(event: &arkret_wire::Event) -> Vec<u8> {
    arkret_canonical::canonical_json_bytes(&event.digest_payload().expect("digest preimage"))
        .expect("canonical digest preimage")
}

fn valid_signing_key_binding_for(
    pairing_request_id: &str,
) -> arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding {
    let event_id = valid_authorize_event_typed(pairing_request_id).event_id;
    let mut binding: arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding =
        serde_json::from_value(json!({
            "schema": "ak.schema.agent_signing_key_binding.v1",
            "agent_id": AGENT,
            "agent_key_id": "runtime-key-1",
            "verification_method": VM,
            "public_key": {
                "kty": "OKP",
                "algorithm": "Ed25519",
                "key": runtime_public_key_b64()
            },
            "public_key_digest": SIGNING_KEY_PUBLIC_KEY_DIGEST,
            "agent_key_authorize_event_id": event_id,
            "issued_at": "2026-07-06T00:00:00.000Z",
            "expires_at": "2026-07-06T00:10:00.000Z",
            "controller_principal_id": CONTROLLER,
            "controller_proof": {
                "kind": "detached_jws",
                "verification_method": CONTROLLER_VM,
                "jws": "eyJhbGciOiJFZDI1NTE5In0..unsigned"
            }
        }))
        .unwrap();
    // The controller proof signs the binding transcript, so it is attached
    // after the binding exists. The transcript covers only the proof's `kind`
    // and `verification_method`, and `agent_signing_key_binding_digest`
    // excludes `controller_proof` entirely, so replacing the placeholder JWS
    // moves neither the transcript nor the digest the authorize Event commits
    // to.
    binding.controller_proof.jws = arkret_wire::NonEmptyString::new(controller_detached_jws(
        &arkret_signatures::agent_evidence::agent_signing_key_binding_signing_bytes(&binding)
            .expect("binding transcript"),
    ))
    .expect("a detached JWS is not empty");
    binding
}

/// A detached JWS from the fixture controller over `transcript`.
fn controller_detached_jws(transcript: &[u8]) -> String {
    arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        CONTROLLER_KEY_SEED,
        CONTROLLER_VM.to_owned(),
    )
    .sign_detached_jws(transcript)
}

fn controller_public_key_material() -> arkret_signatures::proof::PublicKeyMaterial {
    arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
        bytes: controller_signer().verifying_key().to_bytes().to_vec(),
    }
}

fn valid_signing_key_binding()
-> arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding {
    valid_signing_key_binding_for(PAIRING_REQUEST_ID)
}

fn valid_authorize_event(pairing_request_id: &str) -> Value {
    serde_json::to_value(valid_authorize_event_typed(pairing_request_id)).unwrap()
}

#[test]
fn fixture_runtime_key_is_a_real_ed25519_key_the_fixture_can_sign_with() {
    let published = Base64UrlUnpadded::decode_vec(&runtime_public_key_b64())
        .expect("the published runtime key is canonical base64url");
    let published: [u8; 32] = published
        .try_into()
        .expect("an Ed25519 verifying key is 32 bytes");
    // Curve validation. `pair_agent_key` runs exactly this decompression before
    // it verifies the runtime proof of possession;
    // `validate_agent_runtime_public_key` does not, so the fixture owes the
    // check itself rather than publishing bytes the endpoint would reject.
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&published)
        .expect("the fixture runtime key must decompress to an Ed25519 curve point");
    assert_eq!(verifying.as_bytes(), &published);

    // Possession. The fixture holds the private half, so it can produce a
    // signature the pairing verifier accepts -- which a bare 32-byte constant
    // can never do, whether or not that constant happens to decompress.
    use ed25519_dalek::Signer as _;
    let transcript = b"agent runtime proof-of-possession fixture transcript";
    let signature = runtime_signing_key().sign(transcript);
    let material = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
        bytes: published.to_vec(),
    };
    assert!(arkret_signatures::proof::verify_detached_ed25519_signature(
        &material,
        transcript,
        &Base64UrlUnpadded::encode_string(&signature.to_bytes()),
    ));

    let mut tampered = signature.to_bytes();
    tampered[0] ^= 0x01;
    assert!(
        !arkret_signatures::proof::verify_detached_ed25519_signature(
            &material,
            transcript,
            &Base64UrlUnpadded::encode_string(&tampered),
        ),
        "one changed signature byte must not still verify"
    );
}

#[test]
fn fixture_public_key_digests_are_pinned_in_both_domains() {
    assert_eq!(
        arkret_signatures::agent::agent_runtime_public_key_digest(&valid_public_key())
            .expect("runtime request digest")
            .as_str(),
        PUBLIC_KEY_DIGEST
    );
    assert_eq!(
        valid_signing_key_binding().public_key_digest.as_str(),
        SIGNING_KEY_PUBLIC_KEY_DIGEST
    );
}

#[test]
fn authorize_event_controller_proof_verifies_and_one_changed_byte_breaks_it() {
    let event = valid_authorize_event_typed(PAIRING_REQUEST_ID);
    let proof = event.proofs[0]
        .as_producer()
        .expect("the fixture carries a controller producer proof")
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
fn signing_key_binding_controller_proof_verifies_and_one_changed_byte_breaks_it() {
    let binding = valid_signing_key_binding();
    let expected_binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&binding)
            .expect("binding digest");
    let verify =
        |candidate: &arkret_models_identity::agent_signer_evidence::AgentSigningKeyBinding| {
            arkret_signatures::agent_evidence::verify_agent_signing_key_binding(
                candidate,
                &arkret_identifiers::DidCoreId::new(AGENT).expect("agent core id"),
                &candidate.agent_key_id.clone(),
                &arkret_identifiers::DidCoreId::new(CONTROLLER).expect("controller core id"),
                &arkret_wire::DidUrl::new(VM).expect("runtime verification method"),
                &candidate.agent_key_authorize_event_id.clone(),
                &arkret_identifiers::Hash::new(SIGNING_KEY_PUBLIC_KEY_DIGEST)
                    .expect("signing key digest"),
                &expected_binding_digest,
                &controller_public_key_material(),
            )
        };
    verify(&binding).expect("the fixture controller proof must really verify");

    let mut tampered = valid_signing_key_binding();
    let mut jws = tampered.controller_proof.jws.as_str().to_owned();
    let signature_start = jws.rfind('.').expect("compact JWS") + 1;
    let flipped = if jws.as_bytes()[signature_start] == b'A' {
        "B"
    } else {
        "A"
    };
    jws.replace_range(signature_start..=signature_start, flipped);
    tampered.controller_proof.jws =
        arkret_wire::NonEmptyString::new(jws).expect("a tampered JWS is not empty");
    verify(&tampered).expect_err("one changed signature byte must not still verify");
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

/// Parse a test envelope into the wire Event the handler actually receives.
fn authorize_event(value: Value) -> arkret_wire::Event {
    serde_json::from_value(value).expect("test authorize_event envelope is a wire Event")
}

/// The closed `ak.agent.key.authorize` payload carried by `value`.
fn authorize_payload(value: Value) -> AgentKeyAuthorizePayload {
    AgentKeyAuthorizePayload::try_from(&authorize_event(value))
        .expect("test authorize_event carries a valid authorize payload")
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
    let binding = valid_signing_key_binding();
    let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
    envelope["kind"] = json!("ak.agent.key.revoke");

    let err = validate_controller_authorize_event(
        &authorize_event(envelope),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
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
    let binding = valid_signing_key_binding();
    let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
    envelope["payload"]["unregistered_field"] = json!(true);

    let err = validate_controller_authorize_event(
        &authorize_event(envelope),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
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
    let binding = valid_signing_key_binding();
    validate_controller_authorize_event(
        &authorize_event(valid_authorize_event(PAIRING_REQUEST_ID)),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect("matching pairing_request_id accepts");

    let wrong_pairing_request_id = "agent_pairing_request:wrong";
    let wrong_binding = valid_signing_key_binding_for(wrong_pairing_request_id);
    let err = validate_controller_authorize_event(
        &authorize_event(valid_authorize_event(wrong_pairing_request_id)),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &wrong_binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("authorize_event pairing id mismatch must reject");

    assert!(err.message().contains("pairing_request_id"));
}

#[test]
fn authorize_event_accepts_distinct_runtime_and_signing_key_public_key_digests() {
    let binding = valid_signing_key_binding();

    assert_ne!(binding.public_key_digest.as_str(), PUBLIC_KEY_DIGEST);
    validate_controller_authorize_event(
        &authorize_event(valid_authorize_event(PAIRING_REQUEST_ID)),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect("the raw signing-key disclosure must map back to the runtime JWK digest");
}

#[test]
fn authorize_event_rejects_same_controller_principal_at_another_station() {
    let binding = valid_signing_key_binding();
    let mut envelope = valid_authorize_event(PAIRING_REQUEST_ID);
    envelope["executed_by"]["account_id"]["station_id"] =
        json!("ak:did_core:web:other-station.example");

    let err = validate_controller_authorize_event(
        &authorize_event(envelope),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
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

    validate_authorize_event_supersedes(&authorize_payload(envelope), &key_state)
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

    let err = validate_authorize_event_supersedes(
        &authorize_payload(valid_authorize_event(PAIRING_REQUEST_ID)),
        &key_state,
    )
    .expect_err("omitting the old same-key authorization dot must fail closed");

    assert_eq!(err.status(), http::StatusCode::CONFLICT);
    assert!(err.message().contains("active key set"));
}

#[test]
fn authorize_event_pairing_evidence_rejects_durable_ref() {
    let binding = valid_signing_key_binding();
    let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
    event["payload"]["approval_evidence"]["evidence_ref"] =
        json!("ak:event:AQ4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4O");

    let err = validate_controller_authorize_event(
        &authorize_event(event),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("pairing evidence must not masquerade as a durable object reference");

    assert!(err.message().contains("ref must be absent"));
}

#[test]
fn authorize_event_accepts_absent_expires_at_as_non_expiring() {
    let mut binding = valid_signing_key_binding();
    let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
    event["payload"]
        .as_object_mut()
        .unwrap()
        .remove("expires_at");
    binding.core.expires_at = None;
    event["payload"]["signing_key_binding_digest"] = json!(
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&binding).unwrap()
    );

    let validated = validate_controller_authorize_event(
        &authorize_event(event),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect("absent expires_at means a non-expiring durable key authorization");

    assert!(validated.payload.expires_at.is_none());
}

#[test]
fn authorize_event_rejects_malformed_expires_at() {
    let binding = valid_signing_key_binding();
    let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
    event["payload"]["expires_at"] = json!("not-a-timestamp");

    let err = validate_controller_authorize_event(
        &authorize_event(event),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("present but malformed expires_at must fail closed");

    // The SDK payload deserializer reports the canonical-timestamp
    // violation without echoing the field path, so assert the reason
    // rather than the field name — the point of the test is that a present
    // but malformed `expires_at` fails closed instead of being treated as
    // absent (which `authorize_event_accepts_absent_expires_at_as_non_expiring`
    // shows would mean "non-expiring").
    assert!(
        err.message()
            .contains("canonical millisecond timestamp must be"),
        "unexpected rejection message: {}",
        err.message()
    );
}

#[test]
fn authorize_event_accepts_lifetime_longer_than_session_ttl() {
    let mut binding = valid_signing_key_binding();
    let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
    event["payload"]["expires_at"] = json!("2026-08-05T00:00:00.000Z");
    binding.core.expires_at = Some(
        DateTime::parse_from_rfc3339("2026-08-05T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
    );
    event["payload"]["signing_key_binding_digest"] = json!(
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&binding).unwrap()
    );

    validate_controller_authorize_event(
        &authorize_event(event),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect("durable key authorization must outlive individual session grants");
}

#[test]
fn authorize_event_rejects_non_positive_authorization_lifetime() {
    let mut binding = valid_signing_key_binding();
    let mut event = valid_authorize_event(PAIRING_REQUEST_ID);
    event["payload"]["issued_at"] = json!("2026-07-06T00:06:00.000Z");
    event["payload"]["expires_at"] = json!("2026-07-06T00:06:00.000Z");
    binding.core.issued_at = DateTime::parse_from_rfc3339("2026-07-06T00:06:00.000Z")
        .unwrap()
        .with_timezone(&Utc);
    binding.core.expires_at = Some(binding.issued_at);
    event["payload"]["signing_key_binding_digest"] = json!(
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&binding).unwrap()
    );

    let err = validate_controller_authorize_event(
        &authorize_event(event),
        AGENT,
        VM,
        &valid_public_key_typed(),
        &binding,
        PAIRING_REQUEST_ID,
        AUDIENCE,
        &authoritative_key_state(),
        test_now(),
    )
    .expect_err("key authorization must end after it is issued");

    assert!(err.message().contains("must be after issued_at"));
}
