// Copyright 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Relay an exact signed invite to its recipient Station.
//!
//! The holder's current permission set is private and its display summary is
//! not an authorization result. Coauth forwards the complete typed delivery;
//! the target Station checks Consent, policy, identity and final delivery CAS.
//! An opaque deferred outcome stays opaque to this relay.

use arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody;
use arkret_models_collaboration::governance::membership_invite::{
    InviteCreatePayload, validate_invite_create_wire_keys,
};
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_wire::{DidCoreId, EventKind};
use coauth_config::ArkretConfig;
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use super::{DepotExt, RouteError, make_clock};
use crate::handlers::arkret;
use crate::services::peer_protocol_client::PeerProtocolClient;
use crate::services::station_trust::{self, StationTrustResolver};

// ── Request / response shapes ──────────────────────────────────

/// Body of `POST /_coauth/self/account/invites/relay`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRelayRequestBody {
    /// DID of the actor issuing the invite. The route is guarded by the
    /// browser-session cookie / OAuth bearer (`post_invite_relay` runs
    /// `extract_session_info` + `get_requester`): a non-admin caller may
    /// only relay for their own published principal DID, while an admin
    /// session may relay on behalf of any `inviter_id`. The value is never
    /// trusted as authentication on its own.
    pub inviter_id: DidCoreId,

    /// Base URL of the target's `server_name` (`coland`).
    ///
    /// With an invite delivery, this must match the configured endpoint for
    /// its exact recipient AccountId's Station. When omitted, that Station
    /// supplies the endpoint.
    #[serde(default)]
    pub target_principal_url: Option<Url>,

    /// The signed recipient's principal DID, checked against its complete AccountId.
    pub target_holder_principal_id: DidCoreId,

    /// Typed v1 invite-delivery body for `POST /_arkret/peer/invites`.
    pub invite_delivery: InviteDeliveryRequestBody,
}

fn invite_delivery_target(
    delivery: &InviteDeliveryRequestBody,
    target_holder_principal_id: &DidCoreId,
    requested_endpoint: Option<&Url>,
    config: &ArkretConfig,
    resolver: &StationTrustResolver,
) -> Result<Url, RouteError> {
    delivery
        .validate_minimal()
        .map_err(|error| RouteError::BadRequest(format!("invalid_invite_delivery: {error}")))?;
    if delivery.invite_event.kind != EventKind::InviteCreate {
        return Err(RouteError::BadRequest(
            "invalid_invite_event_kind".to_owned(),
        ));
    }
    let payload_value =
        serde_json::Value::Object(delivery.invite_event.payload.clone().into_iter().collect());
    validate_invite_create_wire_keys(&payload_value)
        .map_err(|error| RouteError::BadRequest(format!("invalid_invite_payload: {error}")))?;
    let payload: InviteCreatePayload = serde_json::from_value(payload_value)
        .map_err(|error| RouteError::BadRequest(format!("invalid_invite_payload: {error}")))?;
    let account_id = &delivery.invite_address.account_id;
    if &account_id.principal_id != target_holder_principal_id {
        return Err(RouteError::BadRequest(
            "invite_delivery_subject_mismatch".to_owned(),
        ));
    }
    if payload.invitee_account_id != *account_id {
        return Err(RouteError::BadRequest(
            "invite_delivery_account_mismatch".to_owned(),
        ));
    }

    // The signed invite selects the complete account. Configuration resolves
    // that account's Station; it must never fill in or replace its identity.
    let requested = requested_endpoint
        .map(|endpoint| CanonicalServiceUrl::canonicalize(endpoint.as_str()))
        .transpose()
        .map_err(|_| RouteError::BadRequest("invalid_principal_url".to_owned()))?;
    let mut known_station = false;
    for station in &config.stations {
        if station_trust::effective_audience(station, resolver)
            .is_none_or(|service_id| service_id != account_id.station_id)
        {
            continue;
        }
        known_station = true;
        let endpoint = CanonicalServiceUrl::canonicalize(station.endpoint.as_str())
            .map_err(|error| RouteError::Internal(Box::new(error)))?;
        if requested
            .as_ref()
            .is_none_or(|requested| requested == &endpoint)
        {
            return Ok(endpoint.as_url());
        }
    }
    Err(RouteError::BadRequest(
        if known_station {
            "invite_delivery_station_mismatch"
        } else {
            "invite_delivery_station_unknown"
        }
        .to_owned(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InviteRelayHttpOutcome {
    pub status: &'static str,
    pub forwarded_ok: bool,
}

/// Transport success does not disclose or authorize the holder's decision.
pub async fn relay_invite_with(
    peer_protocol_client: &PeerProtocolClient<'_>,
    invite_delivery: &InviteDeliveryRequestBody,
) -> InviteRelayHttpOutcome {
    let forwarded_ok = match peer_protocol_client
        .post_invite_delivery(invite_delivery)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            warn!(?error, "invite forward: peer invite delivery failed");
            false
        }
    };
    InviteRelayHttpOutcome {
        status: "forwarded",
        forwarded_ok,
    }
}

// ── Salvo handler ──────────────────────────────────────────────

/// `POST /_coauth/self/account/invites/relay`
#[endpoint]
#[tracing::instrument(name = "handlers.account.invite_relay.post", skip_all, err)]
pub async fn post_invite_relay(
    req: &mut Request,
    depot: &Depot,
    res: &mut Response,
) -> Result<(), RouteError> {
    let params: InviteRelayRequestBody = req
        .parse_json()
        .await
        .map_err(|_| RouteError::BadRequest("invalid_request_body".into()))?;

    let arkret_config = depot.arkret_config()?;
    let http_client = depot.http_client()?;
    let keyring = depot.keyring()?;
    let url_builder = depot.url_builder()?;

    // ── Authentication + authorization ─────────────────────────────
    // This endpoint drives a signed, coauth-DID-attested outbound forward to
    // a target Station, so it MUST NOT be reachable anonymously
    // (the `/_coauth` parent router only mounts CORS). Mirror the standard
    // `self/` auth pattern (`viewer`, `sessions`): require an authenticated
    // requester, then bind the relay to that identity.
    let clock = make_clock();
    let (requester, mut repo) =
        crate::handlers::account::authenticated_requester(req, depot, &clock).await?;

    let user = requester.user().ok_or(RouteError::Unauthorized)?;

    // A non-admin session may only relay invites for its own published
    // principal DID. An admin session (OAuth scope) may relay on behalf of
    // any `inviter_id`. The body-supplied `inviter_id` is otherwise never
    // trusted as authentication.
    if !requester.is_admin() {
        let caller_id = arkret::published_principal_id_for_user(&mut repo, &arkret_config, user)
            .await?
            .ok_or(RouteError::Unauthorized)?;
        if caller_id != params.inviter_id
            || params
                .invite_delivery
                .invite_event
                .actor_id
                .as_account_id()
                .is_none_or(|account| account.principal_id != caller_id)
        {
            return Err(RouteError::Unauthorized);
        }
    }

    repo.cancel().await?;

    let principal_url = invite_delivery_target(
        &params.invite_delivery,
        &params.target_holder_principal_id,
        params.target_principal_url.as_ref(),
        &arkret_config,
        station_trust::shared(),
    )?;

    // Deny-by-default for the federation hop: the relay forwards a request
    // signed under coauth's service DID, so the destination MUST resolve to
    // a configured trust anchor (a `stations` endpoint, an
    // configured Station endpoint or the `identity_registry` resolver).
    // This blocks the SSRF / signing-oracle vector where a caller supplies
    // an arbitrary `target_principal_url`.
    if !arkret_config.is_trusted_outbound_target(&principal_url) {
        warn!(
            host = principal_url.host_str().unwrap_or("<none>"),
            "invite-relay: rejected untrusted target_principal_url"
        );
        return Err(RouteError::BadRequest("untrusted_principal_url".into()));
    }

    let service_id = crate::services::station_trust::owning_station_id_for(&arkret_config);
    let trust_domain = arkret_identifiers::TrustDomainId::new(arkret::trust_domain_for(
        &url_builder,
        &arkret_config,
    ))
    .map_err(|error| RouteError::Internal(Box::new(error)))?;
    let destination_id = params
        .invite_delivery
        .invite_address
        .account_id
        .station_id
        .clone();
    let identity = arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding {
        source_id: service_id,
        destination_id,
    };
    let peer_client = PeerProtocolClient::new(
        Some(&principal_url),
        &http_client,
        &keyring,
        crate::services::station_trust::owning_station_did_for(&arkret_config),
        identity,
        trust_domain.clone(),
        trust_domain,
    )
    .map_err(|error| RouteError::Internal(Box::new(error)))?;
    let body = relay_invite_with(&peer_client, &params.invite_delivery).await;
    res.status_code(StatusCode::OK);
    res.render(Json(body));
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::handlers::test_utils::setup;

    /// The Realm named by the invite Event. A bundle whose authority commit
    /// sits in another Realm stream is rejected as cross-Realm.
    const FIXTURE_REALM: &str = "ak:realm:Acewuy1nKbK90D-V6pWEnoWq1drBx9FVel0gtDQlninN";

    fn core_id(value: &str) -> DidCoreId {
        DidCoreId::new(value).unwrap()
    }

    fn test_keyring() -> coauth_keyring::Keyring {
        use coauth_keyring::{JsonWebKey, JsonWebKeySet, PrivateKey};
        use rand_chacha::rand_core::SeedableRng as _;
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(9);
        let key = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid(coauth_keyring::ACCOUNT_AUTHORITY_KEY_ID);
        coauth_keyring::Keyring::new(JsonWebKeySet::new(vec![key]))
    }

    fn trust_domain() -> arkret_identifiers::TrustDomainId {
        arkret_identifiers::TrustDomainId::new("ak:trust_domain:auth.example".to_owned()).unwrap()
    }

    fn service_resolution() -> arkret_models_identity::identity_resolution::ServiceResolutionCarrier
    {
        arkret_models_identity::identity_resolution::ServiceResolutionCarrier::ResolutionUrl {
            resolution_url:
                "https://auth.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Aauth.example/resolution"
                    .to_owned(),
        }
    }

    fn payload() -> serde_json::Value {
        arkret_models_collaboration::governance::membership_invite::InviteCreatePayload::new(
            arkret_wire::AccountId::new(
                arkret_identifiers::DidCoreId::new("ak:did_core:web:holder".to_owned()).unwrap(),
                arkret_identifiers::DidCoreId::new("ak:did_core:web:auth.example".to_owned())
                    .unwrap(),
            ),
            arkret_identifiers::Hash::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .to_value()
        .unwrap()
    }

    fn invite_delivery()
    -> arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody {
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-20T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let principal = arkret_wire::Did::new("did:web:inviter").unwrap();
        let device =
            arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(&principal).unwrap(),
            core_id("ak:did_core:web:auth.example"),
        ));
        let raw = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::InviteCreate.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_identifiers::RealmId::new(FIXTURE_REALM).unwrap(),
            },
            actor.clone(),
            payload(),
            at,
        )
        .unwrap();
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            raw,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let device_seed = [77; 32];
        let vm = arkret_wire::DidUrl::new(format!("{principal}#{device}")).unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &arkret_signatures::Ed25519DetachedJwsSigner::from_seed(device_seed, vm.to_string()),
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let event = authored.into_event();
        // Public immutable source coordinates are independent of the target Invite Commit.
        let authorization_ref = arkret_wire::CommittedEventRef {
            event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [71; 32],
            ),
            commit_id: arkret_wire::RealmCommitId::from_digest([72; 32]),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [73; 32],
                )),
            },
            stream_position: 2,
        };
        let fact =
            arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact {
                event_id: event.event_id.clone(),
                actor,
                device_id: device,
                verification_method: vm,
                key: arkret_models_identity::ResolvedSignerKey {
                    public_key_b64u: arkret_wire::Base64UrlString::new(
                        arkret_canonical::base64url_encode(
                            crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&device_seed)
                                .verifying_key()
                                .as_bytes(),
                        ),
                    )
                    .unwrap(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: authorization_ref.commit_id.clone(),
                        stream_position: authorization_ref.stream_position,
                    },
                    authorization_ref,
                    governance_generation: 0,
                },
                accepted_at: at,
            };
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            &event,
            &fact,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let mut invite_commit = arkret_wire::RealmCommit {
            commit_id: arkret_wire::RealmCommitId::from_digest([0x02; 32]),
            realm_id: event.realm_id.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position: 1,
            previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest([0x01; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            producer_signer_fact_digest: Some(fact.digest().unwrap()),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.realm_id.event_id(),
            ),
            committed_at: chrono::DateTime::parse_from_rfc3339("2026-09-20T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:auth.example#notary-key".to_owned(),
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: chrono::DateTime::parse_from_rfc3339("2026-09-20T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        };
        let identity = arkret_canonical::canonical::unsigned_value(
            &invite_commit,
            &["commit_id", "signature"],
        )
        .unwrap();
        invite_commit.commit_id =
            arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(&identity).unwrap(),
            ));
        let unsigned =
            arkret_canonical::canonical::unsigned_value(&invite_commit, &["signature"]).unwrap();
        let authority_key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[23; 32]);
        invite_commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            invite_commit.signature.verification_method.clone(),
            at,
            &authority_key,
        )
        .unwrap();
        arkret_signatures::detached_object::verify_detached_object_signature(
            &invite_commit.signature,
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: authority_key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        fact.validate_commit_binding(
            &arkret_wire::CommittedEventFullView {
                event: event.clone(),
                commit: invite_commit.clone(),
            },
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        arkret_models_collaboration::governance::invite_addressing::InviteDeliveryRequestBody::new(
            event,
            invite_commit,
            Some(fact),
            vec![
                arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidate {
                    service_kind: arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidateServiceKind::Station,
                    service_id: arkret_identifiers::DidCoreId::new(
                        "ak:did_core:web:auth.example".to_owned(),
                    )
                    .unwrap(),
                    endpoint_url: None,
                    source: arkret_models_collaboration::governance::realm_join_intake::AuthorityLocatorSource::Invite,
                },
            ],
            arkret_models_collaboration::governance::invite_addressing::InviteAddress::station(
                arkret_identifiers::DidCoreId::new("ak:did_core:web:holder".to_owned()).unwrap(),
                arkret_identifiers::DidCoreId::new("ak:did_core:web:auth.example".to_owned()).unwrap(),
                service_resolution(),
            ),
            arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence::ExplicitAddress,
            "idem-1",
        ).unwrap()
    }

    fn relay_config() -> ArkretConfig {
        let station = |name: &str, endpoint: &str| coauth_config::StationConfig {
            name: name.to_owned(),
            endpoint: Url::parse(endpoint).unwrap(),
            internal_authority_shared_secret: None,
            embedded_webvh_registration_bearer: None,
            trust_domain: None,
        };
        ArkretConfig {
            stations: vec![
                station("other", "https://other.example/"),
                station("recipient", "https://auth.example/"),
            ],
            ..ArkretConfig::default()
        }
    }

    fn relay_resolver(config: &ArkretConfig) -> StationTrustResolver {
        let resolver = StationTrustResolver::new();
        for station in &config.stations {
            let service_id = if station.name == "other" {
                "ak:did_core:web:other.example"
            } else {
                "ak:did_core:web:auth.example"
            };
            resolver.insert_for_test(&station.endpoint, service_id);
        }
        resolver
    }

    /// Re-author negative fixtures so target-specific rejection follows a
    /// valid original Event/fact/Commit binding, rather than stale signatures.
    fn reseal_delivery_original(delivery: &mut InviteDeliveryRequestBody) {
        let raw = arkret_wire::test_support::raw_event_for_actor_at(
            delivery.invite_event.kind.as_str(),
            delivery.invite_event.scope_ref.clone(),
            delivery.invite_event.actor_id.clone(),
            serde_json::Value::Object(delivery.invite_event.payload.clone().into_iter().collect()),
            delivery.invite_event.created_at,
        )
        .unwrap();
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            raw,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let fact = delivery.producer_signer_fact.as_mut().unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
                [77; 32],
                fact.verification_method.to_string(),
            ),
            arkret_signatures::SignEventOptions::new()
                .with_created_at(delivery.invite_event.created_at),
        )
        .unwrap();
        delivery.invite_event = authored.into_event();
        fact.event_id = delivery.invite_event.event_id.clone();
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
            &delivery.invite_event,
            fact,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        delivery.invite_commit.event_ref = delivery.invite_event.event_id.clone();
        delivery.invite_commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
        let identity = arkret_canonical::canonical::unsigned_value(
            &delivery.invite_commit,
            &["commit_id", "signature"],
        )
        .unwrap();
        delivery.invite_commit.commit_id =
            arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(&identity).unwrap(),
            ));
        let unsigned =
            arkret_canonical::canonical::unsigned_value(&delivery.invite_commit, &["signature"])
                .unwrap();
        let key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&[23; 32]);
        delivery.invite_commit.signature =
            arkret_signatures::detached_object::sign_detached_object(
                &unsigned,
                arkret_wire::DetachedSignatureContext::RealmCommit,
                delivery.invite_commit.signature.verification_method.clone(),
                delivery.invite_commit.committed_at,
                &key,
            )
            .unwrap();
        arkret_signatures::detached_object::verify_detached_object_signature(
            &delivery.invite_commit.signature,
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        delivery.validate_minimal().unwrap();
    }

    fn assert_target_rejected(
        delivery: &InviteDeliveryRequestBody,
        holder: &DidCoreId,
        endpoint: Option<&Url>,
        config: &ArkretConfig,
        reason: &str,
    ) {
        let error =
            invite_delivery_target(delivery, holder, endpoint, config, &relay_resolver(config))
                .unwrap_err();
        assert!(matches!(error, RouteError::BadRequest(message) if message == reason));
    }

    #[test]
    fn relay_destination_uses_signed_account_station_without_rewriting_event() {
        let delivery = invite_delivery();
        let before = serde_json::to_vec(&delivery.invite_event).unwrap();
        let config = relay_config();
        let resolver = relay_resolver(&config);
        let endpoint = invite_delivery_target(
            &delivery,
            &core_id("ak:did_core:web:holder"),
            None,
            &config,
            &resolver,
        )
        .unwrap();
        assert_eq!(endpoint, config.stations[1].endpoint);
        assert_ne!(endpoint, config.stations[0].endpoint);
        assert_eq!(serde_json::to_vec(&delivery.invite_event).unwrap(), before);
    }

    #[test]
    fn relay_destination_rejects_holder_and_exact_account_substitution() {
        let delivery = invite_delivery();
        let config = relay_config();
        let holder = core_id("ak:did_core:web:holder");
        assert_target_rejected(
            &delivery,
            &core_id("ak:did_core:web:another-holder"),
            None,
            &config,
            "invite_delivery_subject_mismatch",
        );
        for (field, replacement) in [
            ("principal_id", "ak:did_core:web:another-holder"),
            ("station_id", "ak:did_core:web:other.example"),
        ] {
            let mut substituted = delivery.clone();
            substituted
                .invite_event
                .payload
                .get_mut("invitee_account_id")
                .unwrap()[field] = serde_json::json!(replacement);
            reseal_delivery_original(&mut substituted);
            assert_target_rejected(
                &substituted,
                &holder,
                None,
                &config,
                "invite_delivery_account_mismatch",
            );
        }

        let mut retargeted = delivery.clone();
        retargeted.invite_address.account_id.station_id = core_id("ak:did_core:web:other.example");
        reseal_delivery_original(&mut retargeted);
        assert_target_rejected(
            &retargeted,
            &holder,
            None,
            &config,
            "invite_delivery_account_mismatch",
        );
        retargeted.invite_event.payload.insert(
            "invitee_account_id".into(),
            serde_json::to_value(&retargeted.invite_address.account_id).unwrap(),
        );
        reseal_delivery_original(&mut retargeted);
        assert_target_rejected(
            &retargeted,
            &holder,
            Some(&config.stations[1].endpoint),
            &config,
            "invite_delivery_station_mismatch",
        );
    }

    #[test]
    fn relay_destination_enforces_invite_kind_and_closed_payload_extensions() {
        let delivery = invite_delivery();
        let config = relay_config();
        let holder = core_id("ak:did_core:web:holder");
        let resolver = relay_resolver(&config);
        let mut wrong_kind = delivery.clone();
        wrong_kind.invite_event.kind = EventKind::ViewCreate;
        reseal_delivery_original(&mut wrong_kind);
        assert_target_rejected(
            &wrong_kind,
            &holder,
            None,
            &config,
            "invalid_invite_event_kind",
        );
        for field in ["unknown", "x_", "x_Invalid"] {
            let mut invalid = delivery.clone();
            invalid
                .invite_event
                .payload
                .insert(field.into(), serde_json::json!(true));
            reseal_delivery_original(&mut invalid);
            let error =
                invite_delivery_target(&invalid, &holder, None, &config, &resolver).unwrap_err();
            assert!(
                matches!(error, RouteError::BadRequest(message) if message.starts_with("invalid_invite_payload:"))
            );
        }
        let mut extended = delivery;
        extended
            .invite_event
            .payload
            .insert("x_vendor".into(), serde_json::json!({"enabled": true}));
        reseal_delivery_original(&mut extended);
        assert_eq!(
            invite_delivery_target(&extended, &holder, None, &config, &resolver).unwrap(),
            config.stations[1].endpoint,
        );
    }

    #[test]
    fn relay_destination_rejects_url_substitution_even_on_a_trusted_host() {
        let delivery = invite_delivery();
        let holder = core_id("ak:did_core:web:holder");
        let config = relay_config();
        for endpoint in [
            "https://other.example/",
            "https://auth.example:444/",
            "https://auth.example/other/",
            "http://auth.example/",
        ] {
            let endpoint = Url::parse(endpoint).unwrap();
            assert!(config.is_trusted_outbound_target(&endpoint));
            assert_target_rejected(
                &delivery,
                &holder,
                Some(&endpoint),
                &config,
                "invite_delivery_station_mismatch",
            );
        }
    }

    #[test]
    fn relay_destination_accepts_each_configured_endpoint_for_the_signed_station() {
        let delivery = invite_delivery();
        let holder = core_id("ak:did_core:web:holder");
        let mut config = relay_config();
        let mut alternate = config.stations[1].clone();
        alternate.name = "recipient-alternate".into();
        alternate.endpoint = Url::parse("https://auth.example:8443/alternate/").unwrap();
        config.stations.push(alternate.clone());
        let resolver = relay_resolver(&config);
        assert_eq!(
            invite_delivery_target(&delivery, &holder, None, &config, &resolver).unwrap(),
            config.stations[1].endpoint,
        );
        assert_eq!(
            invite_delivery_target(
                &delivery,
                &holder,
                Some(&alternate.endpoint),
                &config,
                &resolver,
            )
            .unwrap(),
            alternate.endpoint,
        );
        for endpoint in [
            "https://auth.example:8443/other/",
            "https://auth.example:8444/alternate/",
        ] {
            assert_target_rejected(
                &delivery,
                &holder,
                Some(&Url::parse(endpoint).unwrap()),
                &config,
                "invite_delivery_station_mismatch",
            );
        }
    }

    #[test]
    fn relay_destination_requires_a_verified_station_binding() {
        let delivery = invite_delivery();
        let holder = core_id("ak:did_core:web:holder");
        let config = relay_config();
        let mut unknown_station = delivery.clone();
        unknown_station.invite_address.account_id.station_id =
            core_id("ak:did_core:web:unconfigured.example");
        unknown_station
            .invite_event
            .payload
            .get_mut("invitee_account_id")
            .unwrap()["station_id"] = serde_json::json!("ak:did_core:web:unconfigured.example");
        reseal_delivery_original(&mut unknown_station);
        assert_target_rejected(
            &unknown_station,
            &holder,
            None,
            &config,
            "invite_delivery_station_unknown",
        );
        let resolver = StationTrustResolver::new();
        assert!(matches!(
            invite_delivery_target(&delivery, &holder, None, &config, &resolver),
            Err(RouteError::BadRequest(message)) if message == "invite_delivery_station_unknown"
        ));
        resolver.insert_for_test(&config.stations[1].endpoint, "ak:did_core:web:auth.example");
        assert_eq!(
            invite_delivery_target(
                &delivery,
                &holder,
                Some(&config.stations[1].endpoint),
                &config,
                &resolver,
            )
            .unwrap(),
            config.stations[1].endpoint,
        );
    }

    #[tokio::test]
    async fn relay_uses_only_the_actual_recipient_admission_endpoint() {
        setup();
        for (status, response, expected_ok) in [
            (200, serde_json::json!({"status":"accepted"}), true),
            (200, serde_json::json!({"status":"deferred"}), true),
            (503, serde_json::json!({}), false),
        ] {
            let server = MockServer::start().await;
            let expected_attempts = if status == 503 { 2 } else { 1 };
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(r"^/_arkret/peer/invites$"))
                .respond_with(ResponseTemplate::new(status).set_body_json(response))
                .expect(expected_attempts)
                .mount(&server)
                .await;
            let base = Url::parse(&format!("{}/", server.uri())).unwrap();
            let http = reqwest::Client::new();
            let keyring = test_keyring();
            let original = invite_delivery();
            let original_bytes = arkret_canonical::canonical_json_bytes(&original).unwrap();
            let relay_source = core_id("ak:did_core:web:relay.example");
            let recipient_station = original.invite_address.account_id.station_id.clone();
            let identity = arkret_models_crypto::http_bodies::KeyPackagesClaimServiceBinding {
                source_id: relay_source.clone(),
                destination_id: recipient_station.clone(),
            };
            let peer = PeerProtocolClient::new(
                Some(&base),
                &http,
                &keyring,
                arkret_identifiers::Did::new("did:web:relay.example").unwrap(),
                identity,
                trust_domain(),
                trust_domain(),
            )
            .unwrap();
            let outcome = relay_invite_with(&peer, &original).await;
            assert_eq!(outcome.status, "forwarded");
            assert_eq!(outcome.forwarded_ok, expected_ok);
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len() as u64, expected_attempts);
            for request in &requests {
                assert_eq!(request.body, original_bytes);
                let header = |name: &str| request.headers.get(name).unwrap().to_str().unwrap();
                assert_eq!(header("Source-Service-ID"), relay_source.as_str());
                assert_eq!(header("Destination-Service-ID"), recipient_station.as_str());
                assert_eq!(
                    header("Arkret-Operation"),
                    arkret_wire::ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT_V1,
                );
                assert_eq!(header("Idempotency-Key"), original.idempotency_key);
                for component in [
                    "source-service-id",
                    "destination-service-id",
                    "arkret-operation",
                    "content-digest",
                    "idempotency-key",
                ] {
                    assert!(header("Signature-Input").contains(component));
                }
                assert!(!header("Signature").is_empty());
            }
        }
    }

    #[test]
    fn relay_rejects_native_consent_identifier_and_gate_only_requests() {
        let body = serde_json::json!({
            "inviter_id":"ak:did_core:web:inviter",
            "target_holder_principal_id":"ak:did_core:web:holder",
            "consent_id":"native-cell-is-retired", "scope":"invite"
        });
        assert!(serde_json::from_value::<InviteRelayRequestBody>(body).is_err());
    }
}
