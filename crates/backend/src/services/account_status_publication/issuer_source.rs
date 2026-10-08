//! Internal retained authoring provenance; never a protocol or public read carrier.

use arkret_identity::{AcceptedDidBinding, DidBindingPurpose};
use arkret_models_collaboration::account_status::AccountStatusRecord;
use arkret_models_identity::AccountBindingReceipt;
use arkret_wire::{Did, DidCoreId, DidUrl, Hash};
use chrono::{DateTime, Utc};
use coauth_data::PrincipalDidBinding;
use serde::{Deserialize, Serialize};

use crate::services::did_binding::AuthorityDocument;

/// Request-owned real resolver context; no globals or synthetic acceptance.
#[derive(Clone)]
pub struct AccountStatusIssuerContext {
    http_client: reqwest::Client,
    url_builder: coauth_data::UrlBuilder,
    config: coauth_config::ArkretConfig,
    delegated_identity: Option<coauth_config::DelegatedStationIdentity>,
    resolver: crate::services::did_resolver::DidResolverServiceHandle,
    store: crate::services::did_binding::VerifiedDidBindingStoreHandle,
}

impl AccountStatusIssuerContext {
    pub(crate) fn from_components(
        http_client: reqwest::Client,
        url_builder: coauth_data::UrlBuilder,
        config: coauth_config::ArkretConfig,
        resolver: crate::services::did_resolver::DidResolverServiceHandle,
        store: crate::services::did_binding::VerifiedDidBindingStoreHandle,
    ) -> Self {
        let delegated_identity = config.runtime_owning_station_identity.get();
        Self {
            http_client,
            url_builder,
            config,
            delegated_identity,
            resolver,
            store,
        }
    }

    pub fn from_depot(depot: &salvo::Depot) -> Result<Self, crate::handlers::common::RouteError> {
        use crate::handlers::common::DepotExt as _;
        Ok(Self::from_components(
            depot.http_client()?,
            depot.url_builder()?,
            depot.arkret_config()?,
            depot.did_resolver_service()?,
            depot.verified_did_binding_store()?,
        ))
    }

    pub fn ensure_current_authority(&self, authority: &DidCoreId) -> Result<(), String> {
        let captured = self
            .delegated_identity
            .as_ref()
            .ok_or("account_status_delegated_issuer_unavailable")?;
        let current = self
            .config
            .runtime_owning_station_identity
            .get()
            .ok_or("account_status_delegated_issuer_unavailable")?;
        if current.station_id != captured.station_id
            || current.did != captured.did
            || captured.station_id != *authority
        {
            return Err("account_status_issuer_context_changed".into());
        }
        Ok(())
    }

    pub async fn prepare(
        &self,
        repo: &mut coauth_data::BoxRepository,
        keyring: &coauth_keyring::Keyring,
        authority: &DidCoreId,
        binding: &PrincipalDidBinding,
        now: DateTime<Utc>,
    ) -> Result<PreparedAccountStatusIssuerSource, String> {
        self.ensure_current_authority(authority)?;
        validate_original_binding_tuple(binding, authority)?;
        let now = arkret_canonical::normalize_timestamp_canonical(now);
        let own = crate::handlers::arkret::owning_station_id_for(&self.config);
        let did = crate::handlers::arkret::owning_station_did_for(&self.config);
        let method = DidUrl::new(format!(
            "{}#{}",
            did,
            crate::services::peer_protocol_client::ACCOUNT_AUTHORITY_VERIFICATION_METHOD_FRAGMENT
        ))
        .map_err(|e| e.to_string())?;
        if &own != authority
            || binding.binding_receipt.account_authority_id != own
            || binding.binding_receipt.proof.verification_method != method
        {
            return Err("account_status_actual_issuer_mismatch".into());
        }
        let source = crate::services::did_binding::authority_document(
            &self.http_client,
            &self.url_builder,
            &self.config,
            keyring,
            repo,
            self.resolver.as_ref(),
            self.store.as_ref(),
            did.as_str(),
            DidBindingPurpose::Issuer,
            crate::services::did_binding::high_risk_freshness(),
            now,
        )
        .await
        .map_err(|e| e.to_string())?;
        self.ensure_current_authority(authority)?;
        PreparedAccountStatusIssuerSource::from_accepted_document(
            source, authority, &method, keyring, now,
        )
    }
}

/// The accepted current issuer document is captured only for NEW authoring.
/// Loading an old Record never constructs this from today's discovery.
pub struct PreparedAccountStatusIssuerSource {
    accepted: AcceptedDidBinding,
    authority_id: DidCoreId,
    verification_method: DidUrl,
    prepared_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedAccountStatusIssuerSource {
    record_id: arkret_wire::AccountStatusRecordId,
    record_digest: Hash,
    accepted: AcceptedDidBinding,
    prepared_at: DateTime<Utc>,
    binding_receipt: AccountBindingReceipt,
    binding_receipt_digest: Hash,
}

impl PreparedAccountStatusIssuerSource {
    pub fn from_accepted_document(
        source: AuthorityDocument,
        authority_id: &DidCoreId,
        method: &DidUrl,
        keyring: &coauth_keyring::Keyring,
        now: DateTime<Utc>,
    ) -> Result<Self, String> {
        let accepted = source.accepted;
        let document: crate::handlers::arkret::DidDocument = serde_json::from_value(
            serde_json::to_value(accepted.document()).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let did = Did::new(document.id.clone()).map_err(|e| e.to_string())?;
        if arkret_wire::project_did_to_core_id(&did).map_err(|e| e.to_string())? != *authority_id
            || accepted.binding().purpose() != DidBindingPurpose::Issuer
            || !accepted.binding().is_usable_for_authority(
                &crate::services::did_binding::high_risk_freshness().requirement(),
                now,
            )
        {
            return Err("account_status_issuer_source_unavailable".into());
        }
        let material = source_key(&accepted, method)?;
        let seed = keyring
            .account_authority_seed()
            .map_err(|e| e.to_string())?;
        let signing = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&seed);
        if material.ed25519_bytes().map_err(|e| e.to_string())?
            != *signing.verifying_key().as_bytes()
        {
            return Err("account_status_issuer_key_mismatch".into());
        }
        Ok(Self {
            accepted,
            authority_id: authority_id.clone(),
            verification_method: method.clone(),
            prepared_at: now,
        })
    }

    pub fn retain_for(
        &self,
        record: &AccountStatusRecord,
        binding: &PrincipalDidBinding,
    ) -> Result<serde_json::Value, String> {
        record.validate_shape().map_err(|e| e.to_string())?;
        validate_original_binding_tuple(binding, &self.authority_id)?;
        if !self.accepted.binding().is_usable_for_authority(
            &crate::services::did_binding::high_risk_freshness().requirement(),
            record.issued_at,
        ) {
            return Err("account_status_new_issuer_source_expired".into());
        }
        if record.account_authority_id != self.authority_id
            || record.proof.verification_method != self.verification_method
            || record.issued_at < self.prepared_at
            || record.account_id != binding.account_id
            || record.principal_control_realm_id != binding.principal_control_realm_id
            || record.binding_version != binding.binding_version
            || record.account_authority_id != binding.binding_receipt.account_authority_id
        {
            return Err("account_status_issuer_source_mismatch".into());
        }
        arkret_signatures::account_status::verify_account_status_record(
            record,
            &source_key(&self.accepted, &self.verification_method)?,
        )
        .map_err(|e| e.to_string())?;
        let receipt_digest = Hash::new(
            arkret_canonical::canonical_sha256(&binding.binding_receipt)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if receipt_digest != binding.binding_receipt_digest {
            return Err("account_status_binding_receipt_mismatch".into());
        }
        serde_json::to_value(RetainedAccountStatusIssuerSource {
            record_id: record.account_status_record_id.clone(),
            record_digest: signed_record_digest(record)?,
            accepted: self.accepted.clone(),
            prepared_at: self.prepared_at,
            binding_receipt: binding.binding_receipt.clone(),
            binding_receipt_digest: receipt_digest,
        })
        .map_err(|e| e.to_string())
    }
}

/// The Receipt has no PCR or binding-version fields. Those coordinates come
/// from the locked durable binding; never invent them inside the signed Receipt.
fn validate_original_binding_tuple(
    binding: &PrincipalDidBinding,
    authority: &DidCoreId,
) -> Result<(), String> {
    let receipt = &binding.binding_receipt;
    receipt.validate_shape().map_err(|e| e.to_string())?;
    let subject = crate::handlers::arkret::account_subject(authority, binding.user_id)
        .map_err(|e| e.to_string())?;
    if receipt.account_authority_id != *authority
        || receipt.account_subject != subject
        || receipt.principal_id != binding.principal_id
        || receipt.did != binding.verified_did
        || receipt.did_version_id != binding.verified_version_id
        || binding.account_id.principal_id != binding.principal_id
        || binding.account_id.station_id != *authority
        || binding.audience_id != *authority
        || binding.accepted_id != *authority
        || binding.binding_version == 0
    {
        return Err("account_status_original_binding_tuple_mismatch".into());
    }
    Ok(())
}

fn source_key(
    accepted: &AcceptedDidBinding,
    method: &DidUrl,
) -> Result<arkret_signatures::PublicKeyMaterial, String> {
    let document: crate::handlers::arkret::DidDocument = serde_json::from_value(
        serde_json::to_value(accepted.document()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if !document
        .assertion_method
        .iter()
        .any(|id| id == method.as_str())
    {
        return Err("account_status_issuer_method_not_authorized".into());
    }
    let key = document
        .verification_method
        .iter()
        .find(|key| key.id == method.as_str())
        .ok_or("account_status_issuer_method_missing")?;
    if key.controller != document.id {
        return Err("account_status_issuer_controller_mismatch".into());
    }
    key.enforce_formal_key_admission(&document.id, None)
        .map_err(|e| e.to_string())?;
    key.public_key_material()
}

pub fn signed_record_digest(record: &AccountStatusRecord) -> Result<Hash, String> {
    record.validate_shape().map_err(|e| e.to_string())?;
    Hash::new(arkret_canonical::canonical_sha256(record).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

pub fn verify_retained_account_status_source(
    value: serde_json::Value,
    record: &AccountStatusRecord,
    binding: &PrincipalDidBinding,
) -> Result<Hash, String> {
    let source: RetainedAccountStatusIssuerSource =
        serde_json::from_value(value).map_err(|e| e.to_string())?;
    validate_original_binding_tuple(binding, &record.account_authority_id)?;
    let digest = signed_record_digest(record)?;
    let original_receipt_digest = Hash::new(
        arkret_canonical::canonical_sha256(&source.binding_receipt).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if source.binding_receipt_digest != original_receipt_digest {
        return Err("account_status_original_receipt_digest_mismatch".into());
    }
    let did = Did::new(source.accepted.document().id.to_string()).map_err(|e| e.to_string())?;
    if source.record_id != record.account_status_record_id
        || source.record_digest != digest
        || arkret_wire::project_did_to_core_id(&did).map_err(|e| e.to_string())?
            != record.account_authority_id
        || source.accepted.binding().purpose() != DidBindingPurpose::Issuer
        || record.account_id != binding.account_id
        || record.principal_control_realm_id != binding.principal_control_realm_id
        || record.binding_version != binding.binding_version
        || record.account_authority_id != binding.binding_receipt.account_authority_id
        || source.binding_receipt != binding.binding_receipt
        || source.binding_receipt_digest != binding.binding_receipt_digest
        || source.prepared_at > record.issued_at
    {
        return Err("account_status_retained_source_mismatch".into());
    }
    // Validate at ORIGINAL authoring time; today's expiry/rotation must not erase historical truth.
    if !source.accepted.binding().is_usable_for_authority(
        &crate::services::did_binding::high_risk_freshness().requirement(),
        record.issued_at,
    ) {
        return Err("account_status_retained_source_unavailable".into());
    }
    arkret_signatures::account_status::verify_account_status_record(
        record,
        &source_key(&source.accepted, &record.proof.verification_method)?,
    )
    .map_err(|e| e.to_string())?;
    Ok(digest)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use async_trait::async_trait;

    use super::*;
    use crate::services::did_resolver::{
        DidResolution, DidResolutionSource, DidResolveError, DidResolverService,
        DidResolverServiceHandle, ResolverEgressPolicy,
    };

    /// Fixture transport for one exact original document. WebVH documents are
    /// admitted only after the real SDK chain verifier validates their log.
    struct OriginalIssuerResolver {
        original: DidResolution,
        inner: DidResolverServiceHandle,
    }

    #[async_trait]
    impl DidResolverService for OriginalIssuerResolver {
        fn service_id(&self, config: &coauth_config::ArkretConfig) -> DidCoreId {
            self.inner.service_id(config)
        }
        fn issuer_did(&self, config: &coauth_config::ArkretConfig) -> Did {
            self.inner.issuer_did(config)
        }
        fn resolver_egress_policy(&self) -> &ResolverEgressPolicy {
            self.inner.resolver_egress_policy()
        }
        async fn primary_did_for_user(
            &self,
            repo: &mut coauth_data::BoxRepository,
            config: &coauth_config::ArkretConfig,
            user: &coauth_data::User,
        ) -> Result<Did, crate::handlers::arkret::SessionGrantError> {
            self.inner.primary_did_for_user(repo, config, user).await
        }
        fn delegated_resolver(&self, config: &coauth_config::ArkretConfig) -> Option<String> {
            self.inner.delegated_resolver(config)
        }
        fn proof_required_for_pairwise(&self, config: &coauth_config::ArkretConfig) -> bool {
            self.inner.proof_required_for_pairwise(config)
        }
        async fn resolve_did_document(
            &self,
            http: &reqwest::Client,
            url: &coauth_data::UrlBuilder,
            config: &coauth_config::ArkretConfig,
            keyring: &coauth_keyring::Keyring,
            repo: &mut coauth_data::BoxRepository,
            did: &str,
        ) -> Result<DidResolution, DidResolveError> {
            if did == self.original.document.id {
                return Ok(self.original.clone());
            }
            self.inner
                .resolve_did_document(http, url, config, keyring, repo, did)
                .await
        }
        async fn resolve_did_binding_evidence(
            &self,
            http: &reqwest::Client,
            url: &coauth_data::UrlBuilder,
            config: &coauth_config::ArkretConfig,
            keyring: &coauth_keyring::Keyring,
            repo: &mut coauth_data::BoxRepository,
            did: &str,
        ) -> Result<DidResolution, DidResolveError> {
            if did == self.original.document.id {
                return Ok(self.original.clone());
            }
            self.inner
                .resolve_did_binding_evidence(http, url, config, keyring, repo, did)
                .await
        }
    }

    pub(crate) fn web_issuer_resolver(
        config: &coauth_config::ArkretConfig,
        keyring: &coauth_keyring::Keyring,
    ) -> DidResolverServiceHandle {
        let did = crate::handlers::arkret::owning_station_did_for(config);
        assert!(
            did.as_str().starts_with("did:web:"),
            "non-Web issuer requires original verified history"
        );
        let seed = keyring.account_authority_seed().unwrap();
        let key = crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(&seed);
        let method = format!("{did}#account-authority");
        // DID Web has no native history. This fixture supplies its exact HTTP
        // document, with the same explicit method and designated custody key.
        let document = serde_json::from_value(serde_json::json!({
            "id": did, "verificationMethod": [{ "id": method,
                "type": "JsonWebKey2020", "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519",
                    "x": arkret_canonical::base64url_encode(key.verifying_key().as_bytes()) }}],
            "assertionMethod": [method]
        }))
        .unwrap();
        std::sync::Arc::new(OriginalIssuerResolver {
            original: DidResolution {
                document,
                source: DidResolutionSource::DidWeb,
                verified_local_binding: false,
                key_log_head: None,
                method_evidence: serde_json::json!({"resolver":"did_web"}),
                closed_method_evidence: None,
                identity_fact_rejection: None,
            },
            inner: crate::services::did_resolver::default_did_resolver_service(config),
        })
    }

    pub(crate) fn webvh_issuer_resolver(
        config: &coauth_config::ArkretConfig,
        history: &[u8],
    ) -> DidResolverServiceHandle {
        let did = crate::handlers::arkret::owning_station_did_for(config);
        let verified = arkret_identity::verify_did_webvh_v1_chain_bytes(&did, history).unwrap();
        let document = serde_json::from_value(verified.head_state.clone()).unwrap();
        let key_log_head =
            Hash::new(arkret_canonical::canonical_sha256(&verified.raw_entries).unwrap()).unwrap();
        std::sync::Arc::new(OriginalIssuerResolver {
            original: DidResolution {
                document,
                source: DidResolutionSource::DelegatedResolver,
                verified_local_binding: false,
                key_log_head: Some(key_log_head),
                method_evidence: serde_json::json!({ "method":"did:webvh",
                    "history_evidence_kind":"webvh_key_log", "controller_proof_verified":true }),
                closed_method_evidence: None,
                identity_fact_rejection: None,
            },
            inner: crate::services::did_resolver::default_did_resolver_service(config),
        })
    }
}

#[cfg(test)]
mod tests {
    use coauth_data::{Clock as _, RepositoryAccess as _};
    use rand_core::SeedableRng as _;

    use super::*;
    use crate::handlers::test_utils::{TestState, setup, unique_test_nonce};

    #[tokio::test]
    async fn status_original_retention_rollback_and_expired_preparation_preserve_authoritative_state()
     {
        setup();
        let pool = coauth_storage_postgres::test_utils::setup_test_pool()
            .await
            .expect("actual PostgreSQL is required for original retention");
        let mut state = TestState::from_pool_with_station(pool.clone())
            .await
            .unwrap();
        let authority = state.configure_status_issuer_webvh();
        let mut rng = state.rng();
        let mut transaction = state.repository().await.unwrap();
        let user = transaction
            .user()
            .add(
                &mut rng,
                state.clock.as_ref(),
                format!("original-retention-{}", unique_test_nonce()),
            )
            .await
            .unwrap();
        transaction.save().await.unwrap();
        let principal = state
            .seed_principal_binding(
                &user,
                &format!("original-retention-{}", unique_test_nonce()),
            )
            .await;
        let mut transaction = state.repository().await.unwrap();
        let binding = transaction
            .principal_did()
            .get_by_principal_id_and_audience(&principal, authority.as_str())
            .await
            .unwrap()
            .unwrap();
        let original = transaction
            .account_status_ledger()
            .current_for_gate(authority.as_str(), &user.id.to_string())
            .await
            .unwrap()
            .unwrap();
        let context = state.account_status_issuer_context();
        let mut stale_binding = binding.clone();
        stale_binding.binding_version += 1;
        assert!(
            super::super::author_and_enqueue_transition(
                &mut transaction,
                &mut rng,
                state.clock.as_ref(),
                state.station_admin.as_ref(),
                &state.keyring,
                authority.as_str(),
                &user,
                &stale_binding,
                arkret_models_collaboration::objects::account_status::AccountStatus::Suspended,
                None,
                state.clock.now(),
                &context
            )
            .await
            .is_err()
        );
        transaction.cancel().await.unwrap();
        let mut transaction = state.repository().await.unwrap();
        assert_eq!(
            transaction
                .account_status_ledger()
                .current_for_gate(authority.as_str(), &user.id.to_string())
                .await
                .unwrap(),
            Some(original.clone())
        );
        let prepared = context
            .prepare(
                &mut transaction,
                &state.keyring,
                &authority,
                &binding,
                state.clock.now(),
            )
            .await
            .unwrap();
        let publication = super::super::author_and_enqueue_transition(
            &mut transaction,
            &mut rng,
            state.clock.as_ref(),
            state.station_admin.as_ref(),
            &state.keyring,
            authority.as_str(),
            &user,
            &binding,
            arkret_models_collaboration::objects::account_status::AccountStatus::Suspended,
            None,
            state.clock.now(),
            &context,
        )
        .await
        .unwrap();
        let record = publication.body.publication.record().clone();
        let source = transaction
            .account_status_ledger()
            .issuer_source(
                authority.as_str(),
                &user.id.to_string(),
                record.account_status_record_id.as_str(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            verify_retained_account_status_source(source.clone(), &record, &binding).unwrap(),
            signed_record_digest(&record).unwrap()
        );
        transaction.cancel().await.unwrap();
        // The same original transaction contains Record, original issuer
        // material and exact publication: cancellation leaves none of them.
        let mut reopened = state.repository().await.unwrap();
        assert_eq!(
            reopened
                .account_status_ledger()
                .current_for_gate(authority.as_str(), &user.id.to_string())
                .await
                .unwrap(),
            Some(original)
        );
        assert!(
            reopened
                .account_status_ledger()
                .issuer_source(
                    authority.as_str(),
                    &user.id.to_string(),
                    record.account_status_record_id.as_str()
                )
                .await
                .unwrap()
                .is_none()
        );
        reopened.cancel().await.unwrap();
        use diesel_async::RunQueryDsl as _;
        #[derive(diesel::QueryableByName)]
        struct Footprint {
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            count: i64,
        }
        let mut conn = pool.get().await.unwrap();
        let footprint = diesel::sql_query("SELECT (SELECT count(*) FROM account_status_records WHERE record_id=$1) + (SELECT count(*) FROM queue_jobs WHERE payload::text LIKE $2) AS count")
            .bind::<diesel::sql_types::Text,_>(record.account_status_record_id.as_str())
            .bind::<diesel::sql_types::Text,_>(format!("%{}%",record.account_status_record_id))
            .get_result::<Footprint>(&mut conn).await.unwrap();
        assert_eq!(footprint.count, 0);
        drop(conn);
        // An authentic Prepared source cannot be reused for a NEW Record
        // outside its original authority freshness window. The historical
        // record, however, is checked at its own original instant forever.
        state.clock.advance(chrono::Duration::days(1));
        let late = arkret_signatures::account_status::sign_account_status_record(
            arkret_models_collaboration::account_status::UnsignedAccountStatusRecord {
                schema: record.schema.clone(),
                account_authority_id: record.account_authority_id.clone(),
                account_id: record.account_id.clone(),
                principal_control_realm_id: record.principal_control_realm_id.clone(),
                binding_version: record.binding_version,
                status_seq: record.status_seq,
                previous_account_status_record_id: record.previous_account_status_record_id.clone(),
                status: record.status,
                reason_code: record.reason_code.clone(),
                reason: record.reason.clone(),
                issued_at: state.clock.now(),
                expires_at: None,
            },
            record.proof.verification_method.clone(),
            &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(
                &state.keyring.account_authority_seed().unwrap(),
            ),
        )
        .unwrap();
        assert!(prepared.retain_for(&late, &binding).is_err());
        assert_eq!(
            verify_retained_account_status_source(source.clone(), &record, &binding).unwrap(),
            signed_record_digest(&record).unwrap()
        );
        // Rotation of current custody cannot replace the retained method's
        // old authorized key for this original Record.
        let new_keyring = coauth_keyring::Keyring::new(coauth_keyring::JsonWebKeySet::new(vec![
            coauth_keyring::JsonWebKey::new(coauth_keyring::PrivateKey::generate_ed25519(
                rand_chacha::ChaChaRng::seed_from_u64(91),
            ))
            .with_kid(coauth_keyring::ACCOUNT_AUTHORITY_KEY_ID),
        ]));
        let wrong_key_record = arkret_signatures::account_status::sign_account_status_record(
            arkret_models_collaboration::account_status::UnsignedAccountStatusRecord {
                schema: record.schema.clone(),
                account_authority_id: record.account_authority_id.clone(),
                account_id: record.account_id.clone(),
                principal_control_realm_id: record.principal_control_realm_id.clone(),
                binding_version: record.binding_version,
                status_seq: record.status_seq,
                previous_account_status_record_id: record.previous_account_status_record_id.clone(),
                status: record.status,
                reason_code: record.reason_code.clone(),
                reason: record.reason.clone(),
                issued_at: record.issued_at,
                expires_at: record.expires_at,
            },
            record.proof.verification_method.clone(),
            &crate::arkret_key_bridge::sdk_signing_key_from_seed_bytes(
                &new_keyring.account_authority_seed().unwrap(),
            ),
        )
        .unwrap();
        let mut substituted = source.clone();
        substituted["record_id"] = serde_json::json!(wrong_key_record.account_status_record_id);
        substituted["record_digest"] =
            serde_json::json!(signed_record_digest(&wrong_key_record).unwrap());
        assert!(
            verify_retained_account_status_source(substituted, &wrong_key_record, &binding)
                .is_err()
        );
        let mut current = state.repository().await.unwrap();
        assert!(
            context
                .prepare(
                    &mut current,
                    &new_keyring,
                    &authority,
                    &binding,
                    state.clock.now()
                )
                .await
                .is_err()
        );
        current.cancel().await.unwrap();
        assert_eq!(
            verify_retained_account_status_source(source.clone(), &record, &binding).unwrap(),
            signed_record_digest(&record).unwrap()
        );
        let mut wrong_record = record.clone();
        wrong_record.binding_version += 1;
        assert!(
            verify_retained_account_status_source(source.clone(), &wrong_record, &binding).is_err()
        );
        let mut wrong_binding = binding.clone();
        wrong_binding.principal_control_realm_id = arkret_wire::RealmId::from_event_id(
            &arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x74; 32]),
        );
        assert!(verify_retained_account_status_source(source, &record, &wrong_binding).is_err());
    }
}
