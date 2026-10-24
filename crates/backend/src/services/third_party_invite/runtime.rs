//! Explicit same-Station provider delegation and durable delivery recovery.
use std::sync::Arc;

use coauth_data::RepositoryFactory;
use coauth_messaging::email::Mailer;
use coauth_storage_postgres::PgRepositoryFactory;
use coland_storage::{
    InviteCurrentStateStore, PersistenceError, ThirdPartyInviteProviderLivenessGuard,
    ThirdPartyInviteProviderLivenessRequest,
};

use super::*;

/// A configured provider shares the owning Station's authoritative storage,
/// while private material remains in the separate Coauth database.
pub struct ThirdPartyInviteRuntime {
    pub(crate) factory: PgRepositoryFactory,
    pub(crate) encrypter: Encrypter,
    pub(crate) config: coauth_config::ArkretConfig,
    store: coland_storage_postgres::PgInviteCurrentStateStore,
    mailer: Mailer,
}
impl ThirdPartyInviteRuntime {
    /// Build only for explicit deployment delegation. The governing database
    /// URL is never inferred from the account database or a request.
    pub async fn connect(
        factory: PgRepositoryFactory,
        encrypter: Encrypter,
        config: coauth_config::ArkretConfig,
        mailer: Mailer,
    ) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            mailer.provider_binding_key() != "email.blackhole",
            "IVS delegation requires actual out-of-band delivery"
        );
        let url = &config
            .third_party_invite_provider
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IVS delegation is absent"))?
            .governance_database_url;
        if url.trim().is_empty() {
            anyhow::bail!("IVS governing database must be explicit");
        }
        let db = coland_storage_postgres::Db::connect(
            Some(url),
            coland_storage_postgres::PoolTuning {
                max_size: Some(4),
                acquire_timeout_seconds: Some(30),
            },
        )
        .await?;
        let pool = db
            .pool
            .ok_or_else(|| anyhow::anyhow!("IVS governing database unavailable"))?;
        Ok(Arc::new(Self {
            factory,
            encrypter,
            config,
            store: coland_storage_postgres::PgInviteCurrentStateStore { pool },
            mailer,
        }))
    }
    pub(crate) async fn provision_guard(
        &self,
        request: &ThirdPartyInviteProvisionRequestBody,
    ) -> Result<Box<dyn ThirdPartyInviteProviderLivenessGuard>, PersistenceError> {
        let owning = self
            .config
            .runtime_owning_station_identity
            .get()
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "revision_unavailable: owning Station not verified".into(),
                )
            })?;
        self.store
            .acquire_third_party_invite_provision_device(request, &owning.station_id, &Utc::now)
            .await
    }
    pub(crate) async fn guard(
        &self,
        c: &Custody,
    ) -> Result<Box<dyn ThirdPartyInviteProviderLivenessGuard>, PersistenceError> {
        let activation = c
            .activation
            .as_ref()
            .ok_or_else(|| PersistenceError::NotFound("private invite unavailable".into()))?;
        let owning = self
            .config
            .runtime_owning_station_identity
            .get()
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "revision_unavailable: owning Station not verified".into(),
                )
            })?;
        if owning.station_id != c.public.third_party_invite.verification_id
            || owning.station_id != c.public.inviter_account_id.station_id
        {
            return Err(PersistenceError::NotFound(
                "private invite unavailable".into(),
            ));
        }
        self.store
            .acquire_third_party_invite_provider_liveness(
                &ThirdPartyInviteProviderLivenessRequest {
                    realm_id: c.public.realm_id.clone(),
                    invite_id: activation.invite_id.clone(),
                    inviter_account_id: c.public.inviter_account_id.clone(),
                    third_party_invite: c.public.third_party_invite.clone(),
                    expires_at: c.public.expires_at,
                },
                &owning.station_id,
                &Utc::now,
            )
            .await
    }
    /// Run bounded polling under the server's managed cancellation lifecycle.
    pub async fn run(self: Arc<Self>, cancel: tokio_util::sync::CancellationToken) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _=cancel.cancelled()=>return,
                _=interval.tick()=>{
                    if self.config.runtime_owning_station_identity.get().is_none() {continue;}
                    tokio::select! {
                        _=cancel.cancelled()=>return,
                        result=self.poll_once()=>{if result.is_err() {tracing::warn!("IVS delivery/cleanup attempt failed; durable intent retained");}}
                    }
                }
            }
        }
    }
    async fn poll_once(&self) -> Result<(), InviteError> {
        // Never hold the private row while acquiring a governance lock.
        let mut preview = self.factory.create().await?;
        let row = preview.third_party_invite().due(Utc::now()).await?;
        preview.cancel().await?;
        let Some(row) = row else {
            return Ok(());
        };
        let c = decrypt(&row, &self.encrypter)?;
        if c.state == ThirdPartyInviteProvisioningState::Provisioned {
            let mut repo = self.factory.create().await?;
            let Some(row) = repo.third_party_invite().find(&row.handle_digest).await? else {
                return Ok(());
            };
            let mut c = decrypt(&row, &self.encrypter)?;
            if c.state == ThirdPartyInviteProvisioningState::Provisioned
                && Utc::now() >= c.public.activation_expires_at
            {
                c.state = ThirdPartyInviteProvisioningState::Expired;
                c.secrets = None;
                update(&mut repo, row, &c, &self.encrypter).await?;
            }
            repo.save().await?;
            return Ok(());
        }
        if c.state != ThirdPartyInviteProvisioningState::Activated {
            return Ok(());
        }
        // Private expiry cleanup does not depend on an available governance DB.
        if Utc::now() >= c.public.expires_at {
            let mut repo = self.factory.create().await?;
            let found = repo.third_party_invite().find(&row.handle_digest).await?;
            if let Some(row) = found {
                let mut current = decrypt(&row, &self.encrypter)?;
                if current.state == ThirdPartyInviteProvisioningState::Activated
                    && Utc::now() >= current.public.expires_at
                {
                    current.state = ThirdPartyInviteProvisioningState::Expired;
                    current.secrets = None;
                    update(&mut repo, row, &current, &self.encrypter).await?;
                }
            }
            repo.save().await?;
            return Ok(());
        }
        let gate = self.guard(&c).await;
        let mut repo = self.factory.create().await?;
        let Some(mut row) = repo.third_party_invite().find(&row.handle_digest).await? else {
            return Ok(());
        };
        let mut c = decrypt(&row, &self.encrypter)?;
        if c.state != ThirdPartyInviteProvisioningState::Activated {
            repo.cancel().await?;
            return Ok(());
        }
        let guard = match gate {
            Ok(guard) => guard,
            Err(PersistenceError::NotFound(_)) => {
                c.state = ThirdPartyInviteProvisioningState::Revoked;
                c.secrets = None;
                update(&mut repo, row, &c, &self.encrypter).await?;
                repo.save().await?;
                return Ok(());
            }
            Err(PersistenceError::Conflict(ref reason))
                if reason.starts_with("unsupported_join_rule:") =>
            {
                // An unsupported policy pauses this handoff; it does not
                // withdraw the accepted invite or destroy its original code.
                row.deliver_after = Some(Utc::now() + Duration::seconds(30));
                update(&mut repo, row, &c, &self.encrypter).await?;
                repo.save().await?;
                return Err(InviteError::UnsupportedFeature);
            }
            Err(_) => {
                row.deliver_after = Some(Utc::now() + Duration::seconds(30));
                update(&mut repo, row, &c, &self.encrypter).await?;
                repo.save().await?;
                return Err(InviteError::NotFound);
            }
        };
        let now = guard.observed_at();
        if now >= c.public.expires_at {
            c.state = ThirdPartyInviteProvisioningState::Expired;
            c.secrets = None;
        } else if c.delivery_state == Some(ThirdPartyInviteDeliveryState::Queued) {
            let secret = c.secrets.as_ref().ok_or(InviteError::Internal)?;
            let address = delivery_address(&secret.delivery_target)?;
            let remaining = (c.public.expires_at - Utc::now())
                .to_std()
                .unwrap_or_default();
            let deadline = remaining.min(std::time::Duration::from_secs(30));
            let sent = tokio::time::timeout(
                deadline,
                self.mailer
                    .send_third_party_invite_code(address.into(), &secret.token),
            )
            .await;

            record_delivery_outcome(&mut c, &sent);
            if !matches!(sent, Ok(Ok(_))) {
                let (failure_class, provider_status) = delivery_failure_boundary(&sent);
                // Never format provider errors: they may contain the target,
                // request URL, code, raw response body or arbitrary extensions.
                tracing::warn!(
                    failure_class,
                    provider_status,
                    attempt = c.delivery_attempts,
                    "IVS delivery transport did not confirm success; original retry schedule retained"
                );
            }
        }
        if Utc::now() >= c.public.expires_at {
            c.state = ThirdPartyInviteProvisioningState::Expired;
            c.secrets = None;
        }
        row.deliver_after = Some(
            now + Duration::seconds(
                if c.delivery_state == Some(ThirdPartyInviteDeliveryState::Queued) {
                    30 * (1_i64 << c.delivery_attempts.min(3))
                } else {
                    30
                },
            ),
        );
        update(&mut repo, row, &c, &self.encrypter).await?;
        repo.save().await?;
        guard.finish().await.map_err(|_| InviteError::Internal)?;
        Ok(())
    }
}

fn record_delivery_outcome(
    custody: &mut Custody,
    result: &Result<
        Result<coauth_messaging::email::SendResult, coauth_messaging::email::MailerError>,
        tokio::time::error::Elapsed,
    >,
) {
    custody.delivery_attempts += 1;
    // A later definite failure cannot erase an earlier uncertain send.
    custody.delivery_may_have_succeeded |= delivery_outcome_uncertain(result);
    custody.delivery_state = Some(if matches!(result, Ok(Ok(_))) {
        ThirdPartyInviteDeliveryState::Delivered
    } else if custody.delivery_attempts >= 3 {
        ThirdPartyInviteDeliveryState::Failed
    } else {
        ThirdPartyInviteDeliveryState::Queued
    });
    if custody.delivery_state == Some(ThirdPartyInviteDeliveryState::Failed) {
        // Exhaustion abandons only private delivery. Stop retries and destroy
        // recovery material without asserting any shared Invite revocation.
        custody.secrets = None;
    }
}

fn delivery_outcome_uncertain(
    result: &Result<
        Result<coauth_messaging::email::SendResult, coauth_messaging::email::MailerError>,
        tokio::time::error::Elapsed,
    >,
) -> bool {
    use coauth_messaging::email::{EmailTransportError, MailerError};
    match result {
        Err(_) => true,
        Ok(Err(MailerError::Transport(EmailTransportError::Http(error)))) => !error.is_connect(),
        Ok(Err(MailerError::Transport(EmailTransportError::ProviderError { status, .. }))) => {
            *status >= 500
        }
        Ok(Err(MailerError::Transport(
            EmailTransportError::Smtp(_) | EmailTransportError::Sendmail(_),
        ))) => true,
        _ => false,
    }
}

/// A process-only diagnostic boundary with no private transport material.
fn delivery_failure_boundary(
    result: &Result<
        Result<coauth_messaging::email::SendResult, coauth_messaging::email::MailerError>,
        tokio::time::error::Elapsed,
    >,
) -> (&'static str, u16) {
    use coauth_messaging::email::{EmailTransportError, MailerError};

    match result {
        Err(_) => ("delivery_deadline", 0),
        Ok(Err(MailerError::Transport(error))) => match error {
            EmailTransportError::ProviderError { status, .. } => ("provider_status", *status),
            EmailTransportError::Http(error) if error.is_timeout() => ("http_timeout", 0),
            EmailTransportError::Http(error) if error.is_connect() => ("http_connect", 0),
            EmailTransportError::Http(_) => ("http_other", 0),
            EmailTransportError::Smtp(_) => ("smtp", 0),
            EmailTransportError::Sendmail(_) => ("sendmail", 0),
            EmailTransportError::Message(_) => ("message", 0),
            EmailTransportError::Json(_) => ("json", 0),
        },
        Ok(Err(MailerError::Templates(_))) => ("template", 0),
        Ok(Ok(_)) => ("accepted", 0),
    }
}

#[cfg(test)]
mod private_custody_tests {
    use rand_core::SeedableRng;

    use super::*;

    // The real private poller is tested directly, without claiming a Station
    // current/Device gate or out-of-band send. The expiry branch must not reach
    // the unconfigured governing authority or this inert mail transport.
    async fn expired_worker_scrubs_real_minted_custody(activated: bool) {
        let db = coauth_storage_postgres::test_utils::setup_test_pool()
            .await
            .expect("real isolated PostgreSQL required");
        let factory = PgRepositoryFactory::new(db.clone());
        let workspace_root = camino::Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        let templates = coauth_templates::Templates::load(
            workspace_root.join("templates"),
            coauth_data::UrlBuilder::new("https://example.com/".parse().unwrap(), None, None),
            workspace_root.join("translations"),
            coauth_templates::SiteBranding::new("example.com"),
            coauth_templates::SiteFeatures {
                password_login: true,
                password_registration: true,
                password_registration_contact_required: false,
                account_recovery: true,
                login_with_email_allowed: true,
            },
            true,
        )
        .await
        .unwrap();
        let runtime = ThirdPartyInviteRuntime {
            factory: factory.clone(),
            encrypter: Encrypter::new(&[0x42; 32]),
            config: coauth_config::ArkretConfig::default(),
            // No governance access is permitted in these expiry-only cases.
            store: coland_storage_postgres::PgInviteCurrentStateStore { pool: db.clone() },
            mailer: Mailer::new(
                templates,
                coauth_messaging::email::Transport::blackhole(),
                "hello@example.com".parse().unwrap(),
                "hello@example.com".parse().unwrap(),
            ),
        };
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(93303);
        for mode in [
            ThirdPartyInviteOobKind::OfflineToken,
            ThirdPartyInviteOobKind::Lookup,
        ] {
            let (mut request, did) = super::super::tests::request(mode);
            request.expires_at =
                arkret_canonical::normalize_timestamp_canonical(Utc::now()) + Duration::seconds(5);
            let mut repo = factory.create().await.unwrap();
            let public = provision_verified(
                &mut repo,
                &runtime.encrypter,
                &mut rng,
                &request,
                &did,
                "worker-expiry-source",
                Utc::now(),
            )
            .await
            .unwrap();
            repo.save().await.unwrap();
            let mut activation_request = None;
            let mut original_activation = None;
            if activated {
                let command = super::super::tests::ledger_activation(&public, &did, 97);
                let mut repo = factory.create().await.unwrap();
                original_activation = Some(
                    activate_verified(&mut repo, &runtime.encrypter, &command, Utc::now())
                        .await
                        .unwrap(),
                );
                repo.save().await.unwrap();
                activation_request = Some(command);
            }
            // Cold repository proves secrets existed immediately before actual
            // time expiry. The fixture never assigns terminal state or None.
            let mut before = factory.create().await.unwrap();
            let row = before
                .third_party_invite()
                .find(&digest(public.provisioning_id.as_str()))
                .await
                .unwrap()
                .unwrap();
            let custody = decrypt(&row, &runtime.encrypter).unwrap();
            assert!(custody.secrets.is_some());
            assert_eq!(
                custody.state,
                if activated {
                    ThirdPartyInviteProvisioningState::Activated
                } else {
                    ThirdPartyInviteProvisioningState::Provisioned
                }
            );
            let old_selector = row.token_selector.clone().unwrap();
            assert_eq!(activated, row.deliver_after.is_some());
            let old_ciphertext = row.encrypted_record.clone();
            drop(custody);
            before.cancel().await.unwrap();
            let wait = (public.expires_at - Utc::now())
                .to_std()
                .unwrap_or_default()
                + std::time::Duration::from_millis(100);
            tokio::time::sleep(wait).await;
            assert!(Utc::now() >= public.expires_at && Utc::now() >= public.activation_expires_at);
            // Actual due/row-lock/update/AEAD/repository commit path, not a mirror.
            runtime.poll_once().await.unwrap();
            let mut after = factory.create().await.unwrap();
            let terminal = after
                .third_party_invite()
                .find(&row.handle_digest)
                .await
                .unwrap()
                .unwrap();
            assert_ne!(terminal.encrypted_record, old_ciphertext);
            assert_eq!(terminal.state, "expired");
            assert!(terminal.token_selector.is_none() && terminal.deliver_after.is_none());
            let cleaned = decrypt(&terminal, &runtime.encrypter).unwrap();
            assert_eq!(cleaned.state, ThirdPartyInviteProvisioningState::Expired);
            assert!(cleaned.secrets.is_none());
            assert_eq!(cleaned.delivery_attempts, 0);
            assert_eq!(cleaned.activation, original_activation);
            assert!(
                after
                    .third_party_invite()
                    .find_token(&old_selector)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                after
                    .third_party_invite()
                    .due(Utc::now())
                    .await
                    .unwrap()
                    .is_none()
            );
            after.cancel().await.unwrap();
            // New runtime/repository reads the persisted scrub. Frozen public
            // outcomes replay exactly without restoring secrets or a queue.
            let mut restarted = factory.create().await.unwrap();
            let replay = provision_verified(
                &mut restarted,
                &runtime.encrypter,
                &mut rng,
                &request,
                &did,
                "worker-expiry-source",
                Utc::now(),
            )
            .await
            .unwrap();
            assert_eq!(replay, public);
            if let Some(command) = &activation_request {
                let replay =
                    activate_verified(&mut restarted, &runtime.encrypter, command, Utc::now())
                        .await
                        .unwrap();
                assert_eq!(Some(replay), original_activation);
            }
            let replay_row = restarted
                .third_party_invite()
                .find(&row.handle_digest)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(replay_row.encrypted_record, terminal.encrypted_record);
            assert!(replay_row.token_selector.is_none() && replay_row.deliver_after.is_none());
            assert!(
                decrypt(&replay_row, &runtime.encrypter)
                    .unwrap()
                    .secrets
                    .is_none()
            );
            restarted.save().await.unwrap();
        }
    }

    #[tokio::test]
    async fn delivery_exhaustion_keeps_activation_and_scrubs_cold_retry_material() {
        let db = coauth_storage_postgres::test_utils::setup_test_pool()
            .await
            .unwrap();
        let factory = PgRepositoryFactory::new(db.clone());
        let encrypter = Encrypter::new(&[0x47; 32]);
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(93304);
        let (request, did) = super::super::tests::request(ThirdPartyInviteOobKind::OfflineToken);
        let mut repo = factory.create().await.unwrap();
        let public = provision_verified(
            &mut repo,
            &encrypter,
            &mut rng,
            &request,
            &did,
            "uncertain-delivery",
            Utc::now(),
        )
        .await
        .unwrap();
        let command = super::super::tests::ledger_activation(&public, &did, 98);
        let activation = activate_verified(&mut repo, &encrypter, &command, Utc::now())
            .await
            .unwrap();
        repo.save().await.unwrap();
        let key = digest(public.provisioning_id.as_str());
        let timeout = tokio::time::timeout(
            std::time::Duration::ZERO,
            std::future::pending::<
                Result<coauth_messaging::email::SendResult, coauth_messaging::email::MailerError>,
            >(),
        )
        .await;
        let definite_failure = Ok(Err(coauth_messaging::email::MailerError::Transport(
            coauth_messaging::email::EmailTransportError::ProviderError {
                status: 400,
                code: None,
                body: String::new(),
                retryable: false,
            },
        )));
        let mut frozen_secret = None;
        let mut old_selector = None;
        for attempt in 1..=3 {
            let mut repo = factory.create().await.unwrap();
            let row = repo.third_party_invite().find(&key).await.unwrap().unwrap();
            let mut custody = decrypt(&row, &encrypter).unwrap();
            let secret = custody.secrets.as_ref().unwrap();
            let original = serde_json::to_value(secret).unwrap();
            assert_eq!(frozen_secret.get_or_insert(original.clone()), &original);
            old_selector.get_or_insert(row.token_selector.clone().unwrap());
            record_delivery_outcome(
                &mut custody,
                if attempt == 1 {
                    &timeout
                } else {
                    &definite_failure
                },
            );
            assert_eq!(custody.state, ThirdPartyInviteProvisioningState::Activated);
            assert_eq!(custody.activation.as_ref(), Some(&activation));
            assert!(custody.public == public && custody.delivery_may_have_succeeded);
            assert_eq!(custody.delivery_attempts, attempt);
            if attempt < 3 {
                assert_eq!(
                    custody.delivery_state,
                    Some(ThirdPartyInviteDeliveryState::Queued)
                );
                assert_eq!(
                    serde_json::to_value(custody.secrets.as_ref().unwrap()).unwrap(),
                    original
                );
            }
            update(&mut repo, row, &custody, &encrypter).await.unwrap();
            repo.save().await.unwrap();
        }
        let mut cold = factory.create().await.unwrap();
        let row = cold.third_party_invite().find(&key).await.unwrap().unwrap();
        let custody = decrypt(&row, &encrypter).unwrap();
        assert_eq!(custody.state, ThirdPartyInviteProvisioningState::Activated);
        assert_eq!(
            custody.delivery_state,
            Some(ThirdPartyInviteDeliveryState::Failed)
        );
        assert!(
            custody.secrets.is_none()
                && row.token_selector.is_none()
                && row.deliver_after.is_none()
        );
        assert!(
            cold.third_party_invite()
                .find_token(old_selector.as_ref().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            cold.third_party_invite()
                .due(Utc::now())
                .await
                .unwrap()
                .is_none()
        );
        let replay = activate_verified(&mut cold, &encrypter, &command, Utc::now())
            .await
            .unwrap();
        assert_eq!(replay, activation);
        let row = cold.third_party_invite().find(&key).await.unwrap().unwrap();
        assert!(decrypt(&row, &encrypter).unwrap().secrets.is_none());
        assert!(row.deliver_after.is_none());
        cold.save().await.unwrap();
    }

    #[tokio::test]
    async fn actual_poller_expires_unbound_invites_and_scrubs_cold_custody() {
        Box::pin(expired_worker_scrubs_real_minted_custody(false)).await;
    }

    #[tokio::test]
    async fn actual_poller_expires_activated_invites_and_scrubs_cold_custody() {
        Box::pin(expired_worker_scrubs_real_minted_custody(true)).await;
    }
}

#[cfg(test)]
mod delivery_outcome_tests {
    use super::*;

    #[tokio::test]
    async fn timeout_and_provider_ambiguity_are_distinct_from_definite_failure() {
        use coauth_messaging::email::{EmailTransportError, MailerError, SendResult};
        let timeout = tokio::time::timeout(
            std::time::Duration::ZERO,
            std::future::pending::<Result<SendResult, MailerError>>(),
        )
        .await;
        assert!(delivery_outcome_uncertain(&timeout));
        let provider = |status| {
            Ok(Err(MailerError::Transport(
                EmailTransportError::ProviderError {
                    status,
                    code: None,
                    body: "private response must never enter diagnostics".into(),
                    retryable: true,
                },
            )))
        };
        assert!(delivery_outcome_uncertain(&provider(503)));
        assert!(!delivery_outcome_uncertain(&provider(400)));
        assert_eq!(
            delivery_failure_boundary(&provider(503)),
            ("provider_status", 503)
        );
    }
}
