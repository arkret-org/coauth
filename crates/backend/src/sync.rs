//! Utilities to synchronize the configuration file with the database.

use std::collections::{BTreeMap, BTreeSet};

use coauth_config::{ClientsConfig, UpstreamOAuthConfig};
use coauth_data::{
    Clock, Pagination, PgRepository, RepositoryAccess, UpstreamOAuthProviderSource,
    pg::advisory_lock::advisory_lock_key,
    upstream_oauth::{UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams},
};
use coauth_keystore::Encrypter;
use diesel::sql_query;
use diesel_async::{
    AsyncPgConnection, RunQueryDsl, pooled_connection::deadpool::Object as PooledConnection,
};
use tracing::{error, info, info_span, warn};

fn map_import_action(
    config: coauth_config::UpstreamOAuthImportAction,
) -> coauth_data::UpstreamOAuthProviderImportAction {
    match config {
        coauth_config::UpstreamOAuthImportAction::Ignore => {
            coauth_data::UpstreamOAuthProviderImportAction::Ignore
        }
        coauth_config::UpstreamOAuthImportAction::Suggest => {
            coauth_data::UpstreamOAuthProviderImportAction::Suggest
        }
        coauth_config::UpstreamOAuthImportAction::Force => {
            coauth_data::UpstreamOAuthProviderImportAction::Force
        }
        coauth_config::UpstreamOAuthImportAction::Require => {
            coauth_data::UpstreamOAuthProviderImportAction::Require
        }
    }
}

fn map_import_on_conflict(
    config: coauth_config::UpstreamOAuthOnConflict,
) -> coauth_data::UpstreamOAuthProviderOnConflict {
    match config {
        coauth_config::UpstreamOAuthOnConflict::Add => {
            coauth_data::UpstreamOAuthProviderOnConflict::Add
        }
        coauth_config::UpstreamOAuthOnConflict::Replace => {
            coauth_data::UpstreamOAuthProviderOnConflict::Replace
        }
        coauth_config::UpstreamOAuthOnConflict::Set => {
            coauth_data::UpstreamOAuthProviderOnConflict::Set
        }
        coauth_config::UpstreamOAuthOnConflict::Fail => {
            coauth_data::UpstreamOAuthProviderOnConflict::Fail
        }
    }
}

fn map_claims_imports(
    config: &coauth_config::UpstreamOAuthClaimsImports,
) -> coauth_data::UpstreamOAuthProviderClaimsImports {
    coauth_data::UpstreamOAuthProviderClaimsImports {
        subject: coauth_data::UpstreamOAuthProviderSubjectPreference {
            template: config.subject.template.clone(),
        },
        skip_confirmation: config.skip_confirmation,
        handle: coauth_data::UpstreamOAuthProviderHandlePreference {
            action: map_import_action(config.handle.action),
            template: config.handle.template.clone(),
            on_conflict: map_import_on_conflict(config.handle.on_conflict),
        },
        displayname: coauth_data::UpstreamOAuthProviderImportPreference {
            action: map_import_action(config.displayname.action),
            template: config.displayname.template.clone(),
        },
        email: coauth_data::UpstreamOAuthProviderImportPreference {
            action: map_import_action(config.email.action),
            template: config.email.template.clone(),
        },
        avatar: coauth_data::UpstreamOAuthProviderImportPreference {
            action: map_import_action(config.avatar.action),
            template: config.avatar.template.clone(),
        },
        account_name: coauth_data::UpstreamOAuthProviderSubjectPreference {
            template: config.account_name.template.clone(),
        },
    }
}

#[tracing::instrument(name = "config.sync", skip_all)]
pub async fn config_sync(
    upstream_oauth_config: UpstreamOAuthConfig,
    clients_config: ClientsConfig,
    mut conn: PooledConnection<AsyncPgConnection>,
    encrypter: &Encrypter,
    clock: &dyn Clock,
    prune: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
    // Grab an advisory lock on the connection
    tracing::info!("Acquiring configuration lock");
    // Note: this string is hashed into a pg advisory-lock key. Do not rename
    // without a coordinated upgrade — it would let an old and a new process
    // hold different locks and step on each other.
    let lock_key = advisory_lock_key("coauth config sync");

    // pg_advisory_lock blocks until the lock is acquired (returns void), so
    // there is no boolean to inspect here.
    sql_query(format!("SELECT pg_advisory_lock({lock_key})"))
        .execute(&mut *conn)
        .await?;

    // Create a repository from the locked connection
    let mut repo = PgRepository::new(conn);

    tracing::info!(
        prune,
        dry_run,
        "Syncing providers and clients defined in config to database"
    );

    {
        let _span = info_span!("cli.config.sync.providers").entered();
        let config_ids = upstream_oauth_config
            .providers
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.id)
            .collect::<BTreeSet<_>>();

        // Only consider config-sourced rows. Manually-managed providers
        // (created via the admin API) must be left untouched by sync.
        let config_filter =
            UpstreamOAuthProviderFilter::default().with_source(UpstreamOAuthProviderSource::Config);

        // Let's assume we have less than 1000 providers
        let page = repo
            .upstream_oauth_provider()
            .list(config_filter, Pagination::first(1000))
            .await?;

        // A warning is probably enough
        if page.has_next_page {
            warn!(
                "More than 1000 providers in the database, only the first 1000 will be considered"
            );
        }

        let mut existing_enabled_ids = BTreeSet::new();
        let mut existing_disabled = BTreeMap::new();
        // Process the existing providers
        for edge in page.edges {
            let provider = edge.node;
            if provider.enabled() {
                if config_ids.contains(&provider.id) {
                    existing_enabled_ids.insert(provider.id);
                } else {
                    // Provider is enabled in the database but not in the config
                    info!(%provider.id, "Disabling provider");

                    let provider = if dry_run {
                        provider
                    } else {
                        repo.upstream_oauth_provider()
                            .disable(clock, provider)
                            .await?
                    };

                    existing_disabled.insert(provider.id, provider);
                }
            } else {
                existing_disabled.insert(provider.id, provider);
            }
        }

        if prune {
            for provider_id in existing_disabled.keys().copied() {
                info!(provider.id = %provider_id, "Deleting provider");

                if dry_run {
                    continue;
                }

                repo.upstream_oauth_provider()
                    .delete_by_id(provider_id)
                    .await?;
            }
        } else {
            let len = existing_disabled.len();
            match len {
                0 => {}
                1 => warn!(
                    "A provider is soft-deleted in the database. Run `coauth config sync --prune` to delete it."
                ),
                n => warn!(
                    "{n} providers are soft-deleted in the database. Run `coauth config sync --prune` to delete them."
                ),
            }
        }

        for (index, provider) in upstream_oauth_config.providers.into_iter().enumerate() {
            if !provider.enabled {
                continue;
            }

            // Use the position in the config of the provider as position in the UI
            let ui_order = index.try_into().unwrap_or(i32::MAX);

            let _span = info_span!("provider", %provider.id).entered();
            if existing_enabled_ids.contains(&provider.id) {
                info!(provider.id = %provider.id, "Updating provider");
            } else if existing_disabled.contains_key(&provider.id) {
                info!(provider.id = %provider.id, "Enabling and updating provider");
            } else {
                info!(provider.id = %provider.id, "Adding provider");
            }

            if dry_run {
                continue;
            }

            let encrypted_client_secret = if let Some(client_secret) = provider.client_secret {
                Some(encrypter.encrypt_to_string(client_secret.value().await?.as_bytes())?)
            } else if let Some(mut siwa) = provider.sign_in_with_apple.clone() {
                // if private key file is defined and not private key (raw), we populate the
                // private key to hold the content of the private key file.
                // private key (raw) takes precedence so both can be defined
                // without issues
                if siwa.private_key.is_none()
                    && let Some(private_key_file) = siwa.private_key_file.take()
                {
                    let key = tokio::fs::read_to_string(private_key_file).await?;
                    siwa.private_key = Some(key);
                }
                let encoded = serde_json::to_vec(&siwa)?;
                Some(encrypter.encrypt_to_string(&encoded)?)
            } else {
                None
            };

            let discovery_mode = match provider.discovery_mode {
                coauth_config::UpstreamOAuthDiscoveryMode::Oidc => {
                    coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc
                }
                coauth_config::UpstreamOAuthDiscoveryMode::Insecure => {
                    coauth_data::UpstreamOAuthProviderDiscoveryMode::Insecure
                }
                coauth_config::UpstreamOAuthDiscoveryMode::Disabled => {
                    coauth_data::UpstreamOAuthProviderDiscoveryMode::Disabled
                }
            };

            let token_endpoint_auth_method = match provider.token_endpoint_auth_method {
                coauth_config::UpstreamOAuthTokenAuthMethod::None => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::None
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::ClientSecretBasic => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::ClientSecretPost => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::ClientSecretJwt => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::ClientSecretJwt
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::PrivateKeyJwt => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::PrivateKeyJwt
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::SignInWithApple => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::SignInWithApple
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::QQConnect => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::QQConnect
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::Feishu => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::Feishu
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::Lark => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::Lark
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::DingTalk => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::DingTalk
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::WeChat => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::WeChat
                }
                coauth_config::UpstreamOAuthTokenAuthMethod::WeCom => {
                    coauth_data::UpstreamOAuthProviderTokenAuthMethod::WeCom
                }
            };

            let response_mode = provider
                .response_mode
                .map(|response_mode| match response_mode {
                    coauth_config::UpstreamOAuthResponseMode::Query => {
                        coauth_data::UpstreamOAuthProviderResponseMode::Query
                    }
                    coauth_config::UpstreamOAuthResponseMode::FormPost => {
                        coauth_data::UpstreamOAuthProviderResponseMode::FormPost
                    }
                });

            if discovery_mode.is_disabled() {
                if provider.authorization_endpoint.is_none() {
                    error!(provider.id = %provider.id, "Provider has discovery disabled but no authorization endpoint set");
                }

                if provider.token_endpoint.is_none() {
                    error!(provider.id = %provider.id, "Provider has discovery disabled but no token endpoint set");
                }

                if provider.jwks_uri.is_none() {
                    warn!(provider.id = %provider.id, "Provider has discovery disabled but no JWKS URI set");
                }
            }

            let pkce_mode = match provider.pkce_method {
                coauth_config::UpstreamOAuthPkceMethod::Auto => {
                    coauth_data::UpstreamOAuthProviderPkceMode::Auto
                }
                coauth_config::UpstreamOAuthPkceMethod::Always => {
                    coauth_data::UpstreamOAuthProviderPkceMode::S256
                }
                coauth_config::UpstreamOAuthPkceMethod::Never => {
                    coauth_data::UpstreamOAuthProviderPkceMode::Disabled
                }
            };

            let on_backchannel_logout = match provider.on_backchannel_logout {
                coauth_config::UpstreamOAuthOnBackchannelLogout::DoNothing => {
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing
                }
                coauth_config::UpstreamOAuthOnBackchannelLogout::LogoutBrowserOnly => {
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::LogoutBrowserOnly
                }
                coauth_config::UpstreamOAuthOnBackchannelLogout::LogoutAll => {
                    coauth_data::UpstreamOAuthProviderOnBackchannelLogout::LogoutAll
                }
            };

            // If a row with this id already exists but is `manual`, refuse to
            // clobber it. The admin and the operator have to reconcile by
            // hand.
            if let Some(existing) = repo.upstream_oauth_provider().lookup(provider.id).await?
                && existing.source == UpstreamOAuthProviderSource::Manual
            {
                warn!(
                    provider.id = %provider.id,
                    "Skipping config provider: id collides with a manually-managed provider"
                );
                continue;
            }

            repo.upstream_oauth_provider()
                .upsert(
                    clock,
                    provider.id,
                    UpstreamOAuthProviderParams {
                        issuer: provider.issuer,
                        human_name: provider.human_name,
                        brand_name: provider.brand_name,
                        scope: provider.scope.parse()?,
                        token_endpoint_auth_method,
                        token_endpoint_signing_alg: provider.token_endpoint_auth_signing_alg,
                        id_token_signed_response_alg: provider.id_token_signed_response_alg,
                        client_id: provider.client_id,
                        encrypted_client_secret,
                        claims_imports: map_claims_imports(&provider.claims_imports),
                        token_endpoint_override: provider.token_endpoint,
                        userinfo_endpoint_override: provider.userinfo_endpoint,
                        authorization_endpoint_override: provider.authorization_endpoint,
                        jwks_uri_override: provider.jwks_uri,
                        discovery_mode,
                        pkce_mode,
                        fetch_userinfo: provider.fetch_userinfo,
                        userinfo_signed_response_alg: provider.userinfo_signed_response_alg,
                        response_mode,
                        additional_authorization_parameters: provider
                            .additional_authorization_parameters
                            .into_iter()
                            .collect(),
                        forward_login_hint: provider.forward_login_hint,
                        ui_order,
                        on_backchannel_logout,
                        source: UpstreamOAuthProviderSource::Config,
                    },
                )
                .await?;
        }
    }

    {
        let _span = info_span!("cli.config.sync.clients").entered();
        let config_ids = clients_config
            .iter()
            .map(|c| c.client_id)
            .collect::<BTreeSet<_>>();

        let existing = repo.oauth_client().all_static().await?;
        let existing_ids = existing.iter().map(|p| p.id).collect::<BTreeSet<_>>();
        let to_delete = existing.into_iter().filter(|p| !config_ids.contains(&p.id));
        if prune {
            for client in to_delete {
                info!(client.id = %client.client_id, "Deleting client");

                if dry_run {
                    continue;
                }

                repo.oauth_client().delete(client).await?;
            }
        } else {
            let len = to_delete.count();
            match len {
                0 => {}
                1 => warn!(
                    "A static client in the database is not in the config. Run with `--prune` to delete it."
                ),
                n => warn!(
                    "{n} static clients in the database are not in the config. Run with `--prune` to delete them."
                ),
            }
        }

        for client in clients_config {
            let _span = info_span!("client", client.id = %client.client_id).entered();
            if existing_ids.contains(&client.client_id) {
                info!(client.id = %client.client_id, "Updating client");
            } else {
                info!(client.id = %client.client_id, "Adding client");
            }

            if dry_run {
                continue;
            }

            let client_secret = client.client_secret().await?;
            let client_name = client.client_name.as_ref();
            let client_auth_method = client.client_auth_method();
            let jwks = client.jwks.as_ref();
            let jwks_uri = client.jwks_uri.as_ref();

            // TODO: should be moved somewhere else
            let encrypted_client_secret = client_secret
                .map(|client_secret| encrypter.encrypt_to_string(client_secret.as_bytes()))
                .transpose()?;

            repo.oauth_client()
                .upsert_static(
                    client.client_id,
                    client_name.cloned(),
                    client_auth_method,
                    encrypted_client_secret,
                    jwks.cloned(),
                    jwks_uri.cloned(),
                    client.redirect_uris,
                )
                .await?;
        }
    }

    // Release the advisory lock
    let mut conn = repo.into_inner();
    let _ = sql_query(format!("SELECT pg_advisory_unlock({lock_key})"))
        .execute(&mut *conn)
        .await;

    if dry_run {
        info!("Dry run mode - changes were already auto-committed per statement");
    }
    Ok(())
}
