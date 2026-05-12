use std::{sync::Arc, time::Duration};

use anyhow::Context;
use coauth_config::{
    AccountConfig, BrandingConfig, CaptchaConfig, DatabaseConfig, EmailConfig, EmailProviderConfig,
    EmailSmtpMode, ExperimentalConfig, HomeserverKind, MatrixConfig, PasswordsConfig, PolicyConfig,
    PolicyEngine, SmsConfig, SmsProviderConfig, TemplatesConfig,
};
use coauth_data::{
    BoxRepositoryFactory, RepositoryAccess, RepositoryFactory, SessionExpirationConfig,
    SessionLimitConfig, SiteConfig, UrlBuilder,
};
use coauth_matrix::{ConnectorRegistry, HomeserverAdmin, ReadOnlyHomeserverAdmin};
use coauth_matrix_palpo::PalpoAdmin;
use coauth_messaging::{MailTransport, Mailer, NotificationCenter, SmsSender, SmsTransport};
use coauth_policy::PolicyFactory;
use coauth_templates::{SiteConfigExt, Templates};
use diesel_async::{
    AsyncPgConnection, SimpleAsyncConnection,
    pooled_connection::{
        AsyncDieselConnectionManager, PoolError as AsyncPoolError,
        deadpool::{Hook as DieselPoolHook, HookError as DieselPoolHookError, Pool as DieselPool},
    },
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::Instrument;

use crate::handlers::passwords::PasswordManager;

fn cleanup_pooled_postgres_connection() -> DieselPoolHook<AsyncPgConnection> {
    DieselPoolHook::async_fn(|conn: &mut AsyncPgConnection, _metrics| {
        Box::pin(async move {
            // Pooled sessions must be reset before reuse. `ROLLBACK` clears any
            // leaked transaction, and `pg_advisory_unlock_all()` clears leader
            // locks that are session-scoped.
            conn.batch_execute("ROLLBACK; SELECT pg_advisory_unlock_all();")
                .await
                .map_err(|error| DieselPoolHookError::Backend(AsyncPoolError::QueryError(error)))?;

            Ok(())
        })
    })
}

/// Check whether `c` is a valid character for a username.
fn valid_username_character(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '='
        || c == '_'
        || c == '-'
        || c == '.'
        || c == '/'
        || c == '+'
}

/// Check whether `username` is a valid username.
///
/// Usernames must be non-empty, at most 255 characters, must not start with
/// an underscore, and may only contain lowercase ASCII letters, digits, and
/// the characters `= _ - . / +`.
pub fn username_valid(username: &str) -> bool {
    if username.is_empty() || username.len() > 255 {
        return false;
    }

    // Should not start with an underscore
    if username.starts_with('_') {
        return false;
    }

    // Should only contain valid characters
    if !username.chars().all(valid_username_character) {
        return false;
    }

    true
}

/// Validate that a string is a Contrix typed wire id of shape
/// `cx:<prefix>:<uuid-v7>`, where `<uuid-v7>` parses as a strict v7 UUID.
///
/// This is the Move/Anchor/Lattice typed-id surface (spec `wire-ids.md` —
/// rebased onto UUIDv7 in 2026-05). coauth's internal admin tokens and
/// personal session ids stay ULID; this helper is for the few admin /
/// session-grant handler call-sites that consume Contrix wire ids
/// (`cx:device:<uuid7>`, `cx:space:<uuid7>`, `cx:cell:<family>:<id>`,
/// etc.) from external requests.
///
/// Wire-rejection of legacy ULID is intentional — v1 is unreleased so
/// there is no compatibility burden. Callers that must accept ULID for
/// some other reason should not use this helper.
///
/// # Examples
/// ```
/// use coauth_backend::util::is_typed_uuid7;
/// // valid v7 uuid (timestamp + version bits)
/// assert!(is_typed_uuid7(
///     "cx:device:0190a3c0-0000-7000-8000-000000000000",
///     "device"
/// ));
/// // wrong prefix → false
/// assert!(!is_typed_uuid7(
///     "cx:space:0190a3c0-0000-7000-8000-000000000000",
///     "device"
/// ));
/// // ULID body → false (legacy rejected)
/// assert!(!is_typed_uuid7(
///     "cx:device:01JS0SP000000000000000000",
///     "device"
/// ));
/// ```
#[must_use]
pub fn is_typed_uuid7(s: &str, prefix: &str) -> bool {
    let Some(rest) = s.strip_prefix("cx:") else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(prefix) else {
        return false;
    };
    let Some(body) = rest.strip_prefix(':') else {
        return false;
    };

    // Cell-family ids (`cx:cell:<family>:<uuid>`) are intentionally
    // rejected here — pass `prefix = "cell:<family>"` if you need a
    // cell-family-specific check, or use a dedicated parser.
    if body.contains(':') {
        return false;
    }

    // `Uuid::parse_str` accepts any version; we further require v7.
    match uuid::Uuid::parse_str(body) {
        Ok(u) => u.get_version_num() == 7,
        Err(_) => false,
    }
}

pub async fn password_manager_from_config(
    config: &PasswordsConfig,
) -> Result<PasswordManager, anyhow::Error> {
    if !config.enabled() {
        return Ok(PasswordManager::disabled());
    }

    let schemes = config.load().await?.into_iter().map(
        |(version, algorithm, cost, secret, unicode_normalization)| {
            use crate::handlers::passwords::Hasher;
            let hasher = match algorithm {
                coauth_config::PasswordAlgorithm::Pbkdf2 => {
                    Hasher::pbkdf2(secret, unicode_normalization)
                }
                coauth_config::PasswordAlgorithm::Bcrypt => {
                    Hasher::bcrypt(cost, secret, unicode_normalization)
                }
                coauth_config::PasswordAlgorithm::Argon2id => {
                    Hasher::argon2id(secret, unicode_normalization)
                }
            };

            (version, hasher)
        },
    );

    PasswordManager::new(config.minimum_complexity(), schemes)
}

pub fn mailer_from_config(
    config: &EmailConfig,
    templates: &Templates,
) -> Result<Mailer, anyhow::Error> {
    let from = config
        .from
        .parse()
        .context("invalid email configuration: invalid 'from' address")?;
    let reply_to = config
        .reply_to
        .parse()
        .context("invalid email configuration: invalid 'reply_to' address")?;
    let transport = match &config.provider {
        EmailProviderConfig::Blackhole => MailTransport::blackhole(),
        EmailProviderConfig::Smtp(provider) => {
            let credentials = match (&provider.username, &provider.password) {
                (Some(username), Some(password)) => Some(coauth_messaging::SmtpCredentials::new(
                    username.to_owned(),
                    password.to_owned(),
                )),
                (None, None) => None,
                _ => {
                    anyhow::bail!("invalid email configuration: missing username or password");
                }
            };

            let mode = match provider.mode {
                EmailSmtpMode::Plain => coauth_messaging::SmtpMode::Plain,
                EmailSmtpMode::StartTls => coauth_messaging::SmtpMode::StartTls,
                EmailSmtpMode::Tls => coauth_messaging::SmtpMode::Tls,
            };

            MailTransport::smtp(mode, &provider.hostname, provider.port, credentials)
                .context("failed to build SMTP transport")?
        }
        EmailProviderConfig::Sendmail(provider) => {
            MailTransport::sendmail(Some(provider.command.clone()))
        }
        EmailProviderConfig::HttpWebhook(provider) => MailTransport::http_webhook(
            crate::reqwest_client(),
            provider
                .url
                .parse()
                .context("invalid email configuration: invalid provider.url")?,
            provider.api_key.clone(),
            provider.headers.clone(),
        ),
        EmailProviderConfig::PaloudInternal(provider) => MailTransport::paloud_internal(
            crate::reqwest_client(),
            provider
                .url
                .parse()
                .context("invalid email configuration: invalid provider.url")?,
            provider.key_id.clone(),
            provider.secret.clone(),
            provider.workspace.clone(),
        ),
        EmailProviderConfig::Resend(provider) => MailTransport::resend(
            crate::reqwest_client(),
            provider
                .base_url
                .parse()
                .context("invalid email configuration: invalid provider.base_url")?,
            provider.api_key.clone(),
        ),
        EmailProviderConfig::Sendgrid(provider) => MailTransport::sendgrid(
            crate::reqwest_client(),
            provider
                .base_url
                .parse()
                .context("invalid email configuration: invalid provider.base_url")?,
            provider.api_key.clone(),
        ),
        EmailProviderConfig::Twilio(provider) => MailTransport::twilio(
            crate::reqwest_client(),
            provider
                .base_url
                .parse()
                .context("invalid email configuration: invalid provider.base_url")?,
            provider.api_key.clone(),
        ),
        EmailProviderConfig::Brevo(provider) => MailTransport::brevo(
            crate::reqwest_client(),
            provider
                .base_url
                .parse()
                .context("invalid email configuration: invalid provider.base_url")?,
            provider.api_key.clone(),
        ),
        EmailProviderConfig::AwsSes(provider) => MailTransport::aws_ses(
            crate::reqwest_client(),
            provider.region.clone(),
            provider.access_key_id.clone(),
            provider.secret_access_key.clone(),
            provider.session_token.clone(),
            provider
                .endpoint
                .as_deref()
                .map(str::parse)
                .transpose()
                .context("invalid email configuration: invalid provider.endpoint")?,
            provider.configuration_set_name.clone(),
        ),
    };

    Ok(Mailer::new(templates.clone(), transport, from, reply_to))
}

pub fn sms_sender_from_config(config: &SmsConfig) -> Result<SmsSender, anyhow::Error> {
    let transport = match &config.provider {
        SmsProviderConfig::Blackhole => SmsTransport::blackhole(),
        SmsProviderConfig::Twilio(provider) => SmsTransport::twilio(
            provider.account_sid.clone(),
            provider.auth_token.clone(),
            provider.from_number.clone(),
        ),
        SmsProviderConfig::HttpWebhook(provider) => SmsTransport::http_webhook(
            provider
                .url
                .parse()
                .context("invalid sms configuration: invalid provider.url")?,
            provider.api_key.clone(),
            provider.from_number.clone(),
        ),
        SmsProviderConfig::AliyunSms(provider) => SmsTransport::aliyun(
            provider.access_key_id.clone(),
            provider.access_key_secret.clone(),
            provider.sign_name.clone(),
            provider.template_code.clone(),
        ),
        SmsProviderConfig::TencentCloudSms(provider) => SmsTransport::tencent_cloud(
            provider.secret_id.clone(),
            provider.secret_key.clone(),
            provider.sdk_app_id.clone(),
            provider.sign_name.clone(),
            provider.template_id.clone(),
        ),
        SmsProviderConfig::PaloudInternal(provider) => SmsTransport::paloud_internal(
            provider
                .url
                .parse()
                .context("invalid sms configuration: invalid provider.url")?,
            provider.key_id.clone(),
            provider.secret.clone(),
            provider.workspace.clone(),
        ),
    };

    Ok(SmsSender::new(transport))
}

pub fn notification_center_from_config(
    email_config: &EmailConfig,
    sms_config: &SmsConfig,
    templates: &Templates,
) -> Result<NotificationCenter, anyhow::Error> {
    let mailer = mailer_from_config(email_config, templates)?;
    let sms = sms_sender_from_config(sms_config)?;
    Ok(NotificationCenter::email_only(mailer).with_sms(sms))
}

/// Test the connection to the mailer in a background task
pub fn test_mailer_in_background(mailer: &Mailer, timeout: Duration) {
    let mailer = mailer.clone();

    let span = tracing::info_span!("cli.test_mailer");
    tokio::spawn(async move {
        match tokio::time::timeout(timeout, mailer.test_connection()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(
                    error = &err as &dyn std::error::Error,
                    "Could not connect to the mail backend, tasks sending mails may fail!"
                );
            }
            Err(_) => {
                tracing::warn!("Timed out while testing the mail backend connection, tasks sending mails may fail!");
            }
        }
    }
    .instrument(span));
}

pub async fn policy_factory_from_config(
    config: &PolicyConfig,
    _matrix_config: &MatrixConfig,
    _experimental_config: &ExperimentalConfig,
) -> Result<PolicyFactory, anyhow::Error> {
    match config.engine {
        PolicyEngine::Cedar => {
            #[cfg(feature = "cedar")]
            {
                let default_path =
                    camino::Utf8PathBuf::from("/usr/local/share/coauth/cedar/default.cedar");
                let path = config.cedar_policy_file.as_ref().unwrap_or(&default_path);
                PolicyFactory::load_cedar_from_file(path.as_str())
                    .await
                    .context("failed to load Cedar policy")
            }

            #[cfg(not(feature = "cedar"))]
            anyhow::bail!(
                "Cedar policy engine is not available. \
                 Recompile with the `cedar` feature to enable it."
            )
        }

        PolicyEngine::Remote => {
            #[cfg(feature = "remote")]
            {
                let endpoint = config
                    .remote_endpoint
                    .as_ref()
                    .context("remote_endpoint must be set when using the Remote engine")?;
                let client = reqwest::Client::new();
                PolicyFactory::load_remote(endpoint.clone(), client)
                    .context("failed to create remote policy factory")
            }

            #[cfg(not(feature = "remote"))]
            anyhow::bail!(
                "Remote policy engine is not available. \
                 Recompile with the `remote` feature to enable it."
            )
        }
    }
}

pub fn captcha_config_from_config(
    captcha_config: &CaptchaConfig,
) -> Result<Option<coauth_data::CaptchaConfig>, anyhow::Error> {
    let Some(service) = captcha_config.service else {
        return Ok(None);
    };

    let service = match service {
        coauth_config::CaptchaServiceKind::RecaptchaV2 => coauth_data::CaptchaService::RecaptchaV2,
        coauth_config::CaptchaServiceKind::CloudflareTurnstile => {
            coauth_data::CaptchaService::CloudflareTurnstile
        }
        coauth_config::CaptchaServiceKind::HCaptcha => coauth_data::CaptchaService::HCaptcha,
    };

    Ok(Some(coauth_data::CaptchaConfig {
        service,
        site_key: captcha_config
            .site_key
            .clone()
            .context("missing site key")?,
        secret_key: captcha_config
            .secret_key
            .clone()
            .context("missing secret key")?,
    }))
}

pub fn site_config_from_config(
    branding_config: &BrandingConfig,
    matrix_config: &MatrixConfig,
    experimental_config: &ExperimentalConfig,
    password_config: &PasswordsConfig,
    account_config: &AccountConfig,
    captcha_config: &CaptchaConfig,
    sms_config: &SmsConfig,
) -> Result<SiteConfig, anyhow::Error> {
    let captcha = captcha_config_from_config(captcha_config)?;
    let session_expiration = experimental_config
        .inactive_session_expiration
        .as_ref()
        .map(|c| SessionExpirationConfig {
            oauth_session_inactivity_ttl: c.expire_oauth_sessions.then_some(c.ttl),
            user_session_inactivity_ttl: c.expire_user_sessions.then_some(c.ttl),
        });

    Ok(SiteConfig {
        access_token_ttl: experimental_config.access_token_ttl,
        server_name: matrix_config.homeserver.clone(),
        policy_uri: branding_config.policy_uri.clone(),
        tos_uri: branding_config.tos_uri.clone(),
        imprint: branding_config.imprint.clone(),
        password_login_enabled: password_config.enabled(),
        password_registration_enabled: password_config.enabled()
            && account_config.password_registration_enabled,
        password_registration_contact_required: account_config
            .password_registration_contact_required,
        registration_token_required: account_config.registration_token_required,
        bootstrap_admin_token: account_config.bootstrap_admin_token.clone(),
        email_change_allowed: account_config.email_change_allowed,
        displayname_change_allowed: account_config.displayname_change_allowed,
        password_change_allowed: password_config.enabled()
            && account_config.password_change_allowed,
        account_recovery_allowed: password_config.enabled()
            && account_config.password_recovery_enabled,
        account_deactivation_allowed: account_config.account_deactivation_allowed,
        captcha,
        minimum_password_complexity: password_config.minimum_complexity(),
        session_expiration,
        login_with_email_allowed: account_config.login_with_email_allowed,
        admin_portal_url: account_config.admin_portal_url.clone(),
        plan_management_iframe_uri: experimental_config.plan_management_iframe_uri.clone(),
        session_limit: experimental_config
            .session_limit
            .as_ref()
            .map(|c| SessionLimitConfig {
                soft_limit: c.soft_limit,
                hard_limit: c.hard_limit,
            }),
        flow_engine_enabled: false,
        phone_verification_enabled: !matches!(&sms_config.provider, SmsProviderConfig::Blackhole),
    })
}

pub async fn templates_from_config(
    config: &TemplatesConfig,
    site_config: &SiteConfig,
    url_builder: &UrlBuilder,
    strict: bool,
) -> Result<Templates, anyhow::Error> {
    let default_locale = match config.default_locale.as_deref() {
        Some(raw) => raw.parse::<icu_locid::Locale>().with_context(|| {
            format!("Invalid templates.default_locale {raw:?} in configuration")
        })?,
        None => icu_locid::locale!("en"),
    };

    Templates::load_with_default_locale(
        config.path.clone(),
        url_builder.clone(),
        config.translations_path.clone(),
        default_locale,
        site_config.templates_branding(),
        site_config.templates_features(),
        strict,
    )
    .await
    .with_context(|| format!("Failed to load the templates at {}", config.path))
}

/// Build a connection string from the [`DatabaseConfig`] for use with
/// diesel-async.
///
/// This mirrors the logic from [`database_connect_options_from_config`] but
/// produces a plain URL string suitable for
/// [`AsyncDieselConnectionManager`].
pub fn database_url_from_config(config: &DatabaseConfig) -> Result<String, anyhow::Error> {
    if let Some(uri) = config.uri.as_deref() {
        return Ok(uri.to_owned());
    }

    let mut url = String::from("postgres://");
    if let Some(username) = config.username.as_deref() {
        url.push_str(username);
        if let Some(password) = config.password.as_deref() {
            url.push(':');
            url.push_str(password);
        }
        url.push('@');
    }
    if let Some(host) = config.host.as_deref() {
        url.push_str(host);
    } else {
        url.push_str("localhost");
    }
    if let Some(port) = config.port {
        url.push(':');
        url.push_str(&port.to_string());
    }
    if let Some(database) = config.database.as_deref() {
        url.push('/');
        url.push_str(database);
    }
    url.push_str("?application_name=coauth");

    Ok(url)
}

/// Create a diesel-async deadpool connection pool from the configuration.
///
/// This pool is used by [`PgRepositoryFactory`] for all non-migration
/// database access.
#[tracing::instrument(name = "db.connect.diesel", skip_all)]
pub async fn diesel_pool_from_config(
    config: &DatabaseConfig,
) -> Result<DieselPool<AsyncPgConnection>, anyhow::Error> {
    let url = database_url_from_config(config)?;
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = DieselPool::builder(manager)
        .max_size(config.max_connections.get() as usize)
        .wait_timeout(Some(config.connect_timeout))
        .create_timeout(Some(config.connect_timeout))
        .recycle_timeout(Some(std::time::Duration::from_secs(5)))
        .pre_recycle(cleanup_pooled_postgres_connection())
        .runtime(deadpool::Runtime::Tokio1)
        .build()
        .context("could not build diesel connection pool")?;
    Ok(pool)
}

/// Update the policy factory dynamic data from the database and spawn a
/// task to periodically refresh it. Lives in `util.rs` rather than the
/// `policy` crate because it wires together a policy factory with a
/// repository factory + task tracker, which are backend-level concerns.
pub async fn load_policy_factory_dynamic_data_continuously(
    policy_factory: &Arc<PolicyFactory>,
    repository_factory: BoxRepositoryFactory,
    cancellation_token: CancellationToken,
    task_tracker: &TaskTracker,
) -> Result<(), anyhow::Error> {
    let policy_factory = policy_factory.clone();

    load_policy_factory_dynamic_data(&policy_factory, &*repository_factory).await?;

    task_tracker.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                () = cancellation_token.cancelled() => {
                    return;
                }
                _ = interval.tick() => {}
            }

            if let Err(err) =
                load_policy_factory_dynamic_data(&policy_factory, &*repository_factory).await
            {
                tracing::error!(
                    error = ?err,
                    "Failed to load policy factory dynamic data"
                );
                cancellation_token.cancel();
                return;
            }
        }
    });

    Ok(())
}

/// Update the policy factory dynamic data from the database
#[tracing::instrument(name = "policy.load_dynamic_data", skip_all)]
pub async fn load_policy_factory_dynamic_data(
    policy_factory: &PolicyFactory,
    repository_factory: &(dyn RepositoryFactory + Send + Sync),
) -> Result<(), anyhow::Error> {
    let mut repo = repository_factory
        .create()
        .await
        .context("Failed to acquire database connection")?;

    let policy_data = repo.policy_data().get().await;
    repo.cancel()
        .await
        .context("Failed to close read-only policy transaction")?;

    if let Some(data) = policy_data? {
        let id = data.id;
        let updated = policy_factory.set_dynamic_data(data).await?;
        if updated {
            tracing::info!(policy_data.id = %id, "Loaded dynamic policy data from the database");
        }
    }

    Ok(())
}

/// Create a clonable, type-erased [`HomeserverAdmin`] and a
/// [`ConnectorRegistry`] from the configuration.
///
/// The returned registry contains the connector as its primary provider,
/// while the `Arc<dyn HomeserverAdmin>` is kept for backward
/// compatibility with code that accesses the homeserver directly.
pub async fn homeserver_connection_from_config(
    config: &MatrixConfig,
    http_client: reqwest::Client,
) -> anyhow::Result<(Arc<dyn HomeserverAdmin>, ConnectorRegistry)> {
    let mut registry = ConnectorRegistry::new();

    if !config.enabled {
        // Legacy Matrix / Palpo adapter retired for this deployment.
        // Wire a no-op stub for any code path that still reaches for
        // `homeserver_admin`, and leave the connector registry empty so
        // the connector-health surface honestly reports "no connector".
        // The handshake against a real homeserver is skipped entirely.
        tracing::info!(
            "Matrix homeserver adapter disabled (matrix.enabled = false); using no-op stub"
        );
        let stub: Arc<dyn HomeserverAdmin> = Arc::new(coauth_matrix::MockHomeserverAdmin::new(
            config.homeserver.clone(),
        ));
        return Ok((stub, registry));
    }

    Ok(match config.kind {
        HomeserverKind::Palpo | HomeserverKind::PalpoModern => {
            let palpo = Arc::new(PalpoAdmin::new(
                config.homeserver.clone(),
                config.endpoint.clone(),
                config.secret().await?,
                http_client,
            ));
            registry.register(Arc::clone(&palpo) as _);
            (palpo as Arc<dyn HomeserverAdmin>, registry)
        }
        HomeserverKind::PalpoReadOnly => {
            let palpo = PalpoAdmin::new(
                config.homeserver.clone(),
                config.endpoint.clone(),
                config.secret().await?,
                http_client,
            );
            let readonly = Arc::new(ReadOnlyHomeserverAdmin::new(palpo));
            registry.register(Arc::clone(&readonly) as _);
            (readonly as Arc<dyn HomeserverAdmin>, registry)
        }
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use diesel::{
        QueryableByName, sql_query,
        sql_types::{BigInt, Uuid as DieselUuid},
    };
    use diesel_async::RunQueryDsl as _;
    use rand_core::SeedableRng;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::*;

    #[tokio::test]
    async fn test_password_manager_from_config() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = Zeroizing::new("hunter2".to_owned());

        // Test a valid, enabled config
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 10,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(manager.is_enabled());
        let hashed = manager.hash(&mut rng, password.clone()).await;
        assert!(hashed.is_ok());
        let (version, hashed) = hashed.unwrap();
        assert_eq!(version, 42);
        assert!(hashed.starts_with("$argon2id$"));

        // Test a valid, disabled config
        let config = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "schemes": []
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(!manager.is_enabled());
        let res = manager.hash(&mut rng, password.clone()).await;
        assert!(res.is_err());

        // Test an invalid config
        // Repeat the same version twice
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 42,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());

        // Empty schemes
        let config = serde_json::from_value(serde_json::json!({
            "schemes": []
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());
    }

    #[derive(QueryableByName)]
    struct RowCount {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    #[tokio::test]
    async fn test_diesel_pool_recycles_connections_back_to_a_clean_session() {
        // Postgres-only path: skip cleanly when DATABASE_URL is not configured
        // (matches the workspace-wide gate added in C32.4).
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let config = DatabaseConfig {
            uri: Some(database_url),
            max_connections: NonZeroU32::new(1).unwrap(),
            ..Default::default()
        };
        let pool = diesel_pool_from_config(&config).await.unwrap();
        let row_id = Uuid::now_v7();
        let table_name = format!("codex_pool_cleanup_test_{}", Uuid::now_v7().simple());

        {
            let mut conn = pool.get().await.unwrap();
            let drop_table_sql = format!("DROP TABLE IF EXISTS {table_name}");
            sql_query(&drop_table_sql)
                .execute(&mut *conn)
                .await
                .unwrap();
            let create_table_sql = format!(
                r"
                    CREATE TABLE IF NOT EXISTS {table_name} (
                        id UUID PRIMARY KEY
                    )
                "
            );
            sql_query(&create_table_sql)
                .execute(&mut *conn)
                .await
                .unwrap();

            sql_query("BEGIN").execute(&mut *conn).await.unwrap();
            let insert_sql = format!("INSERT INTO {table_name} (id) VALUES ($1)");
            sql_query(&insert_sql)
                .bind::<DieselUuid, _>(row_id)
                .execute(&mut *conn)
                .await
                .unwrap();
        }

        let mut conn = pool.get().await.unwrap();
        let select_sql = format!("SELECT COUNT(*) AS count FROM {table_name} WHERE id = $1");
        let row_count = sql_query(&select_sql)
            .bind::<DieselUuid, _>(row_id)
            .get_result::<RowCount>(&mut *conn)
            .await
            .unwrap();

        assert_eq!(row_count.count, 0);

        let insert_sql = format!("INSERT INTO {table_name} (id) VALUES ($1)");
        sql_query(&insert_sql)
            .bind::<DieselUuid, _>(row_id)
            .execute(&mut *conn)
            .await
            .unwrap();

        let row_count = sql_query(&select_sql)
            .bind::<DieselUuid, _>(row_id)
            .get_result::<RowCount>(&mut *conn)
            .await
            .unwrap();

        assert_eq!(row_count.count, 1);

        let drop_sql = format!("DROP TABLE IF EXISTS {table_name}");
        sql_query(&drop_sql).execute(&mut *conn).await.unwrap();
    }

    #[test]
    fn typed_uuid7_accepts_valid_v7_with_matching_prefix() {
        let id = Uuid::now_v7();
        let s = format!("cx:device:{id}");
        assert!(super::is_typed_uuid7(&s, "device"));
    }

    #[test]
    fn typed_uuid7_rejects_wrong_prefix() {
        let id = Uuid::now_v7();
        let s = format!("cx:space:{id}");
        assert!(!super::is_typed_uuid7(&s, "device"));
    }

    #[test]
    fn typed_uuid7_rejects_legacy_ulid() {
        // ULID format (Crockford base32), no compatibility expected.
        let s = "cx:device:01JS0SP000000000000000000";
        assert!(!super::is_typed_uuid7(s, "device"));
    }

    #[test]
    fn typed_uuid7_rejects_v4_uuid() {
        // Random v4 — must be rejected since the spec mandates v7.
        let s = "cx:device:550e8400-e29b-41d4-a716-446655440000";
        assert!(!super::is_typed_uuid7(s, "device"));
    }

    #[test]
    fn typed_uuid7_rejects_missing_cx_namespace() {
        let id = Uuid::now_v7();
        let s = format!("device:{id}");
        assert!(!super::is_typed_uuid7(&s, "device"));
    }

    #[test]
    fn typed_uuid7_rejects_extra_segments() {
        // Cell-family ids have more colons; the basic helper rejects them.
        let id = Uuid::now_v7();
        let s = format!("cx:cell:cx.component.consent.grant.v1:{id}");
        assert!(!super::is_typed_uuid7(&s, "cell"));
    }

    #[test]
    fn typed_uuid7_rejects_empty_body() {
        assert!(!super::is_typed_uuid7("cx:device:", "device"));
    }
}
