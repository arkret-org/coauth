// Copyright 2025 Taidge Ltd.
// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2025 Taidge Ltd.
//
// Portions based on mas-cli by The Matrix.org Foundation C.I.C.

//! Individual manage subcommand handler implementations.

use std::process::ExitCode;

use anyhow::Context;
use chrono::Duration;
use figment::Figment;
use coauth_backend::util::{diesel_pool_from_config, password_manager_from_config};
use coauth_config::{ConfigurationSectionExt, DatabaseConfig, PasswordsConfig};
use coauth_data::{
    Clock, Pagination, PgRepository, RepositoryAccess, SystemClock,
    oauth2::OAuth2SessionFilter,
    queue::{
        DeactivateUserJob, ProvisionUserJob, QueueJobRepositoryExt as _, ReactivateUserJob,
        SyncDevicesJob,
    },
    user::{
        BrowserSessionFilter, UserEmailRepository, UserFilter, UserPasswordRepository,
        UserRepository,
    },
};
use rand_core::{RngCore, SeedableRng};
use tracing::{error, info, info_span, warn};
use zeroize::Zeroizing;

pub(super) async fn handle_set_password(
    figment: &Figment,
    username: String,
    password: String,
    ignore_complexity: bool,
) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let _span = info_span!("cli.manage.set_password", user.username = %username).entered();

    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let passwords_config =
        PasswordsConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;

    let pool = diesel_pool_from_config(&database_config).await?;
    let password_manager = password_manager_from_config(&passwords_config).await?;

    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);
    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .context("User not found")?;

    if !ignore_complexity && !password_manager.is_password_complex_enough(&password)? {
        error!("That password is too weak.");
        return Ok(ExitCode::from(1));
    }

    let password = Zeroizing::new(password);

    let (version, hashed_password) = password_manager.hash(&mut rng, password).await?;

    repo.user_password()
        .add(&mut rng, &clock, &user, version, hashed_password, None)
        .await?;

    info!(%user.id, %user.username, "Password changed");

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_add_email(
    figment: &Figment,
    username: String,
    email: String,
) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let _span = info_span!(
        "cli.manage.add_email",
        user.username = username,
        user_email.email = email
    )
    .entered();

    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .context("User not found")?;

    // Find any existing email address
    let existing_email = repo.user_email().find(&user, &email).await?;
    let email = if let Some(email) = existing_email {
        info!(%email.id, "Email already exists, makring as verified");
        email
    } else {
        repo.user_email()
            .add(&mut rng, &clock, &user, email)
            .await?
    };
    info!(
        %user.id,
        %user.username,
        %email.id,
        %email.email,
        "Email added"
    );

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_verify_email(
    username: String,
    email: String,
) -> anyhow::Result<ExitCode> {
    let _span = info_span!(
        "cli.manage.verify_email",
        user.username = username,
        user_email.email = email
    )
    .entered();

    tracing::warn!(
        "The 'verify-email' command is deprecated and will be removed in a future version. Use 'add-email' instead."
    );

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_promote_admin(
    figment: &Figment,
    username: String,
) -> anyhow::Result<ExitCode> {
    let _span = info_span!("cli.manage.promote_admin", user.username = username,).entered();

    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .context("User not found")?;

    let user = repo.user().set_can_request_admin(user, true).await?;

    info!(%user.id, %user.username, "User promoted to admin");

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_demote_admin(
    figment: &Figment,
    username: String,
) -> anyhow::Result<ExitCode> {
    let _span = info_span!("cli.manage.demote_admin", user.username = username,).entered();

    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .context("User not found")?;

    let user = repo.user().set_can_request_admin(user, false).await?;

    info!(%user.id, %user.username, "User is no longer admin");

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_list_admin_users(figment: &Figment) -> anyhow::Result<ExitCode> {
    let _span = info_span!("cli.manage.list_admins").entered();
    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    let mut cursor = Pagination::first(1000);
    let filter = UserFilter::new().can_request_admin_only();
    let total = repo.user().count(filter).await?;

    info!("The following users can request admin privileges ({total} total):");
    loop {
        let page = repo.user().list(filter, cursor).await?;
        for edge in page.edges {
            let user = edge.node;
            info!(%user.id, username = %user.username);
            cursor = cursor.after(edge.cursor);
        }

        if !page.has_next_page {
            break;
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_issue_registration_token(
    figment: &Figment,
    token: Option<String>,
    usage_limit: Option<u32>,
    unlimited: bool,
    expires_in: Option<u32>,
) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let _span = info_span!("cli.manage.add_user_registration_token").entered();

    let usage_limit = match (usage_limit, unlimited) {
        (Some(usage_limit), false) => Some(usage_limit),
        (None, false) => Some(1),
        (None, true) => None,
        (Some(_), true) => unreachable!(), // This should be handled by the clap group
    };

    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    // Calculate expiration time if provided
    let expires_at = expires_in.map(|seconds| clock.now() + Duration::seconds(seconds.into()));

    // Generate a token if not provided
    let token_str = token.unwrap_or_else(|| {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut bytes = [0u8; 12];
        rng.fill_bytes(&mut bytes);
        bytes
            .iter()
            .map(|b| CHARSET[*b as usize % CHARSET.len()] as char)
            .collect()
    });

    // Create the token
    let registration_token = repo
        .user_registration_token()
        .add(&mut rng, &clock, token_str, usage_limit, expires_at)
        .await?;

    info!(%registration_token.id, "Created user registration token: {}", registration_token.token);

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_provision_all_users(figment: &Figment) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let _span = info_span!("cli.manage.provision_all_users").entered();
    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    // List all users via the repository
    let mut cursor = Pagination::first(1000);
    let filter = UserFilter::new();
    loop {
        let page = repo.user().list(filter, cursor).await?;
        for edge in page.edges {
            let user = edge.node;
            info!(user.id = %user.id, "Scheduling provisioning job");
            let job = ProvisionUserJob::new(&user);
            repo.queue_job().schedule_job(&mut rng, &clock, job).await?;
            cursor = cursor.after(edge.cursor);
        }

        if !page.has_next_page {
            break;
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_kill_sessions(
    figment: &Figment,
    username: String,
    dry_run: bool,
) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let _span = info_span!("cli.manage.kill_sessions", user.username = username).entered();
    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .context("User not found")?;

    let filter = OAuth2SessionFilter::new().for_user(&user).active_only();
    let affected = if dry_run {
        repo.oauth2_session().count(filter).await?
    } else {
        repo.oauth2_session().finish_bulk(&clock, filter).await?
    };

    match affected {
        0 => info!("No active OAuth 2.0 sessions to end"),
        1 => info!("Ended 1 active OAuth 2.0 session"),
        _ => info!("Ended {affected} active OAuth 2.0 sessions"),
    }

    let filter = BrowserSessionFilter::new().for_user(&user).active_only();
    let affected = if dry_run {
        repo.browser_session().count(filter).await?
    } else {
        repo.browser_session().finish_bulk(&clock, filter).await?
    };

    match affected {
        0 => info!("No active browser sessions to end"),
        1 => info!("Ended 1 active browser session"),
        _ => info!("Ended {affected} active browser sessions"),
    }

    // Schedule a job to sync the devices of the user with the homeserver
    warn!("Scheduling job to sync devices for the user");
    repo.queue_job()
        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
        .await?;

    if dry_run {
        info!("Dry run mode - changes were already auto-committed per statement");
    }

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_lock_user(
    figment: &Figment,
    username: String,
    deactivate: bool,
) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let _span = info_span!("cli.manage.lock_user", user.username = username).entered();
    let config = DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .context("User not found")?;

    info!(%user.id, "Locking user");

    // Even though the deactivation job will lock the user, we lock it here in case
    // the worker is not running, as we don't have a good way to run a job
    // synchronously yet.
    let user = repo.user().lock(&clock, user).await?;

    if deactivate {
        warn!(%user.id, "Scheduling user deactivation");
        repo.queue_job()
            .schedule_job(&mut rng, &clock, DeactivateUserJob::new(&user, false))
            .await?;
    }

    Ok(ExitCode::SUCCESS)
}

pub(super) async fn handle_unlock_user(
    figment: &Figment,
    username: String,
    reactivate: bool,
) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let _span = info_span!("cli.manage.unlock_user", user.username = username).entered();
    let config = DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let pool = diesel_pool_from_config(&config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    let user = repo
        .user()
        .find_by_username(&username)
        .await?
        .context("User not found")?;

    if reactivate {
        warn!(%user.id, "Scheduling user reactivation");
        repo.queue_job()
            .schedule_job(&mut rng, &clock, ReactivateUserJob::new(&user))
            .await?;
    } else {
        repo.user().unlock(user).await?;
    }

    Ok(ExitCode::SUCCESS)
}
