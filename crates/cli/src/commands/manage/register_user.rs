// Copyright 2025 Taidge Ltd.
// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2025 Taidge Ltd.
//
// Portions based on mas-cli by The Matrix.org Foundation C.I.C.

//! Interactive user registration flow and related types.

use std::collections::BTreeMap;
use std::process::ExitCode;

use anyhow::Context;
use clap::CommandFactory;
use coauth_backend::util::{diesel_pool_from_config, password_manager_from_config};
use coauth_config::{ConfigurationSectionExt, DatabaseConfig, PasswordsConfig};
use coauth_data::queue::{ProvisionUserJob, QueueJobRepositoryExt as _};
use coauth_data::user::{UserEmailRepository, UserPasswordRepository, UserRepository};
use coauth_data::{
    Clock, DatabaseError, PgRepository, RepositoryAccess, SystemClock, UpstreamOAuthProvider, User,
};
use coauth_messaging::email::Address;
use console::{Alignment, Style, Term, pad_str, style};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, FuzzySelect, Input, Password};
use figment::Figment;
use rand_core::{RngCore, SeedableRng};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::UpstreamProviderMapping;

/// A wrapper to display some objects differently
#[derive(Debug, Clone, Copy)]
struct HumanReadable<T>(T);

impl std::fmt::Display for HumanReadable<&UpstreamOAuthProvider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let provider = self.0;
        if let Some(human_name) = &provider.human_name {
            write!(f, "{} ({})", human_name, provider.id)
        } else if let Some(issuer) = &provider.issuer {
            write!(f, "{} ({})", issuer, provider.id)
        } else {
            write!(f, "{}", provider.id)
        }
    }
}

async fn check_and_normalize_handle<'a>(
    handle: &'a str,
    repo: &mut dyn RepositoryAccess<Error = DatabaseError>,
) -> anyhow::Result<&'a str> {
    let handle = handle.trim();

    if handle.is_empty() {
        return Err(anyhow::anyhow!("handle cannot be empty"));
    }

    if repo.user().exists(handle).await? {
        return Err(anyhow::anyhow!("User already exists"));
    }

    Ok(handle)
}

pub(super) struct UserCreationRequest<'a> {
    handle: String,
    hashed_password: Option<(u16, String)>,
    emails: Vec<Address>,
    upstream_provider_mappings: Vec<(&'a UpstreamOAuthProvider, String)>,
    display_name: Option<String>,
    admin: Option<bool>,
}

impl UserCreationRequest<'_> {
    // Get a list of the possible actions
    fn possible_actions(
        &self,
        has_password_auth: bool,
        has_upstream_providers: bool,
    ) -> Vec<Action> {
        let mut actions = vec![Action::CreateUser, Action::ChangeUsername, Action::AddEmail];

        if has_password_auth && self.hashed_password.is_none() {
            actions.push(Action::SetPassword);
        }

        if has_upstream_providers {
            actions.push(Action::AddUpstreamProviderMapping);
        }

        if self.admin.is_none() {
            actions.push(Action::SetAdmin);
        }

        if self.display_name.is_none() {
            actions.push(Action::SetDisplayName);
        }

        actions
    }

    /// Prompt for the next action
    async fn prompt_action(
        &self,
        has_password_auth: bool,
        has_upstream_providers: bool,
    ) -> anyhow::Result<Option<Action>> {
        let actions = self.possible_actions(has_password_auth, has_upstream_providers);
        tokio::task::spawn_blocking(move || {
            let index = FuzzySelect::with_theme(&ColorfulTheme::default())
                .with_prompt("What do you want to do next? (<Esc> to abort)")
                .items(&actions)
                .default(0)
                .interact_opt()?;
            Ok(index.map(|index| actions[index]))
        })
        .await?
    }

    /// Show the user creation request in a human-readable format
    fn show(&self, term: &Term) -> std::io::Result<()> {
        let value_style = Style::new().green();
        let key_style = Style::new().bold();
        let warning_style = Style::new().italic().red().bright();
        let handle = &self.handle;

        term.write_line(&style("User attributes").bold().underlined().to_string())?;

        macro_rules! display {
            ($key:expr, $value:expr) => {
                term.write_line(&format!(
                    "{key}: {value}",
                    key = key_style.apply_to(pad_str($key, 17, Alignment::Right, None)),
                    value = value_style.apply_to($value)
                ))?;
            };
        }

        display!("handle", handle);
        if let Some(display_name) = &self.display_name {
            display!("Display name", display_name);
        }

        if self.hashed_password.is_some() {
            display!("Password", "********");
        }

        for (provider, subject) in &self.upstream_provider_mappings {
            let provider = HumanReadable(*provider);
            display!("Upstream account", format!("{provider} : {subject:?}"));
        }

        for email in &self.emails {
            display!("Email", email);
        }

        if self.emails.is_empty() {
            term.write_line(
                &warning_style
                    .apply_to("No email address provided, user will be prompted to add one")
                    .to_string(),
            )?;
        }

        if self.hashed_password.is_none() && self.upstream_provider_mappings.is_empty() {
            term.write_line(
                &warning_style.apply_to("No password or upstream provider mapping provided, user will not be able to log in")
                    .to_string(),
            )?;
        }

        if let Some(admin) = self.admin {
            display!("Can request admin", admin);
        }

        term.flush()?;

        Ok(())
    }

    /// Submit the user creation request
    async fn do_register<E: std::error::Error + Send + Sync + 'static>(
        self,
        repo: &mut dyn RepositoryAccess<Error = E>,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<User, E> {
        let Self {
            handle,
            hashed_password,
            emails,
            upstream_provider_mappings,
            display_name,
            admin,
        } = self;
        let mut user = repo.user().add(rng, clock, handle).await?;

        if let Some((version, hashed_password)) = hashed_password {
            repo.user_password()
                .add(rng, clock, &user, version, hashed_password, None)
                .await?;
        }

        for email in emails {
            repo.user_email()
                .add(rng, clock, &user, email.to_string())
                .await?;
        }

        for (provider, subject) in upstream_provider_mappings {
            // Note that we don't pass a human_account_name here, as we don't ask for it
            let link = repo
                .upstream_oauth_link()
                .add(rng, clock, provider, subject, None)
                .await?;

            repo.upstream_oauth_link()
                .associate_to_user(&link, &user)
                .await?;
        }

        if let Some(admin) = admin {
            user = repo.user().set_can_request_admin(user, admin).await?;
        }

        let mut provision_job = ProvisionUserJob::new(&user);
        if let Some(display_name) = display_name {
            provision_job = provision_job.set_display_name(display_name);
        }

        repo.queue_job()
            .schedule_job(rng, clock, provision_job)
            .await?;

        Ok(user)
    }
}

#[derive(Debug, Clone, Copy)]
enum Action {
    CreateUser,
    ChangeUsername,
    SetPassword,
    SetDisplayName,
    AddEmail,
    SetAdmin,
    AddUpstreamProviderMapping,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::CreateUser => write!(f, "Create the user"),
            Action::ChangeUsername => write!(f, "Change the handle"),
            Action::SetPassword => write!(f, "Set a password"),
            Action::AddEmail => write!(f, "Add email"),
            Action::SetDisplayName => write!(f, "Set a display name"),
            Action::SetAdmin => write!(f, "Set the admin status"),
            Action::AddUpstreamProviderMapping => write!(f, "Add upstream provider mapping"),
        }
    }
}

/// A wrapper to display the user creation request as a command
struct UserCreationCommand<'a>(&'a UserCreationRequest<'a>);

impl std::fmt::Display for UserCreationCommand<'_> {
    fn fmt(&self, w: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let command = crate::commands::Options::command();
        let manage = command.find_subcommand("manage").unwrap();
        let register_user = manage.find_subcommand("register-user").unwrap();
        let yes_arg = &register_user[&clap::Id::from("yes")];
        let password_arg = &register_user[&clap::Id::from("password")];
        let email_arg = &register_user[&clap::Id::from("emails")];
        let upstream_provider_mapping_arg =
            &register_user[&clap::Id::from("upstream_provider_mappings")];
        let display_name_arg = &register_user[&clap::Id::from("display_name")];
        let admin_arg = &register_user[&clap::Id::from("admin")];
        let no_admin_arg = &register_user[&clap::Id::from("no_admin")];

        write!(
            w,
            "{} {} {} --{} {}",
            command.get_name(),
            manage.get_name(),
            register_user.get_name(),
            yes_arg.get_long().unwrap(),
            self.0.handle,
        )?;

        for email in &self.0.emails {
            let email: &str = email.as_ref();
            write!(w, " --{} {email:?}", email_arg.get_long().unwrap())?;
        }

        if let Some(display_name) = &self.0.display_name {
            write!(
                w,
                " --{} {:?}",
                display_name_arg.get_long().unwrap(),
                display_name
            )?;
        }

        if self.0.hashed_password.is_some() {
            write!(w, " --{} $PASSWORD", password_arg.get_long().unwrap())?;
        }

        for (provider, subject) in &self.0.upstream_provider_mappings {
            let mapping = format!("{}:{}", provider.id, subject);
            write!(
                w,
                " --{} {mapping:?}",
                upstream_provider_mapping_arg.get_long().unwrap(),
            )?;
        }

        match self.0.admin {
            Some(true) => write!(w, " --{}", admin_arg.get_long().unwrap())?,
            Some(false) => write!(w, " --{}", no_admin_arg.get_long().unwrap())?,
            None => {}
        }

        Ok(())
    }
}

/// Handle the interactive register-user subcommand.
#[expect(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub(super) async fn handle_register_user(
    figment: &Figment,
    handle: Option<String>,
    password: Option<String>,
    emails: Vec<Address>,
    upstream_provider_mappings: Vec<UpstreamProviderMapping>,
    admin: bool,
    no_admin: bool,
    display_name: Option<String>,
    yes: bool,
    ignore_password_complexity: bool,
) -> anyhow::Result<ExitCode> {
    let clock = SystemClock::default();
    let mut rng = rand_chacha::ChaChaRng::from_entropy();

    let password_config =
        PasswordsConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
    let database_config =
        DatabaseConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;

    let password_manager = password_manager_from_config(&password_config).await?;
    let pool = diesel_pool_from_config(&database_config).await?;
    let conn = pool
        .get()
        .await
        .context("could not get connection from pool")?;
    let mut repo = PgRepository::new(conn);

    if let Some(password) = &password
        && !ignore_password_complexity
        && !password_manager.is_password_complex_enough(password)?
    {
        tracing::error!("That password is too weak.");
        return Ok(ExitCode::from(1));
    }

    // If the handle is provided, check if it's available and normalize it.
    let handle = if let Some(handle) = handle {
        check_and_normalize_handle(&handle, &mut repo)
            .await?
            .to_owned()
    } else {
        // Else we prompt for one until we get a valid one.
        loop {
            let handle = tokio::task::spawn_blocking(|| {
                Input::<String>::with_theme(&ColorfulTheme::default())
                    .with_prompt("handle")
                    .interact_text()
            })
            .await??;

            match check_and_normalize_handle(&handle, &mut repo).await {
                Ok(handle) => break handle.to_owned(),
                Err(e) => {
                    warn!("Invalid handle: {e}");
                }
            }
        }
    };

    // Load all the upstream providers
    let upstream_providers: BTreeMap<_, _> = repo
        .upstream_oauth_provider()
        .all_enabled()
        .await?
        .into_iter()
        .map(|provider| (provider.id, provider))
        .collect();

    let upstream_provider_mappings = upstream_provider_mappings
        .into_iter()
        .map(|mapping| {
            (
                &upstream_providers[&mapping.upstream_provider_id],
                mapping.subject,
            )
        })
        .collect();

    let admin = match (admin, no_admin) {
        (false, false) => None,
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => unreachable!("This should be handled by the clap group"),
    };

    // Hash the password if it's provided
    let hashed_password = if let Some(password) = password {
        let password = Zeroizing::new(password);
        Some(password_manager.hash(&mut rng, password).await?)
    } else {
        None
    };

    let mut req = UserCreationRequest {
        handle,
        hashed_password,
        emails,
        upstream_provider_mappings,
        display_name,
        admin,
    };

    let term = Term::buffered_stdout();
    loop {
        req.show(&term)?;

        // If we're in `yes` mode, we don't prompt for actions
        if yes {
            break;
        }

        term.write_line(&format!(
            "\n{msg}:\n\n  {cmd}\n",
            msg = style("Non-interactive equivalent to create this user").bold(),
            cmd = style(UserCreationCommand(&req)).underlined(),
        ))?;

        term.flush()?;

        let action = req
            .prompt_action(
                password_manager.is_enabled(),
                !upstream_providers.is_empty(),
            )
            .await?
            .context("Aborted")?;

        match action {
            Action::CreateUser => break,
            Action::ChangeUsername => {
                req.handle = loop {
                    let current_handle = req.handle.clone();
                    let handle = tokio::task::spawn_blocking(|| {
                        Input::<String>::with_theme(&ColorfulTheme::default())
                            .with_prompt("handle")
                            .with_initial_text(current_handle)
                            .interact_text()
                    })
                    .await??;

                    match check_and_normalize_handle(&handle, &mut repo).await {
                        Ok(handle) => break handle.to_owned(),
                        Err(e) => {
                            warn!("Invalid handle: {e}");
                        }
                    }
                };
            }
            Action::SetPassword => {
                let password = tokio::task::spawn_blocking(|| {
                    Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Password")
                        .with_confirmation("Confirm password", "Passwords mismatching")
                        .interact()
                })
                .await??;
                let password = Zeroizing::new(password);
                req.hashed_password = Some(password_manager.hash(&mut rng, password).await?);
            }
            Action::SetDisplayName => {
                let display_name = tokio::task::spawn_blocking(|| {
                    Input::<String>::with_theme(&ColorfulTheme::default())
                        .with_prompt("Display name")
                        .interact()
                })
                .await??;
                req.display_name = Some(display_name);
            }
            Action::AddEmail => {
                let email = tokio::task::spawn_blocking(|| {
                    Input::<Address>::with_theme(&ColorfulTheme::default())
                        .with_prompt("Email")
                        .interact_text()
                })
                .await??;
                req.emails.push(email);
            }
            Action::SetAdmin => {
                let admin = tokio::task::spawn_blocking(|| {
                    Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Make user admin?")
                        .interact()
                })
                .await??;
                req.admin = Some(admin);
            }
            Action::AddUpstreamProviderMapping => {
                let providers = upstream_providers.clone();
                let provider_id = tokio::task::spawn_blocking(move || {
                    let providers: Vec<_> = providers.into_values().collect();
                    let human_readable_providers: Vec<_> =
                        providers.iter().map(HumanReadable).collect();
                    FuzzySelect::with_theme(&ColorfulTheme::default())
                        .with_prompt("Upstream provider")
                        .items(&human_readable_providers)
                        .default(0)
                        .interact()
                        .map(move |selected| providers[selected].id)
                })
                .await??;
                let provider = &upstream_providers[&provider_id];

                let subject = tokio::task::spawn_blocking(|| {
                    Input::<String>::with_theme(&ColorfulTheme::default())
                        .with_prompt("Subject")
                        .interact()
                })
                .await??;

                req.upstream_provider_mappings.push((provider, subject));
            }
        }
    }

    if req.emails.is_empty() {
        warn!("No email address provided, user will need to add one");
    }

    let confirmation = if yes {
        true
    } else {
        tokio::task::spawn_blocking(|| {
            Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Confirm?")
                .interact()
        })
        .await??
    };

    if confirmation {
        let user = req.do_register(&mut repo, &mut rng, &clock).await?;
        info!(%user.id, "User registered");
    } else {
        warn!("Aborted");
    }

    Ok(ExitCode::SUCCESS)
}
