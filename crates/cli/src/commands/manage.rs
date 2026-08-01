// Copyright 2025 Taidge Ltd.
// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2025 Taidge Ltd.
//
// Portions based on mas-cli by The Matrix.org Foundation C.I.C.

//! CLI subcommands for managing the coauth instance (users, tokens, sessions,
//! etc.).

mod command_handlers;
mod register_user;

use std::process::ExitCode;

use anyhow::Context;
use clap::{ArgAction, Parser};
use coauth_data::Ulid;
use coauth_messaging::email::Address;
use figment::Figment;

const USER_ATTRIBUTES_HEADING: &str = "User attributes";

#[derive(Debug, Clone)]
struct UpstreamProviderMapping {
    upstream_provider_id: Ulid,
    subject: String,
}

fn parse_upstream_provider_mapping(s: &str) -> Result<UpstreamProviderMapping, anyhow::Error> {
    let (id, subject) = s.split_once(':').context("Invalid format")?;
    let upstream_provider_id = id.parse().context("Invalid upstream provider ID")?;
    let subject = subject.to_owned();

    Ok(UpstreamProviderMapping {
        upstream_provider_id,
        subject,
    })
}

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Add an email address to the specified user
    AddEmail { handle: String, email: String },

    /// Set a user password
    SetPassword {
        handle: String,
        password: String,
        /// Don't enforce that the password provided is above the minimum
        /// configured complexity.
        #[clap(long)]
        ignore_complexity: bool,
    },

    /// Make a user admin
    PromoteAdmin { handle: String },

    /// Make a user non-admin
    DemoteAdmin { handle: String },

    /// List all users with admin privileges
    ListAdminUsers,

    /// Create a new user registration token
    IssueUserRegistrationToken {
        /// Specific token string to use. If not provided, a random token will
        /// be generated.
        #[arg(long)]
        token: Option<String>,

        /// Maximum number of times this token can be used.
        /// If not provided, the token can be used only once, unless the
        /// `--unlimited` flag is set.
        #[arg(long, group = "token-usage-limit")]
        usage_limit: Option<u32>,

        /// Allow the token to be used an unlimited number of times.
        #[arg(long, action = ArgAction::SetTrue, group = "token-usage-limit")]
        unlimited: bool,

        /// Time in seconds after which the token expires.
        /// If not provided, the token never expires.
        #[arg(long)]
        expires_in: Option<u32>,
    },

    /// Trigger a provisioning job for all users
    ProvisionAllUsers,

    /// Kill all sessions for a user
    KillSessions {
        /// User for which to kill sessions
        handle: String,

        /// Do a dry run
        #[arg(long)]
        dry_run: bool,
    },

    /// Lock a user
    LockUser {
        /// User to lock
        handle: String,

        /// Whether to deactivate the user
        #[arg(long)]
        deactivate: bool,
    },

    /// Unlock a user
    UnlockUser {
        /// User to unlock
        handle: String,
    },

    /// Register a user
    ///
    /// This will interactively prompt for the user's attributes unless the
    /// `--yes` flag is set. It bypasses any policy check on the password,
    /// email, etc.
    RegisterUser {
        /// handle to register
        #[arg(help_heading = USER_ATTRIBUTES_HEADING, required_if_eq("yes", "true"))]
        handle: Option<String>,

        /// Password to set
        #[arg(short, long, help_heading = USER_ATTRIBUTES_HEADING)]
        password: Option<String>,

        /// Email to add
        #[arg(short, long = "email", action = ArgAction::Append, help_heading = USER_ATTRIBUTES_HEADING)]
        emails: Vec<Address>,

        /// Upstream OAuth provider mapping to add
        #[arg(
            short = 'm',
            long = "upstream-provider-mapping",
            value_parser = parse_upstream_provider_mapping,
            action = ArgAction::Append,
            value_name = "UPSTREAM_PROVIDER_ID:SUBJECT",
            help_heading = USER_ATTRIBUTES_HEADING
        )]
        upstream_provider_mappings: Vec<UpstreamProviderMapping>,

        /// Make the user an admin
        #[arg(short, long, action = ArgAction::SetTrue, group = "admin-flag", help_heading = USER_ATTRIBUTES_HEADING)]
        admin: bool,

        /// Make the user not an admin
        #[arg(short = 'A', long, action = ArgAction::SetTrue, group = "admin-flag", help_heading = USER_ATTRIBUTES_HEADING)]
        no_admin: bool,

        // Don't ask questions, just do it
        #[arg(short, long, action = ArgAction::SetTrue)]
        yes: bool,

        /// Set the user's display name
        #[arg(short, long, help_heading = USER_ATTRIBUTES_HEADING)]
        display_name: Option<String>,
        /// Don't enforce that the password provided is above the minimum
        /// configured complexity.
        #[clap(long)]
        ignore_password_complexity: bool,
    },
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;

        match self.subcommand {
            SC::SetPassword {
                handle,
                password,
                ignore_complexity,
            } => {
                command_handlers::handle_set_password(figment, handle, password, ignore_complexity)
                    .await
            }

            SC::AddEmail { handle, email } => {
                command_handlers::handle_add_email(figment, handle, email).await
            }

            SC::PromoteAdmin { handle } => {
                command_handlers::handle_promote_admin(figment, handle).await
            }

            SC::DemoteAdmin { handle } => {
                command_handlers::handle_demote_admin(figment, handle).await
            }

            SC::ListAdminUsers => command_handlers::handle_list_admin_users(figment).await,

            SC::IssueUserRegistrationToken {
                token,
                usage_limit,
                unlimited,
                expires_in,
            } => {
                command_handlers::handle_issue_registration_token(
                    figment,
                    token,
                    usage_limit,
                    unlimited,
                    expires_in,
                )
                .await
            }

            SC::ProvisionAllUsers => command_handlers::handle_provision_all_users(figment).await,

            SC::KillSessions { handle, dry_run } => {
                command_handlers::handle_kill_sessions(figment, handle, dry_run).await
            }

            SC::LockUser { handle, deactivate } => {
                command_handlers::handle_lock_user(figment, handle, deactivate).await
            }

            SC::UnlockUser { handle } => {
                command_handlers::handle_unlock_user(figment, handle).await
            }

            SC::RegisterUser {
                handle,
                password,
                emails,
                upstream_provider_mappings,
                admin,
                no_admin,
                display_name,
                yes,
                ignore_password_complexity,
            } => {
                register_user::handle_register_user(
                    figment,
                    handle,
                    password,
                    emails,
                    upstream_provider_mappings,
                    admin,
                    no_admin,
                    display_name,
                    yes,
                    ignore_password_complexity,
                )
                .await
            }
        }
    }
}
