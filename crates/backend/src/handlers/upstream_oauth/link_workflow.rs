use std::net::IpAddr;

use anyhow::Error as AnyhowError;
use coauth_account_types::UpstreamLinkFieldErrors;
use coauth_data::upstream_oauth::{
    UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
    UpstreamOAuthSessionRepository,
};
use coauth_data::user::{
    BrowserSessionRepository, UserEmailRepository, UserRegistrationRepository, UserRepository,
};
use coauth_data::{
    BoxRepository, BrowserSession, Clock, Pagination, PostAuthAction, RepositoryAccess,
    RepositoryError, SiteConfig, UpstreamOAuthAuthorizationSession, UpstreamOAuthLink,
    UpstreamOAuthProvider, UpstreamOAuthProviderOnConflict, UrlBuilder, User, UserRegistration,
};
use coauth_jose::jwt::Jwt;
use coauth_policy::{
    PolicyInstance, RegisterInput, RegistrationMethod, Requester as PolicyRequester,
};
use coauth_principal::ConnectorAdmin;
use minijinja::Environment;
use rand_core::RngCore;
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::post_auth::OptionalPostAuthAction;
use crate::handlers::upstream_oauth::UpstreamSessionsCookie;
use crate::handlers::upstream_oauth::template::{AttributeMappingContext, environment};
use crate::salvo_utils::SessionInfo;

const DEFAULT_HANDLE_TEMPLATE: &str = "{{ user.preferred_username }}";
const DEFAULT_DISPLAYNAME_TEMPLATE: &str = "{{ user.name }}";
const DEFAULT_EMAIL_TEMPLATE: &str = "{{ user.email }}";
const DEFAULT_AVATAR_TEMPLATE: &str = "{{ user.picture }}";

#[derive(Debug, Error)]
pub enum UpstreamLinkWorkflowError {
    #[error("missing upstream session cookie")]
    MissingCookie,

    #[error("upstream OAuth link not found")]
    LinkNotFound,

    #[error("upstream OAuth session not found")]
    SessionNotFound,

    #[error("upstream OAuth session already consumed")]
    SessionConsumed,

    #[error("user not found")]
    UserNotFound,

    #[error("upstream OAuth provider not found")]
    ProviderNotFound,

    #[error("template {template:?} rendered to an empty string")]
    RequiredAttributeEmpty { template: String },

    #[error("failed to render required template {template:?}")]
    RequiredAttributeRender {
        template: String,
        #[source]
        source: minijinja::Error,
    },

    #[error("username conflict: existing user cannot be linked (on_conflict=fail)")]
    ConflictFail { handle: String },

    #[error(
        "username conflict: existing user already has a link to this provider (on_conflict=set)"
    )]
    ConflictSetBlocked { handle: String },

    #[error("policy denied the suggested username")]
    PolicyDeniedHandle { handle: String, detail: String },

    #[error("username not available on principal server")]
    HandleUnavailable { handle: String },

    #[error("principal server admin call failed")]
    ConnectorAdmin(#[source] AnyhowError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Internal(#[from] AnyhowError),
}

impl UpstreamLinkWorkflowError {
    fn internal<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Internal(AnyhowError::new(error))
    }

    fn principal_server(error: AnyhowError) -> Self {
        Self::ConnectorAdmin(error)
    }
}

pub struct LoadedUpstreamLinkContext {
    pub link: UpstreamOAuthLink,
    pub upstream_session: UpstreamOAuthAuthorizationSession,
    pub browser_session: Option<BrowserSession>,
    pub post_auth_action: Option<PostAuthAction>,
}

pub struct UpstreamRegisterScreen {
    pub suggested_handle: Option<String>,
    pub handle_forced: bool,
    pub suggested_display_name: Option<String>,
    pub display_name_forced: bool,
    pub suggested_email: Option<String>,
    pub email_forced: bool,
    pub provider_name: Option<String>,
    pub has_tos: bool,
}

#[allow(clippy::large_enum_variant)]
pub enum LoadUpstreamLinkOutcome {
    Authenticated {
        session: BrowserSession,
        redirect_url: String,
    },
    LoggedIn {
        session: BrowserSession,
        redirect_url: String,
        provider_id: Ulid,
    },
    LinkMismatch {
        existing_handle: String,
    },
    SuggestLink {
        provider_name: Option<String>,
        upstream_subject: Option<String>,
    },
    Register {
        screen: UpstreamRegisterScreen,
    },
    Registered {
        registration: UserRegistration,
        redirect_url: String,
        provider_id: Ulid,
    },
    AccountDeactivated {
        handle: String,
    },
    AccountLocked {
        handle: String,
    },
}

pub enum UpstreamLinkAction {
    LinkCurrentSession,
    Register(UpstreamLinkRegistrationAction),
}

pub struct UpstreamLinkRegistrationAction {
    pub handle: Option<String>,
    pub import_email: bool,
    pub import_display_name: bool,
    pub accept_terms: bool,
}

#[allow(clippy::large_enum_variant)]
pub enum SubmitUpstreamLinkOutcome {
    Linked {
        session: BrowserSession,
        redirect_url: String,
    },
    Registered {
        registration: UserRegistration,
        redirect_url: String,
        provider_id: Ulid,
    },
}

#[derive(Debug, Error)]
pub enum SubmitUpstreamLinkError {
    #[error("invalid action for current upstream link state")]
    InvalidAction,

    #[error("validation failed")]
    Validation {
        field_errors: UpstreamLinkFieldErrors,
    },

    #[error(transparent)]
    Workflow(#[from] UpstreamLinkWorkflowError),
}

pub async fn load_upstream_link_context(
    repo: &mut BoxRepository,
    session_info: &SessionInfo,
    sessions_cookie: &UpstreamSessionsCookie,
    link_id: Ulid,
) -> Result<LoadedUpstreamLinkContext, UpstreamLinkWorkflowError> {
    let (session_id, post_auth_action) = sessions_cookie
        .lookup_link(link_id)
        .map_err(|_| UpstreamLinkWorkflowError::MissingCookie)?;

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(UpstreamLinkWorkflowError::LinkNotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(UpstreamLinkWorkflowError::SessionNotFound)?;

    if upstream_session.link_id() != Some(link.id) {
        return Err(UpstreamLinkWorkflowError::SessionNotFound);
    }

    if upstream_session.is_consumed() {
        return Err(UpstreamLinkWorkflowError::SessionConsumed);
    }

    let browser_session = session_info.load_active_session(repo).await?;

    Ok(LoadedUpstreamLinkContext {
        link,
        upstream_session,
        browser_session,
        post_auth_action: post_auth_action.cloned(),
    })
}

pub async fn load_upstream_link_state(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    principal_server: &dyn ConnectorAdmin,
    policy: &mut PolicyInstance,
    site_config: &SiteConfig,
    user_agent: Option<String>,
    ip_address: Option<IpAddr>,
    context: LoadedUpstreamLinkContext,
) -> Result<LoadUpstreamLinkOutcome, UpstreamLinkWorkflowError> {
    let LoadedUpstreamLinkContext {
        link,
        upstream_session,
        browser_session,
        post_auth_action,
    } = context;
    let redirect_url =
        OptionalPostAuthAction::from(post_auth_action.clone()).next_relative_url(url_builder);

    match (browser_session, link.user_id) {
        (Some(session), Some(user_id)) if session.user.id == user_id => {
            let upstream_session = repo
                .upstream_oauth_session()
                .consume(clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(rng, clock, &session, &upstream_session)
                .await?;

            Ok(LoadUpstreamLinkOutcome::Authenticated {
                session,
                redirect_url,
            })
        }

        (Some(_session), Some(user_id)) => {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(UpstreamLinkWorkflowError::UserNotFound)?;

            Ok(LoadUpstreamLinkOutcome::LinkMismatch {
                existing_handle: user.localpart,
            })
        }

        (Some(_session), None) => {
            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await?
                .ok_or(UpstreamLinkWorkflowError::ProviderNotFound)?;

            Ok(LoadUpstreamLinkOutcome::SuggestLink {
                provider_name: provider.human_name,
                upstream_subject: Some(link.subject),
            })
        }

        (None, Some(user_id)) => {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or(UpstreamLinkWorkflowError::UserNotFound)?;

            if user.deactivated_at.is_some() {
                return Ok(LoadUpstreamLinkOutcome::AccountDeactivated {
                    handle: user.localpart,
                });
            }

            if user.locked_at.is_some() {
                return Ok(LoadUpstreamLinkOutcome::AccountLocked {
                    handle: user.localpart,
                });
            }

            let session = repo
                .browser_session()
                .add(rng, clock, &user, user_agent)
                .await?;

            let upstream_session = repo
                .upstream_oauth_session()
                .consume(clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(rng, clock, &session, &upstream_session)
                .await?;

            Ok(LoadUpstreamLinkOutcome::LoggedIn {
                session,
                redirect_url,
                provider_id: upstream_session.provider_id,
            })
        }

        (None, None) => {
            load_upstream_registration_screen(
                repo,
                rng,
                clock,
                url_builder,
                principal_server,
                policy,
                site_config,
                user_agent,
                ip_address,
                link,
                upstream_session,
                post_auth_action,
            )
            .await
        }
    }
}

pub async fn submit_upstream_link_action(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    principal_server: &dyn ConnectorAdmin,
    policy: &mut PolicyInstance,
    site_config: &SiteConfig,
    user_agent: Option<String>,
    ip_address: Option<IpAddr>,
    context: LoadedUpstreamLinkContext,
    action: UpstreamLinkAction,
) -> Result<SubmitUpstreamLinkOutcome, SubmitUpstreamLinkError> {
    let LoadedUpstreamLinkContext {
        link,
        upstream_session,
        browser_session,
        post_auth_action,
    } = context;
    let redirect_url =
        OptionalPostAuthAction::from(post_auth_action.clone()).next_relative_url(url_builder);

    match (browser_session, link.user_id, action) {
        (Some(session), None, UpstreamLinkAction::LinkCurrentSession) => {
            repo.upstream_oauth_link()
                .associate_to_user(&link, &session.user)
                .await
                .map_err(UpstreamLinkWorkflowError::from)?;

            let upstream_session = repo
                .upstream_oauth_session()
                .consume(clock, upstream_session, &session)
                .await
                .map_err(UpstreamLinkWorkflowError::from)?;

            repo.browser_session()
                .authenticate_with_upstream(rng, clock, &session, &upstream_session)
                .await
                .map_err(UpstreamLinkWorkflowError::from)?;

            Ok(SubmitUpstreamLinkOutcome::Linked {
                session,
                redirect_url,
            })
        }

        (None, None, UpstreamLinkAction::Register(action)) => {
            let provider = repo
                .upstream_oauth_provider()
                .lookup(link.provider_id)
                .await
                .map_err(UpstreamLinkWorkflowError::from)?
                .ok_or(UpstreamLinkWorkflowError::ProviderNotFound)?;

            let attributes =
                resolve_registration_attributes(&provider, &upstream_session, &action)?;

            let field_errors = validate_registration_action(
                repo,
                principal_server,
                policy,
                site_config,
                ip_address,
                user_agent.clone(),
                &attributes.handle,
                attributes.email.as_deref(),
                action.accept_terms,
            )
            .await?;

            if !field_errors.is_empty() {
                return Err(SubmitUpstreamLinkError::Validation { field_errors });
            }

            let mut registration = prepare_user_registration(
                rng,
                clock,
                repo,
                upstream_session,
                attributes.handle,
                attributes.display_name,
                attributes.email,
                attributes.avatar_url,
                ip_address,
                user_agent,
                post_auth_action,
            )
            .await?;

            if let Some(terms_url) = &site_config.tos_uri {
                registration = repo
                    .user_registration()
                    .set_terms_url(registration, terms_url.clone())
                    .await
                    .map_err(UpstreamLinkWorkflowError::from)?;
            }

            Ok(SubmitUpstreamLinkOutcome::Registered {
                redirect_url: url_builder
                    .relative_url(&format!("/register/steps/{}/finish", registration.id)),
                registration,
                provider_id: provider.id,
            })
        }

        _ => Err(SubmitUpstreamLinkError::InvalidAction),
    }
}

async fn load_upstream_registration_screen(
    repo: &mut BoxRepository,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    url_builder: &UrlBuilder,
    principal_server: &dyn ConnectorAdmin,
    policy: &mut PolicyInstance,
    site_config: &SiteConfig,
    user_agent: Option<String>,
    ip_address: Option<IpAddr>,
    link: UpstreamOAuthLink,
    upstream_session: UpstreamOAuthAuthorizationSession,
    post_auth_action: Option<PostAuthAction>,
) -> Result<LoadUpstreamLinkOutcome, UpstreamLinkWorkflowError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(link.provider_id)
        .await?
        .ok_or(UpstreamLinkWorkflowError::ProviderNotFound)?;

    let suggestions = resolve_registration_suggestions(&provider, &upstream_session)?;
    let redirect_url =
        OptionalPostAuthAction::from(post_auth_action.clone()).next_relative_url(url_builder);

    // If we have a suggested username, run pre-checks (policy, conflicts,
    // PrincipalServer availability)
    let username = match pre_check_handle(
        repo,
        clock,
        principal_server,
        policy,
        &provider,
        &link,
        suggestions.suggested_handle,
        suggestions.suggested_email.as_deref(),
        user_agent.clone(),
        ip_address,
    )
    .await?
    {
        HandlePreCheckResult::Available(username) => username,
        HandlePreCheckResult::ConflictResolved {
            user: existing_user,
            provider_id,
        } => {
            // Conflict was resolved by linking to an existing user. Check
            // user status and log them in.
            if existing_user.deactivated_at.is_some() {
                return Ok(LoadUpstreamLinkOutcome::AccountDeactivated {
                    handle: existing_user.localpart,
                });
            }

            if existing_user.locked_at.is_some() {
                return Ok(LoadUpstreamLinkOutcome::AccountLocked {
                    handle: existing_user.localpart,
                });
            }

            let session = repo
                .browser_session()
                .add(rng, clock, &existing_user, user_agent)
                .await?;

            let upstream_session = repo
                .upstream_oauth_session()
                .consume(clock, upstream_session, &session)
                .await?;

            repo.browser_session()
                .authenticate_with_upstream(rng, clock, &session, &upstream_session)
                .await?;

            return Ok(LoadUpstreamLinkOutcome::LoggedIn {
                session,
                redirect_url,
                provider_id,
            });
        }
    };

    if provider.claims_imports.skip_confirmation {
        let Some(ref username) = username else {
            return Err(UpstreamLinkWorkflowError::Internal(AnyhowError::msg(
                "No username available even though the provider is configured to skip confirmation",
            )));
        };

        let registration = prepare_user_registration(
            rng,
            clock,
            repo,
            upstream_session,
            username.clone(),
            suggestions.suggested_display_name.clone(),
            suggestions.suggested_email.clone(),
            suggestions.suggested_avatar_url.clone(),
            ip_address,
            user_agent,
            post_auth_action,
        )
        .await?;

        return Ok(LoadUpstreamLinkOutcome::Registered {
            redirect_url: url_builder
                .relative_url(&format!("/register/steps/{}/finish", registration.id)),
            registration,
            provider_id: provider.id,
        });
    }

    let handle_forced = provider.claims_imports.handle.is_forced_or_required();
    let display_name_forced = provider.claims_imports.displayname.is_forced_or_required();
    let email_forced = provider.claims_imports.email.is_forced_or_required();
    let provider_name = provider.human_name.clone();
    Ok(LoadUpstreamLinkOutcome::Register {
        screen: UpstreamRegisterScreen {
            suggested_handle: username,
            handle_forced,
            suggested_display_name: suggestions.suggested_display_name,
            display_name_forced,
            suggested_email: suggestions.suggested_email,
            email_forced,
            provider_name,
            has_tos: site_config.tos_uri.is_some(),
        },
    })
}

/// Result of pre-checking a suggested username from the upstream provider.
enum HandlePreCheckResult {
    /// The username is valid and available for registration.
    Available(Option<String>),
    /// The username matched an existing user whose conflict was resolved by
    /// linking. The caller should log this user in.
    ///
    /// `user` is boxed because [`User`] is ~240 bytes — keeping the enum
    /// itself small avoids forcing every `Available(...)` value to carry
    /// that footprint through call-stack returns.
    ConflictResolved { user: Box<User>, provider_id: Ulid },
}

/// Pre-check a suggested username from the upstream provider.
///
/// This runs policy checks, user conflict resolution (using the provider's
/// `on_conflict` setting), and `PrincipalServer` availability checks on the
/// suggested username.
#[allow(clippy::too_many_arguments)]
async fn pre_check_handle(
    repo: &mut BoxRepository,
    clock: &dyn Clock,
    principal_server: &dyn ConnectorAdmin,
    policy: &mut PolicyInstance,
    provider: &UpstreamOAuthProvider,
    link: &UpstreamOAuthLink,
    suggested_handle: Option<String>,
    email: Option<&str>,
    user_agent: Option<String>,
    ip_address: Option<IpAddr>,
) -> Result<HandlePreCheckResult, UpstreamLinkWorkflowError> {
    let Some(username) = suggested_handle else {
        return Ok(HandlePreCheckResult::Available(None));
    };

    let forced_or_required = provider.claims_imports.handle.is_forced_or_required();

    // Run policy check on the suggested username
    let eval_result = policy
        .evaluate_register(RegisterInput {
            registration_method: RegistrationMethod::UpstreamOAuth,
            handle: &username,
            email,
            requester: PolicyRequester {
                ip_address,
                user_agent: user_agent.clone(),
                ..Default::default()
            },
        })
        .await
        .map_err(UpstreamLinkWorkflowError::internal)?;

    // Only look for violations on the username field at this stage
    if eval_result
        .violations
        .iter()
        .any(|violation| violation.field.as_deref() == Some("handle"))
    {
        if !forced_or_required {
            tracing::warn!(
                upstream_oauth_provider.id = %provider.id,
                upstream_oauth_link.id = %link.id,
                "Upstream provider returned a username {username:?} which was denied by the policy ({eval_result}). As the username is just a suggestion, it was ignored."
            );
            return Ok(HandlePreCheckResult::Available(None));
        }

        return Err(UpstreamLinkWorkflowError::PolicyDeniedHandle {
            handle: username,
            detail: eval_result.to_string(),
        });
    }

    // Check if the username conflicts with an existing user
    let maybe_existing_user = repo.user().find_by_handle(&username).await?;
    if let Some(existing_user) = maybe_existing_user {
        if !forced_or_required {
            tracing::warn!(
                upstream_oauth_provider.id = %provider.id,
                upstream_oauth_link.id = %link.id,
                user.id = %existing_user.id,
                "Upstream provider returned a username {username:?} which is already used by another user. As the username is just a suggestion, it was ignored."
            );
            return Ok(HandlePreCheckResult::Available(None));
        }

        // Apply conflict resolution
        match provider.claims_imports.handle.on_conflict {
            UpstreamOAuthProviderOnConflict::Fail => {
                tracing::warn!(
                    upstream_oauth_provider.id = %provider.id,
                    upstream_oauth_link.id = %link.id,
                    user.id = %existing_user.id,
                    "Upstream provider returned a username {username:?} which is already used by another user. Configuration doesn't allow for automatic linking of existing users."
                );
                return Err(UpstreamLinkWorkflowError::ConflictFail { handle: username });
            }

            UpstreamOAuthProviderOnConflict::Add => {
                tracing::info!(
                    user.id = %existing_user.id,
                    upstream_oauth_provider.id = %provider.id,
                    upstream_oauth_link.id = %link.id,
                    upstream_oauth_link.subject = link.subject,
                    "Upstream account mapped username {username:?} matched an existing user, linking"
                );
                repo.upstream_oauth_link()
                    .associate_to_user(link, &existing_user)
                    .await?;
            }

            UpstreamOAuthProviderOnConflict::Replace => {
                let filter = UpstreamOAuthLinkFilter::new()
                    .for_provider(provider)
                    .for_user(&existing_user);
                let mut cursor = Pagination::first(100);
                let mut removed = 0;
                loop {
                    let page = repo.upstream_oauth_link().list(filter, cursor).await?;
                    for edge in page.edges {
                        repo.upstream_oauth_link().remove(clock, edge.node).await?;
                        cursor = cursor.after(edge.cursor);
                        removed += 1;
                    }

                    if !page.has_next_page {
                        break;
                    }
                }

                if removed > 0 {
                    tracing::warn!(
                        user.id = %existing_user.id,
                        upstream_oauth_provider.id = %provider.id,
                        upstream_oauth_link.id = %link.id,
                        upstream_oauth_link.subject = link.subject,
                        "Upstream account mapped username {username:?} matched an existing user, replaced {removed} links"
                    );
                } else {
                    tracing::info!(
                        user.id = %existing_user.id,
                        upstream_oauth_provider.id = %provider.id,
                        upstream_oauth_link.id = %link.id,
                        upstream_oauth_link.subject = link.subject,
                        "Upstream account mapped username {username:?} matched an existing user, linking"
                    );
                }

                repo.upstream_oauth_link()
                    .associate_to_user(link, &existing_user)
                    .await?;
            }

            UpstreamOAuthProviderOnConflict::Set => {
                let filter = UpstreamOAuthLinkFilter::new()
                    .for_provider(provider)
                    .for_user(&existing_user);

                let count = repo.upstream_oauth_link().count(filter).await?;
                if count > 0 {
                    tracing::warn!(
                        upstream_oauth_provider.id = %provider.id,
                        upstream_oauth_link.id = %link.id,
                        user.id = %existing_user.id,
                        "Upstream provider returned a username {username:?} matching an existing user who already has {count} link(s) to this provider, which isn't allowed by the conflict resolution"
                    );
                    return Err(UpstreamLinkWorkflowError::ConflictSetBlocked { handle: username });
                }

                repo.upstream_oauth_link()
                    .associate_to_user(link, &existing_user)
                    .await?;
            }
        }

        // Conflict resolved by linking. The caller should log this user in.
        return Ok(HandlePreCheckResult::ConflictResolved {
            user: Box::new(existing_user),
            provider_id: provider.id,
        });
    }

    // Check PrincipalServer availability
    let is_available = principal_server
        .is_handle_available(&username)
        .await
        .map_err(UpstreamLinkWorkflowError::principal_server)?;

    if !is_available {
        if !forced_or_required {
            tracing::warn!(
                upstream_oauth_provider.id = %provider.id,
                upstream_oauth_link.id = %link.id,
                "Upstream provider returned a username {username:?} which isn't available on the principal_server. As the username is just a suggestion, it was ignored."
            );
            return Ok(HandlePreCheckResult::Available(None));
        }

        return Err(UpstreamLinkWorkflowError::HandleUnavailable { handle: username });
    }

    Ok(HandlePreCheckResult::Available(Some(username)))
}

struct RegistrationSuggestions {
    suggested_handle: Option<String>,
    suggested_display_name: Option<String>,
    suggested_email: Option<String>,
    suggested_avatar_url: Option<String>,
}

struct SelectedRegistrationAttributes {
    handle: String,
    display_name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

fn resolve_registration_suggestions(
    provider: &UpstreamOAuthProvider,
    upstream_session: &UpstreamOAuthAuthorizationSession,
) -> Result<RegistrationSuggestions, UpstreamLinkWorkflowError> {
    let env = environment();
    let context = build_attribute_context(upstream_session)?;

    let suggested_display_name = if provider.claims_imports.displayname.ignore() {
        None
    } else {
        render_imported_attribute(
            &env,
            provider.claims_imports.displayname.template.as_deref(),
            DEFAULT_DISPLAYNAME_TEMPLATE,
            &context,
            provider.claims_imports.displayname.is_required(),
        )?
    };

    let suggested_email = if provider.claims_imports.email.ignore() {
        None
    } else {
        render_imported_attribute(
            &env,
            provider.claims_imports.email.template.as_deref(),
            DEFAULT_EMAIL_TEMPLATE,
            &context,
            provider.claims_imports.email.is_required(),
        )?
    };

    let suggested_handle = if provider.claims_imports.handle.ignore() {
        None
    } else {
        render_imported_attribute(
            &env,
            provider.claims_imports.handle.template.as_deref(),
            DEFAULT_HANDLE_TEMPLATE,
            &context,
            provider.claims_imports.handle.is_required(),
        )?
    };

    let suggested_avatar_url = if provider.claims_imports.avatar.ignore() {
        None
    } else {
        render_imported_attribute(
            &env,
            provider.claims_imports.avatar.template.as_deref(),
            DEFAULT_AVATAR_TEMPLATE,
            &context,
            provider.claims_imports.avatar.is_required(),
        )?
    };

    Ok(RegistrationSuggestions {
        suggested_handle,
        suggested_display_name,
        suggested_email,
        suggested_avatar_url,
    })
}

fn resolve_registration_attributes(
    provider: &UpstreamOAuthProvider,
    upstream_session: &UpstreamOAuthAuthorizationSession,
    action: &UpstreamLinkRegistrationAction,
) -> Result<SelectedRegistrationAttributes, UpstreamLinkWorkflowError> {
    let env = environment();
    let context = build_attribute_context(upstream_session)?;

    let display_name = if provider
        .claims_imports
        .displayname
        .should_import(action.import_display_name)
    {
        render_imported_attribute(
            &env,
            provider.claims_imports.displayname.template.as_deref(),
            DEFAULT_DISPLAYNAME_TEMPLATE,
            &context,
            provider.claims_imports.displayname.is_required(),
        )?
    } else {
        None
    };

    let email = if provider
        .claims_imports
        .email
        .should_import(action.import_email)
    {
        render_imported_attribute(
            &env,
            provider.claims_imports.email.template.as_deref(),
            DEFAULT_EMAIL_TEMPLATE,
            &context,
            provider.claims_imports.email.is_required(),
        )?
    } else {
        None
    };

    let username = if provider.claims_imports.handle.is_forced_or_required() {
        render_imported_attribute(
            &env,
            provider.claims_imports.handle.template.as_deref(),
            DEFAULT_HANDLE_TEMPLATE,
            &context,
            true,
        )?
    } else {
        action.handle.clone()
    }
    .unwrap_or_default();

    // Avatar URL is always imported when configured (not behind a user toggle).
    let avatar_url = if provider.claims_imports.avatar.ignore() {
        None
    } else {
        render_imported_attribute(
            &env,
            provider.claims_imports.avatar.template.as_deref(),
            DEFAULT_AVATAR_TEMPLATE,
            &context,
            provider.claims_imports.avatar.is_required(),
        )?
    };

    Ok(SelectedRegistrationAttributes {
        handle: username,
        display_name,
        email,
        avatar_url,
    })
}

async fn validate_registration_action(
    repo: &mut BoxRepository,
    principal_server: &dyn ConnectorAdmin,
    policy: &mut PolicyInstance,
    site_config: &SiteConfig,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
    username: &str,
    email: Option<&str>,
    accept_terms: bool,
) -> Result<UpstreamLinkFieldErrors, UpstreamLinkWorkflowError> {
    let mut field_errors = UpstreamLinkFieldErrors::default();

    if username.is_empty() {
        field_errors.handle = Some("required".to_owned());
    } else {
        let already_exists = repo.user().exists(username).await?
            || !principal_server
                .is_handle_available(username)
                .await
                .map_err(UpstreamLinkWorkflowError::principal_server)?;
        if already_exists {
            field_errors.handle = Some("exists".to_owned());
        }
    }

    if site_config.tos_uri.is_some() && !accept_terms {
        field_errors.accept_terms = Some("required".to_owned());
    }

    let eval_result = policy
        .evaluate_register(RegisterInput {
            registration_method: RegistrationMethod::UpstreamOAuth,
            handle: username,
            email,
            requester: PolicyRequester {
                ip_address,
                user_agent,
                ..Default::default()
            },
        })
        .await
        .map_err(UpstreamLinkWorkflowError::internal)?;

    for violation in &eval_result.violations {
        let code = if violation.msg.is_empty() {
            "policy_violation".to_owned()
        } else {
            violation.msg.clone()
        };

        match violation.field.as_deref() {
            Some("handle") => {
                field_errors.handle = Some(code);
            }
            _ => {
                field_errors.form = Some(code);
            }
        }
    }

    Ok(field_errors)
}

fn build_attribute_context(
    upstream_session: &UpstreamOAuthAuthorizationSession,
) -> Result<minijinja::Value, UpstreamLinkWorkflowError> {
    let id_token = upstream_session
        .id_token()
        .map(Jwt::try_from)
        .transpose()
        .map_err(UpstreamLinkWorkflowError::internal)?;

    let mut context = AttributeMappingContext::new();
    if let Some(id_token) = id_token {
        let (_, payload) = id_token.into_parts();
        context = context.with_id_token_claims(payload);
    }
    if let Some(extra_callback_parameters) = upstream_session.extra_callback_parameters() {
        context = context.with_extra_callback_parameters(extra_callback_parameters.clone());
    }
    if let Some(userinfo) = upstream_session.userinfo() {
        context = context.with_userinfo_claims(userinfo.clone());
    }

    Ok(context.build())
}

fn render_imported_attribute(
    environment: &Environment,
    template: Option<&str>,
    default_template: &str,
    context: &minijinja::Value,
    required: bool,
) -> Result<Option<String>, UpstreamLinkWorkflowError> {
    render_attribute_template(
        environment,
        template.unwrap_or(default_template),
        context,
        required,
    )
}

fn render_attribute_template(
    environment: &Environment,
    template: &str,
    context: &minijinja::Value,
    required: bool,
) -> Result<Option<String>, UpstreamLinkWorkflowError> {
    match environment.render_str(template, context) {
        Ok(value) if value.is_empty() => {
            if required {
                return Err(UpstreamLinkWorkflowError::RequiredAttributeEmpty {
                    template: template.to_owned(),
                });
            }
            Ok(None)
        }
        Ok(value) => Ok(Some(value)),
        Err(source) => {
            if required {
                return Err(UpstreamLinkWorkflowError::RequiredAttributeRender {
                    template: template.to_owned(),
                    source,
                });
            }
            tracing::warn!(
                error = &source as &dyn std::error::Error,
                %template,
                "Error while rendering template"
            );
            Ok(None)
        }
    }
}

async fn prepare_user_registration(
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    repo: &mut BoxRepository,
    upstream_session: UpstreamOAuthAuthorizationSession,
    username: String,
    displayname: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    ip_address: Option<IpAddr>,
    user_agent: Option<String>,
    post_auth_action: Option<PostAuthAction>,
) -> Result<UserRegistration, UpstreamLinkWorkflowError> {
    let mut registration = repo
        .user_registration()
        .add(
            rng,
            clock,
            username,
            ip_address,
            user_agent,
            post_auth_action,
        )
        .await?;

    if let Some(email) = email {
        let authentication = repo
            .user_email()
            .add_authentication_for_registration(rng, clock, email, &registration)
            .await?;
        let authentication = repo
            .user_email()
            .complete_authentication_with_upstream(clock, authentication, &upstream_session)
            .await?;

        registration = repo
            .user_registration()
            .set_email_authentication(registration, &authentication)
            .await?;
    }

    if let Some(name) = displayname {
        registration = repo
            .user_registration()
            .set_display_name(registration, name)
            .await?;
    }

    if let Some(url) = avatar_url {
        registration = repo
            .user_registration()
            .set_avatar_url(registration, url)
            .await?;
    }

    repo.user_registration()
        .set_upstream_oauth_authorization_session(registration, &upstream_session)
        .await
        .map_err(UpstreamLinkWorkflowError::from)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use coauth_data::{
        UpstreamOAuthAuthorizationSessionState, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderHandlePreference, UpstreamOAuthProviderImportAction,
        UpstreamOAuthProviderImportPreference, UpstreamOAuthProviderTokenAuthMethod,
    };
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_oauth_types::scope::{OPENID, Scope};
    use serde_json::json;

    use super::*;

    #[test]
    fn required_claim_import_fails_when_template_renders_empty() {
        let provider = provider_with_claims_imports(UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: UpstreamOAuthProviderImportAction::Require,
                template: None,
                on_conflict: UpstreamOAuthProviderOnConflict::default(),
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        });
        let session = completed_upstream_session(json!({
            "email": "john@example.com",
            "email_verified": true
        }));

        let error = match resolve_registration_suggestions(&provider, &session) {
            Ok(_) => panic!("required missing handle claim should fail"),
            Err(error) => error,
        };

        match error {
            UpstreamLinkWorkflowError::RequiredAttributeEmpty { template }
            | UpstreamLinkWorkflowError::RequiredAttributeRender { template, .. } => {
                assert_eq!(template, DEFAULT_HANDLE_TEMPLATE);
            }
            other => panic!("unexpected required-claim failure: {other}"),
        }
    }

    #[test]
    fn forced_claim_imports_override_user_registration_toggles() {
        let provider = provider_with_claims_imports(UpstreamOAuthProviderClaimsImports {
            handle: UpstreamOAuthProviderHandlePreference {
                action: UpstreamOAuthProviderImportAction::Force,
                template: None,
                on_conflict: UpstreamOAuthProviderOnConflict::default(),
            },
            displayname: UpstreamOAuthProviderImportPreference {
                action: UpstreamOAuthProviderImportAction::Force,
                template: None,
            },
            email: UpstreamOAuthProviderImportPreference {
                action: UpstreamOAuthProviderImportAction::Force,
                template: None,
            },
            ..UpstreamOAuthProviderClaimsImports::default()
        });
        let session = completed_upstream_session(json!({
            "preferred_username": "john",
            "name": "John Appleseed",
            "email": "john@example.com",
            "email_verified": true
        }));
        let action = UpstreamLinkRegistrationAction {
            handle: Some("manual-handle".to_owned()),
            import_email: false,
            import_display_name: false,
            accept_terms: true,
        };

        let attributes = resolve_registration_attributes(&provider, &session, &action).unwrap();

        assert_eq!(attributes.handle, "john");
        assert_eq!(attributes.display_name.as_deref(), Some("John Appleseed"));
        assert_eq!(attributes.email.as_deref(), Some("john@example.com"));
    }

    fn provider_with_claims_imports(
        claims_imports: UpstreamOAuthProviderClaimsImports,
    ) -> UpstreamOAuthProvider {
        UpstreamOAuthProvider {
            id: Ulid::new(),
            issuer: Some("https://example.com/".to_owned()),
            human_name: Some("Example Ltd.".to_owned()),
            brand_name: None,
            discovery_mode: coauth_data::UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: coauth_data::UpstreamOAuthProviderPkceMode::Auto,
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            scope: Scope::from_iter([OPENID]),
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            client_id: "client".to_owned(),
            encrypted_client_secret: None,
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            response_mode: None,
            created_at: Utc::now(),
            disabled_at: None,
            claims_imports,
            additional_authorization_parameters: Vec::new(),
            forward_login_hint: false,
            on_backchannel_logout: coauth_data::UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            source: coauth_data::UpstreamOAuthProviderSource::Config,
        }
    }

    fn completed_upstream_session(
        id_token_claims: serde_json::Value,
    ) -> UpstreamOAuthAuthorizationSession {
        let now = Utc::now();
        UpstreamOAuthAuthorizationSession {
            id: Ulid::new(),
            state: UpstreamOAuthAuthorizationSessionState::Completed {
                completed_at: now,
                link_id: Ulid::new(),
                id_token: None,
                id_token_claims: None,
                extra_callback_parameters: None,
                userinfo: Some(id_token_claims),
            },
            provider_id: Ulid::new(),
            state_str: "state".to_owned(),
            code_challenge_verifier: None,
            nonce: Some("nonce".to_owned()),
            created_at: now,
        }
    }
}
