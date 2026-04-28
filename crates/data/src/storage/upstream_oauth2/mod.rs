//! Repositories to interact with entities related to the upstream OAuth 2.0
//! providers

mod link;
mod provider;
mod session;

pub use self::{
    link::{UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository},
    provider::{
        UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
    },
    session::{UpstreamOAuthSessionFilter, UpstreamOAuthSessionRepository},
};
