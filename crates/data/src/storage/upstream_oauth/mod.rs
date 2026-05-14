//! Repositories to interact with entities related to the upstream OAuth
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
