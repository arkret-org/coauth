//! Repositories to interact with entities related to the upstream OAuth
//! providers

mod link;
mod provider;
mod session;

pub use self::link::{UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository};
pub use self::provider::{
    UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository,
};
pub use self::session::{UpstreamOAuthSessionFilter, UpstreamOAuthSessionRepository};
