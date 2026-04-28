mod link;
mod provider;
mod session;

pub use self::{
    link::{UpstreamOAuthLink, UpstreamOAuthLinkPatch},
    provider::{
        ClaimsImports as UpstreamOAuthProviderClaimsImports,
        DiscoveryMode as UpstreamOAuthProviderDiscoveryMode,
        ImportAction as UpstreamOAuthProviderImportAction,
        ImportPreference as UpstreamOAuthProviderImportPreference,
        LocalpartPreference as UpstreamOAuthProviderLocalpartPreference,
        OnBackchannelLogout as UpstreamOAuthProviderOnBackchannelLogout,
        OnConflict as UpstreamOAuthProviderOnConflict, PkceMode as UpstreamOAuthProviderPkceMode,
        ProviderSource as UpstreamOAuthProviderSource,
        ResponseMode as UpstreamOAuthProviderResponseMode,
        SubjectPreference as UpstreamOAuthProviderSubjectPreference,
        TokenAuthMethod as UpstreamOAuthProviderTokenAuthMethod, UpstreamOAuthProvider,
    },
    session::{UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState},
};
pub use crate::{
    pg::upstream_oauth2::{
        PgUpstreamOAuthLinkRepository, PgUpstreamOAuthProviderRepository,
        PgUpstreamOAuthSessionRepository,
    },
    storage::upstream_oauth2::*,
};
