//! A module containing the PostgreSQL implementations of the OAuth-related
//! repositories

mod access_token;
mod authorization_grant;
mod client;
mod device_code_grant;
mod refresh_token;
mod session;
mod session_grant;

pub use self::access_token::PgOAuthAccessTokenRepository;
pub use self::authorization_grant::PgOAuthAuthorizationGrantRepository;
pub use self::client::PgOAuthClientRepository;
pub use self::device_code_grant::PgOAuthDeviceCodeGrantRepository;
pub use self::refresh_token::PgOAuthRefreshTokenRepository;
pub use self::session::PgOAuthSessionRepository;
pub use self::session_grant::PgOAuthSessionGrantRepository;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
