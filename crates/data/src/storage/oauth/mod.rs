//! Repositories to interact with entities related to the OAuth protocol

mod access_token;
mod authorization_grant;
mod client;
mod device_code_grant;
mod refresh_token;
mod session;
mod session_grant;

pub use self::{
    access_token::OAuthAccessTokenRepository,
    authorization_grant::OAuthAuthorizationGrantRepository,
    client::OAuthClientRepository,
    device_code_grant::{OAuthDeviceCodeGrantParams, OAuthDeviceCodeGrantRepository},
    refresh_token::OAuthRefreshTokenRepository,
    session::{OAuthSessionFilter, OAuthSessionRepository},
    session_grant::{NewSessionGrant, SessionGrantFilter, SessionGrantRepository},
};
