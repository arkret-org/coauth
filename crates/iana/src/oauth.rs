//! OAuth 2.0 IANA registry values.
//!
//! See <https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml>

use crate::macros::{closed_enum, open_enum};

open_enum! {
    /// OAuth Access Token Type.
    ///
    /// Source: <https://www.iana.org/assignments/oauth-parameters/token-types.csv>
    pub enum OAuthAccessTokenType {
        /// Bearer token
        Bearer => "Bearer",
        /// N_A
        Na => "N_A",
        /// Proof of Possession
        PoP => "PoP",
        /// Demonstrating Proof of Possession
        DPoP => "DPoP",
    }
}

closed_enum! {
    /// OAuth Authorization Endpoint Response Type.
    ///
    /// Source: <https://www.iana.org/assignments/oauth-parameters/endpoint.csv>
    pub enum OAuthAuthorizationEndpointResponseType {
        /// Authorization Code Grant
        Code => "code",
        /// Hybrid: code + id_token
        CodeIdToken => "code id_token",
        /// Hybrid: code + id_token + token
        CodeIdTokenToken => "code id_token token",
        /// Hybrid: code + token
        CodeToken => "code token",
        /// Implicit: id_token only
        IdToken => "id_token",
        /// Implicit: id_token + token
        IdTokenToken => "id_token token",
        /// None
        None => "none",
        /// Implicit: token only
        Token => "token",
    }
}

open_enum! {
    /// OAuth Token Type Hint (for introspection / revocation).
    ///
    /// Source: <https://www.iana.org/assignments/oauth-parameters/token-type-hint.csv>
    pub enum OAuthTokenTypeHint {
        /// An access token
        AccessToken => "access_token",
        /// A refresh token
        RefreshToken => "refresh_token",
        /// PCT (permission ticket)
        Pct => "pct",
    }
}

open_enum! {
    /// OAuth Client Authentication Method.
    ///
    /// Source: <https://www.iana.org/assignments/oauth-parameters/token-endpoint-auth-method.csv>
    pub enum OAuthClientAuthenticationMethod {
        /// No authentication
        None => "none",
        /// Client secret in POST body
        ClientSecretPost => "client_secret_post",
        /// Client secret via HTTP Basic
        ClientSecretBasic => "client_secret_basic",
        /// Client secret signed as JWT
        ClientSecretJwt => "client_secret_jwt",
        /// Private key signed JWT
        PrivateKeyJwt => "private_key_jwt",
        /// Mutual TLS client certificate
        TlsClientAuth => "tls_client_auth",
        /// Self-signed TLS client certificate
        SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
    }
}

open_enum! {
    /// PKCE Code Challenge Method.
    ///
    /// Source: <https://www.iana.org/assignments/oauth-parameters/pkce-code-challenge-method.csv>
    pub enum PkceCodeChallengeMethod {
        /// Plain text (not recommended)
        Plain => "plain",
        /// SHA-256 hash
        S256 => "S256",
    }
}
