// Copyright 2026 Taidge Contributors
// SPDX-License-Identifier: Apache-2.0

//! RP-Initiated Logout request type.

use std::fmt;

use language_tags::LanguageTag;
use serde::{Deserialize, Serialize};
use serde_with::formats::SpaceSeparator;
use serde_with::{StringWithSeparator, serde_as, skip_serializing_none};
use url::Url;

/// The body of a request to the [RP-Initiated Logout Endpoint].
///
/// [RP-Initiated Logout Endpoint]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
#[skip_serializing_none]
#[serde_as]
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct RpInitiatedLogoutRequest {
    /// OAuth Client Identifier valid at the Authorization Server.
    ///
    /// The most common use case for this parameter is to specify the Client
    /// Identifier when `post_logout_redirect_uri` is used but `id_token_hint`
    /// is not. Another use is for symmetrically encrypted ID Tokens used as
    /// `id_token_hint` values that require the Client Identifier to be
    /// specified by other means, so that the ID Tokens can be decrypted by
    /// the OP.
    pub client_id: Option<String>,

    /// ID Token previously issued by the OP to the RP.
    ///
    /// Recommended, used as a hint about the End-User's current authenticated
    /// session with the Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the End-User that is logging out.
    ///
    /// The value and meaning of this parameter is left up to the OP's
    /// discretion. For instance, the value might contain an email address,
    /// phone number, username, or session identifier pertaining to the RP's
    /// session with the OP for the End-User.
    pub logout_hint: Option<String>,

    /// URI to which the RP is requesting that the End-User's User Agent be
    /// redirected after a logout has been performed.
    ///
    /// The value MUST have been previously registered with the OP, using the
    /// `post_logout_redirect_uris` registration parameter.
    pub post_logout_redirect_uri: Option<Url>,

    /// Opaque value used by the RP to maintain state between the logout request
    /// and the callback to the endpoint specified by the
    /// `post_logout_redirect_uri` parameter.
    pub state: Option<String>,

    /// End-User's preferred languages and scripts for the user interface,
    /// ordered by preference.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    #[serde(default)]
    pub ui_locales: Option<Vec<LanguageTag>>,
}

impl fmt::Debug for RpInitiatedLogoutRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpInitiatedLogoutRequest")
            .field("logout_hint", &self.logout_hint)
            .field("post_logout_redirect_uri", &self.post_logout_redirect_uri)
            .field("ui_locales", &self.ui_locales)
            .finish_non_exhaustive()
    }
}
