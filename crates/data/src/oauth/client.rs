use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_iana::oauth::OAuthClientAuthenticationMethod;
use coauth_jose::jwk::PublicJsonWebKeySet;
use oauth_types::oidc::ApplicationType;
use oauth_types::registration::{ClientMetadata, Localized};
use oauth_types::requests::GrantType;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;
use url::Url;

/// OIDC client metadata fields that may have a per-locale variant.
///
/// Mirrors the small allow-list enforced at the database level by the
/// `oauth_client_localized_metadata_field_check` constraint. Adding a new
/// field requires a migration update *and* extending this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalizableField {
    ClientName,
    LogoUri,
    ClientUri,
    PolicyUri,
    TosUri,
}

impl LocalizableField {
    /// String identifier used by the storage column and config sync.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientName => "client_name",
            Self::LogoUri => "logo_uri",
            Self::ClientUri => "client_uri",
            Self::PolicyUri => "policy_uri",
            Self::TosUri => "tos_uri",
        }
    }

    /// Parse the column value back into the typed enum. Returns `None` for
    /// unknown identifiers (which the database constraint should already
    /// reject).
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "client_name" => Some(Self::ClientName),
            "logo_uri" => Some(Self::LogoUri),
            "client_uri" => Some(Self::ClientUri),
            "policy_uri" => Some(Self::PolicyUri),
            "tos_uri" => Some(Self::TosUri),
            _ => None,
        }
    }
}

/// Localised counterparts of the five `Client` metadata strings, indexed by
/// BCP-47 locale tag (the `value` column from
/// `oauth_client_localized_metadata`).
///
/// `BTreeMap` is used so iteration order is deterministic — config sync,
/// JSON serialisation and tests all rely on a stable ordering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedClientMetadata {
    pub client_name: BTreeMap<String, String>,
    pub logo_uri: BTreeMap<String, Url>,
    pub client_uri: BTreeMap<String, Url>,
    pub policy_uri: BTreeMap<String, Url>,
    pub tos_uri: BTreeMap<String, Url>,
}

impl LocalizedClientMetadata {
    /// True if no locale has any localised metadata set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.client_name.is_empty()
            && self.logo_uri.is_empty()
            && self.client_uri.is_empty()
            && self.policy_uri.is_empty()
            && self.tos_uri.is_empty()
    }

    /// Set a localised text value for the given (`field`, `locale`).
    ///
    /// URL-typed fields parse `value` and silently drop bad URLs (the same
    /// behaviour the non-localised columns have for invalid URLs in the
    /// database).
    pub fn set(&mut self, field: LocalizableField, locale: String, value: String) {
        match field {
            LocalizableField::ClientName => {
                self.client_name.insert(locale, value);
            }
            LocalizableField::LogoUri => {
                if let Ok(url) = Url::parse(&value) {
                    self.logo_uri.insert(locale, url);
                }
            }
            LocalizableField::ClientUri => {
                if let Ok(url) = Url::parse(&value) {
                    self.client_uri.insert(locale, url);
                }
            }
            LocalizableField::PolicyUri => {
                if let Ok(url) = Url::parse(&value) {
                    self.policy_uri.insert(locale, url);
                }
            }
            LocalizableField::TosUri => {
                if let Ok(url) = Url::parse(&value) {
                    self.tos_uri.insert(locale, url);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    /// Client's JSON Web Key Set document, passed by value.
    Jwks(PublicJsonWebKeySet),

    /// URL for the Client's JSON Web Key Set document.
    JwksUri(Url),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Client {
    pub id: Ulid,

    /// Client identifier
    pub client_id: String,

    /// coauth extension: hash of the client metadata
    pub metadata_digest: Option<String>,

    pub encrypted_client_secret: Option<String>,

    pub application_type: Option<ApplicationType>,

    /// Array of Redirection URI values used by the Client
    pub redirect_uris: Vec<Url>,

    /// Array containing a list of the OAuth Grant Types that the Client is
    /// declaring that it will restrict itself to using.
    pub grant_types: Vec<GrantType>,

    /// Name of the Client to be presented to the End-User. Default
    /// (non-localised) value; per-locale overrides live in
    /// [`Client::localized_metadata`].
    pub client_name: Option<String>,

    /// URL that references a logo for the Client application
    pub logo_uri: Option<Url>,

    /// URL of the home page of the Client
    pub client_uri: Option<Url>,

    /// URL that the Relying Party Client provides to the End-User to read about
    /// the how the profile data will be used
    pub policy_uri: Option<Url>,

    /// URL that the Relying Party Client provides to the End-User to read about
    /// the Relying Party's terms of service
    pub tos_uri: Option<Url>,

    /// Per-locale variants of the five metadata fields above. Loaded from
    /// the `oauth_client_localized_metadata` table; an empty value means
    /// the client only registered the non-localised default.
    pub localized_metadata: LocalizedClientMetadata,

    pub jwks: Option<JwksOrJwksUri>,

    /// JWS alg algorithm REQUIRED for signing the ID Token issued to this
    /// Client
    pub id_token_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// JWS alg algorithm REQUIRED for signing `UserInfo` Responses.
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// Requested authentication method for the token endpoint
    pub token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,

    /// JWS alg algorithm that MUST be used for signing the JWT used to
    /// authenticate the Client at the Token Endpoint for the `private_key_jwt`
    /// and `client_secret_jwt` authentication methods
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// URI using the https scheme that a third party can use to initiate a
    /// login by the RP
    pub initiate_login_uri: Option<Url>,
}

#[derive(Debug, Error)]
pub enum InvalidRedirectUriError {
    #[error("redirect_uri is not allowed for this client")]
    NotAllowed,

    #[error("multiple redirect_uris registered for this client")]
    MultipleRegistered,

    #[error("client has no redirect_uri registered")]
    NoneRegistered,
}

impl Client {
    /// Determine which redirect URI to use for the given request.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    ///  - no URL was given but multiple redirect URIs are registered,
    ///  - no URL was registered, or
    ///  - the given URL is not registered
    pub fn resolve_redirect_uri<'a>(
        &'a self,
        redirect_uri: &'a Option<Url>,
    ) -> Result<&'a Url, InvalidRedirectUriError> {
        match (&self.redirect_uris[..], redirect_uri) {
            ([], _) => Err(InvalidRedirectUriError::NoneRegistered),
            ([one], None) => Ok(one),
            (_, None) => Err(InvalidRedirectUriError::MultipleRegistered),
            (uris, Some(uri)) if uri_matches_one_of(uri, uris) => Ok(uri),
            _ => Err(InvalidRedirectUriError::NotAllowed),
        }
    }

    /// Pick the best localised `client_name` for the given locale.
    ///
    /// Falls back to a less specific variant of the same language tag, then
    /// to the non-localised default. Locale matching is a simple
    /// case-insensitive equality on the tag prefix because the OIDC spec
    /// only requires byte-for-byte matching, not full BCP-47 fallback.
    #[must_use]
    pub fn localized_client_name(&self, locale: &str) -> Option<&str> {
        pick_localized_str(&self.localized_metadata.client_name, locale)
            .or(self.client_name.as_deref())
    }

    /// Pick the best localised `logo_uri` for the given locale.
    #[must_use]
    pub fn localized_logo_uri(&self, locale: &str) -> Option<&Url> {
        pick_localized_url(&self.localized_metadata.logo_uri, locale).or(self.logo_uri.as_ref())
    }

    /// Pick the best localised `client_uri` for the given locale.
    #[must_use]
    pub fn localized_client_uri(&self, locale: &str) -> Option<&Url> {
        pick_localized_url(&self.localized_metadata.client_uri, locale).or(self.client_uri.as_ref())
    }

    /// Pick the best localised `policy_uri` for the given locale.
    #[must_use]
    pub fn localized_policy_uri(&self, locale: &str) -> Option<&Url> {
        pick_localized_url(&self.localized_metadata.policy_uri, locale).or(self.policy_uri.as_ref())
    }

    /// Pick the best localised `tos_uri` for the given locale.
    #[must_use]
    pub fn localized_tos_uri(&self, locale: &str) -> Option<&Url> {
        pick_localized_url(&self.localized_metadata.tos_uri, locale).or(self.tos_uri.as_ref())
    }

    /// coauth extension: create a client metadata object for this client
    #[must_use]
    pub fn into_metadata(self) -> ClientMetadata {
        let (jwks, jwks_uri) = match self.jwks {
            Some(JwksOrJwksUri::Jwks(jwks)) => (Some(jwks), None),
            Some(JwksOrJwksUri::JwksUri(jwks_uri)) => (None, Some(jwks_uri)),
            _ => (None, None),
        };
        let LocalizedClientMetadata {
            client_name: localized_client_name,
            logo_uri: localized_logo_uri,
            client_uri: localized_client_uri,
            policy_uri: localized_policy_uri,
            tos_uri: localized_tos_uri,
        } = self.localized_metadata;
        ClientMetadata {
            redirect_uris: Some(self.redirect_uris.clone()),
            response_types: None,
            grant_types: Some(self.grant_types.clone()),
            application_type: self.application_type.clone(),
            client_name: build_localized(self.client_name, localized_client_name),
            logo_uri: build_localized(self.logo_uri, localized_logo_uri),
            client_uri: build_localized(self.client_uri, localized_client_uri),
            policy_uri: build_localized(self.policy_uri, localized_policy_uri),
            tos_uri: build_localized(self.tos_uri, localized_tos_uri),
            jwks_uri,
            jwks,
            id_token_signed_response_alg: self.id_token_signed_response_alg,
            userinfo_signed_response_alg: self.userinfo_signed_response_alg,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            token_endpoint_auth_signing_alg: self.token_endpoint_auth_signing_alg,
            initiate_login_uri: self.initiate_login_uri,
            contacts: None,
            software_id: None,
            software_version: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            request_uris: None,
            require_signed_request_object: None,
            require_pushed_authorization_requests: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            post_logout_redirect_uris: None,
        }
    }

    #[doc(hidden)]
    pub fn samples(now: DateTime<Utc>, rng: &mut impl RngCore) -> Vec<Client> {
        vec![
            // A client with all the URIs set
            Self {
                id: crate::new_id(now, rng),
                client_id: "client1".to_owned(),
                metadata_digest: None,
                encrypted_client_secret: None,
                application_type: Some(ApplicationType::Web),
                redirect_uris: vec![
                    Url::parse("https://client1.example.com/redirect").unwrap(),
                    Url::parse("https://client1.example.com/redirect2").unwrap(),
                ],
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                client_name: Some("Client 1".to_owned()),
                client_uri: Some(Url::parse("https://client1.example.com").unwrap()),
                logo_uri: Some(Url::parse("https://client1.example.com/logo.png").unwrap()),
                tos_uri: Some(Url::parse("https://client1.example.com/tos").unwrap()),
                policy_uri: Some(Url::parse("https://client1.example.com/policy").unwrap()),
                initiate_login_uri: Some(
                    Url::parse("https://client1.example.com/initiate-login").unwrap(),
                ),
                token_endpoint_auth_method: Some(OAuthClientAuthenticationMethod::None),
                token_endpoint_auth_signing_alg: None,
                id_token_signed_response_alg: None,
                userinfo_signed_response_alg: None,
                localized_metadata: LocalizedClientMetadata::default(),
                jwks: None,
            },
            // Another client without any URIs set
            Self {
                id: crate::new_id(now, rng),
                client_id: "client2".to_owned(),
                metadata_digest: None,
                encrypted_client_secret: None,
                application_type: Some(ApplicationType::Native),
                redirect_uris: vec![Url::parse("https://client2.example.com/redirect").unwrap()],
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                client_name: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                initiate_login_uri: None,
                token_endpoint_auth_method: None,
                token_endpoint_auth_signing_alg: None,
                id_token_signed_response_alg: None,
                userinfo_signed_response_alg: None,
                localized_metadata: LocalizedClientMetadata::default(),
                jwks: None,
            },
        ]
    }
}

/// Build an OIDC `Localized<T>` value from the non-localised default and the
/// per-locale variants. Returns `None` only when the default is missing
/// *and* no locales are populated, matching the historical behaviour of
/// `into_metadata` for unlocalised clients.
fn build_localized<T: Clone>(
    default: Option<T>,
    by_locale: BTreeMap<String, T>,
) -> Option<Localized<T>> {
    use language_tags::LanguageTag;

    let pairs: Vec<(LanguageTag, T)> = by_locale
        .into_iter()
        .filter_map(|(tag, value)| LanguageTag::parse(&tag).ok().map(|l| (l, value)))
        .collect();
    match (default, pairs.is_empty()) {
        (Some(value), _) => Some(Localized::new(value, pairs)),
        // The OIDC `Localized<T>` type requires a non-localised default, so
        // when the client only registered locale-specific variants we
        // promote the first one (in BTreeMap order — deterministic) to the
        // default slot.
        (None, false) => {
            let mut iter = pairs.into_iter();
            let (_, first) = iter.next().expect("non-empty by check");
            Some(Localized::new(first, iter.collect::<Vec<_>>()))
        }
        (None, true) => None,
    }
}

/// Pick the best matching localised string for `locale` from `map`. Tries
/// the exact tag first, then a language-prefix match (`zh-Hans` → `zh`).
fn pick_localized_str<'a>(map: &'a BTreeMap<String, String>, locale: &str) -> Option<&'a str> {
    if let Some(value) = map.get(locale) {
        return Some(value.as_str());
    }
    let prefix = locale.split('-').next()?;
    map.iter()
        .find(|(tag, _)| tag.split('-').next() == Some(prefix))
        .map(|(_, v)| v.as_str())
}

/// Pick the best matching localised URL for `locale` from `map`.
fn pick_localized_url<'a>(map: &'a BTreeMap<String, Url>, locale: &str) -> Option<&'a Url> {
    if let Some(value) = map.get(locale) {
        return Some(value);
    }
    let prefix = locale.split('-').next()?;
    map.iter()
        .find(|(tag, _)| tag.split('-').next() == Some(prefix))
        .map(|(_, v)| v)
}

/// The hosts that match the loopback interface.
const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

/// Whether the given URI matches one of the registered URIs.
///
/// If the URI host is one if `localhost`, `127.0.0.1` or `[::1]`, any port is
/// accepted.
fn uri_matches_one_of(uri: &Url, registered_uris: &[Url]) -> bool {
    if LOCAL_HOSTS.contains(&uri.host_str().unwrap_or_default()) {
        let mut uri = uri.clone();
        // Try matching without the port first
        if uri.set_port(None).is_ok() && registered_uris.contains(&uri) {
            return true;
        }
    }

    registered_uris.contains(uri)
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    #[test]
    fn test_uri_matches_one_of() {
        let registered_uris = &[
            Url::parse("http://127.0.0.1").unwrap(),
            Url::parse("https://example.org").unwrap(),
        ];

        // Non-loopback interface URIs.
        assert!(uri_matches_one_of(
            &Url::parse("https://example.org").unwrap(),
            registered_uris
        ));
        assert!(!uri_matches_one_of(
            &Url::parse("https://example.org:8080").unwrap(),
            registered_uris
        ));

        // Loopback interface URIS.
        assert!(uri_matches_one_of(
            &Url::parse("http://127.0.0.1").unwrap(),
            registered_uris
        ));
        assert!(uri_matches_one_of(
            &Url::parse("http://127.0.0.1:8080").unwrap(),
            registered_uris
        ));
        assert!(!uri_matches_one_of(
            &Url::parse("http://localhost").unwrap(),
            registered_uris
        ));
    }
}
