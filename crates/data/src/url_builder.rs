//! Utility to build URLs from string paths.

use ulid::Ulid;
use url::Url;

/// URL builder that generates absolute and relative URLs from string paths.
///
/// This replaces the previous typed-route approach with simple `&str` paths,
/// while keeping all the URL-construction logic in one place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlBuilder {
    http_base: Url,
    prefix: String,
    assets_base: String,
    issuer: Url,
}

impl UrlBuilder {
    /// Create a new [`UrlBuilder`] from a base URL.
    ///
    /// # Panics
    ///
    /// Panics if the base URL contains a fragment, a query, credentials or
    /// isn't HTTP/HTTPS.
    #[must_use]
    pub fn new(base: Url, issuer: Option<Url>, assets_base: Option<String>) -> Self {
        assert!(
            base.scheme() == "http" || base.scheme() == "https",
            "base URL must be HTTP/HTTPS"
        );
        assert_eq!(base.query(), None, "base URL must not contain a query");
        assert_eq!(
            base.fragment(),
            None,
            "base URL must not contain a fragment"
        );
        assert_eq!(base.username(), "", "base URL must not contain credentials");
        assert_eq!(
            base.password(),
            None,
            "base URL must not contain credentials"
        );

        let issuer = issuer.unwrap_or_else(|| base.clone());
        let prefix = base.path().trim_end_matches('/').to_owned();
        let assets_base = assets_base.unwrap_or_else(|| format!("{prefix}/assets/"));
        Self {
            http_base: base,
            prefix,
            assets_base,
            issuer,
        }
    }

    /// Create an absolute URL for a path.
    #[must_use]
    pub fn absolute_url(&self, path: &str) -> Url {
        let path = path.trim_start_matches('/');
        self.http_base.join(path).unwrap()
    }

    /// Create a relative URL for a path, prefixed with the base URL prefix.
    #[must_use]
    pub fn relative_url(&self, path: &str) -> String {
        format!("{prefix}{path}", prefix = self.prefix)
    }

    /// The prefix added to all relative URLs.
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        if self.prefix.is_empty() {
            None
        } else {
            Some(&self.prefix)
        }
    }

    /// Site public hostname.
    ///
    /// # Panics
    ///
    /// Panics if the base URL does not have a host.
    #[must_use]
    pub fn public_hostname(&self) -> &str {
        self.http_base
            .host_str()
            .expect("base URL must have a host")
    }

    /// HTTP base URL.
    #[must_use]
    pub fn http_base(&self) -> Url {
        self.http_base.clone()
    }

    /// OIDC issuer URL.
    #[must_use]
    pub fn oidc_issuer(&self) -> Url {
        self.issuer.clone()
    }

    /// OIDC discovery document URL.
    #[must_use]
    pub fn oidc_discovery(&self) -> Url {
        self.absolute_url_for_issuer("/.well-known/openid-configuration")
    }

    /// OAuth 2.0 authorization endpoint.
    #[must_use]
    pub fn oauth_authorization_endpoint(&self) -> Url {
        self.absolute_url("/authorize")
    }

    /// OAuth 2.0 token endpoint.
    #[must_use]
    pub fn oauth_token_endpoint(&self) -> Url {
        self.absolute_url("/oauth2/token")
    }

    /// OAuth 2.0 introspection endpoint.
    #[must_use]
    pub fn oauth_introspection_endpoint(&self) -> Url {
        self.absolute_url("/oauth2/introspect")
    }

    /// OAuth 2.0 revocation endpoint.
    #[must_use]
    pub fn oauth_revocation_endpoint(&self) -> Url {
        self.absolute_url("/oauth2/revoke")
    }

    /// OAuth 2.0 client registration endpoint.
    #[must_use]
    pub fn oauth_registration_endpoint(&self) -> Url {
        self.absolute_url("/oauth2/registration")
    }

    /// OAuth 2.0 device authorization endpoint.
    #[must_use]
    pub fn oauth_device_authorization_endpoint(&self) -> Url {
        self.absolute_url("/oauth2/device")
    }

    /// OAuth 2.0 device code link.
    #[must_use]
    pub fn device_code_link(&self) -> Url {
        self.absolute_url("/link")
    }

    /// OAuth 2.0 device code link full URL.
    #[must_use]
    pub fn device_code_link_full(&self, code: String) -> Url {
        let mut url = self.absolute_url("/link");
        url.set_query(Some(&format!("code={code}")));
        url
    }

    /// OIDC userinfo endpoint.
    #[must_use]
    pub fn oidc_userinfo_endpoint(&self) -> Url {
        self.absolute_url("/oauth2/userinfo")
    }

    /// JWKS URI.
    #[must_use]
    pub fn jwks_uri(&self) -> Url {
        self.absolute_url("/oauth2/keys.json")
    }

    /// Static asset URL.
    #[must_use]
    pub fn static_asset(&self, path: String) -> Url {
        self.absolute_url(&format!("/assets/{path}"))
    }

    /// Static asset base path.
    #[must_use]
    pub fn assets_base(&self) -> &str {
        &self.assets_base
    }

    /// Upstream redirect URI.
    #[must_use]
    pub fn upstream_oauth_callback(&self, id: Ulid) -> Url {
        self.absolute_url(&format!("/upstream/callback/{id}"))
    }

    /// Upstream authorize URI.
    #[must_use]
    pub fn upstream_oauth_authorize(&self, id: Ulid) -> Url {
        self.absolute_url(&format!("/upstream/authorize/{id}"))
    }

    /// Account management URI.
    #[must_use]
    pub fn account_management_uri(&self) -> Url {
        self.absolute_url("/account/")
    }

    /// Account recovery link.
    #[must_use]
    pub fn account_recovery_link(&self, ticket: String) -> Url {
        let mut url = self.absolute_url("/account/password/recovery");
        url.set_query(Some(&format!("ticket={ticket}")));
        url
    }

    /// Create an absolute URL using the issuer base (for OIDC discovery).
    fn absolute_url_for_issuer(&self, path: &str) -> Url {
        let path = path.trim_start_matches('/');
        self.issuer.join(path).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "base URL must be HTTP/HTTPS")]
    fn test_invalid_base_url_scheme() {
        let _ = UrlBuilder::new(Url::parse("file:///tmp/").unwrap(), None, None);
    }

    #[test]
    #[should_panic(expected = "base URL must not contain a query")]
    fn test_invalid_base_url_query() {
        let _ = UrlBuilder::new(
            Url::parse("https://example.com/?foo=bar").unwrap(),
            None,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "base URL must not contain a fragment")]
    fn test_invalid_base_url_fragment() {
        let _ = UrlBuilder::new(Url::parse("https://example.com/#foo").unwrap(), None, None);
    }

    #[test]
    #[should_panic(expected = "base URL must not contain credentials")]
    fn test_invalid_base_url_credentials() {
        let _ = UrlBuilder::new(Url::parse("https://foo@example.com/").unwrap(), None, None);
    }

    #[test]
    fn test_url_prefix() {
        let builder = UrlBuilder::new(Url::parse("https://example.com/foo/").unwrap(), None, None);
        assert_eq!(builder.prefix, "/foo");

        let builder = UrlBuilder::new(Url::parse("https://example.com/").unwrap(), None, None);
        assert_eq!(builder.prefix, "");
    }

    #[test]
    fn test_absolute_uri_prefix() {
        let builder = UrlBuilder::new(Url::parse("https://example.com/foo/").unwrap(), None, None);

        let uri = builder.absolute_url("/authorize");
        assert_eq!(uri.as_str(), "https://example.com/foo/authorize");
    }

    #[test]
    fn test_absolute_urls() {
        let base = Url::parse("https://example.com/").unwrap();
        let builder = UrlBuilder::new(base, None, None);
        assert_eq!(builder.absolute_url("/").as_str(), "https://example.com/");
        assert_eq!(
            builder
                .absolute_url("/.well-known/openid-configuration")
                .as_str(),
            "https://example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn test_relative_urls() {
        let builder = UrlBuilder::new(Url::parse("https://example.com/").unwrap(), None, None);
        assert_eq!(builder.relative_url("/login"), "/login");
        assert_eq!(builder.relative_url("/account/"), "/account/");

        let builder = UrlBuilder::new(
            Url::parse("https://example.com/prefix/").unwrap(),
            None,
            None,
        );
        assert_eq!(builder.relative_url("/login"), "/prefix/login");
    }
}
