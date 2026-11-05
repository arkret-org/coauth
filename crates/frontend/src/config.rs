/// Application configuration, loaded from the server-rendered JSON config.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub api_endpoint: String,
    pub base_path: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "/_coauth".to_owned(),
            base_path: String::new(),
        }
    }
}

/// Get the app configuration.
/// In WASM, this reads the inert JSON config block. Otherwise uses defaults.
pub fn get_config() -> AppConfig {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(val) = read_config_value() {
            let api_endpoint = js_sys::Reflect::get(&val, &"api_endpoint".into())
                .ok()
                .and_then(|v| v.as_string())
                .or_else(|| {
                    js_sys::Reflect::get(&val, &"apiEndpoint".into())
                        .ok()
                        .and_then(|v| v.as_string())
                })
                .unwrap_or_else(|| "/_coauth".to_owned());

            let base_path = js_sys::Reflect::get(&val, &"base_path".into())
                .ok()
                .and_then(|value| value.as_string())
                .unwrap_or_else(|| {
                    // Older servers already publish an account root. Keep their
                    // prefixed shells usable while frontend/server roll out.
                    js_sys::Reflect::get(&val, &"root".into())
                        .ok()
                        .and_then(|value| value.as_string())
                        .and_then(|root| {
                            root.trim_end_matches('/')
                                .strip_suffix("/account")
                                .map(str::to_owned)
                        })
                        .unwrap_or_default()
                });

            return AppConfig {
                api_endpoint,
                base_path,
            };
        }
    }

    AppConfig::default()
}

impl AppConfig {
    /// Translate a browser pathname into the deployment-independent SPA route.
    pub fn route_path<'a>(&self, pathname: &'a str) -> &'a str {
        let prefix = self.base_path.trim_end_matches('/');
        if !prefix.is_empty() {
            if pathname == prefix {
                return "/";
            }
            if let Some(path) = pathname.strip_prefix(prefix)
                && path.starts_with('/')
            {
                return path;
            }
        }
        pathname
    }

    /// Mount application-owned root-relative links exactly once. Server-authored
    /// redirects must instead be followed verbatim (including OAuth callbacks).
    pub fn app_url(&self, target: &str) -> String {
        let prefix = self.base_path.trim_end_matches('/');
        let path = target.split(['?', '#']).next().unwrap_or(target);
        if prefix.is_empty()
            || !target.starts_with('/')
            || target.starts_with("//")
            || path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            target.to_owned()
        } else {
            format!("{prefix}{target}")
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn read_config_value() -> Option<web_sys::wasm_bindgen::JsValue> {
    let window = web_sys::window()?;
    if let Some(document) = window.document()
        && let Some(element) = document.get_element_by_id("coauth-app-config")
        && let Some(text) = element.text_content()
        && let Ok(value) = js_sys::JSON::parse(&text)
        && !value.is_undefined()
        && !value.is_null()
    {
        return Some(value);
    }

    js_sys::Reflect::get(&window, &"APP_CONFIG".into())
        .ok()
        .filter(|value| !value.is_undefined() && !value.is_null())
}

/// Resolve the full API base URL based on the current location.
pub fn api_base_url() -> String {
    let config = get_config();

    #[cfg(target_arch = "wasm32")]
    {
        if let Some(win) = web_sys::window()
            && let Ok(location) = win.location().href()
            && let Ok(base) = web_sys::Url::new_with_base(&config.api_endpoint, &location)
        {
            return base.href();
        }
    }

    config.api_endpoint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounted_routes_respect_segment_boundaries() {
        let config = AppConfig {
            base_path: "/nested/auth/".into(),
            ..AppConfig::default()
        };
        assert_eq!(config.route_path("/nested/auth/login"), "/login");
        assert_eq!(config.route_path("/nested/auth"), "/");
        assert_eq!(config.route_path("/nested/auth/"), "/");
        assert_eq!(
            config.route_path("/nested/authentication/login"),
            "/nested/authentication/login"
        );
        assert_eq!(AppConfig::default().route_path("/login"), "/login");
    }

    #[test]
    fn internal_navigation_keeps_mount_and_continuation_without_double_prefixing() {
        let config = AppConfig {
            base_path: "/auth".into(),
            ..AppConfig::default()
        };
        for (target, expected) in [
            ("/", "/auth/"),
            (
                "/login?kind=continue_authorization_grant&id=grant",
                "/auth/login?kind=continue_authorization_grant&id=grant",
            ),
            ("/oauth/approval/grant", "/auth/oauth/approval/grant"),
            ("/auth/login?x=1#form", "/auth/login?x=1#form"),
            ("/auth?x=1", "/auth?x=1"),
            (
                "https://client.example/callback",
                "https://client.example/callback",
            ),
            ("//client.example/callback", "//client.example/callback"),
            ("#form", "#form"),
        ] {
            assert_eq!(config.app_url(target), expected);
        }
        assert_eq!(AppConfig::default().app_url("/login"), "/login");
    }
}
