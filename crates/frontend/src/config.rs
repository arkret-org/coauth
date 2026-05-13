/// A server-injected error state, rendered instead of the normal SPA when
/// the backend detects an account-level problem during session loading.
#[derive(Debug, Clone, PartialEq)]
pub struct AppError {
    /// One of: `account_deactivated`, `account_locked`, `session_ended`,
    /// `generic`.
    pub kind: String,
    /// The local username (without `@` prefix or `:server` suffix), if known.
    pub username: Option<String>,
    /// Human-readable error description, if any.
    pub description: Option<String>,
}

/// Application configuration, loaded from the server-rendered JSON config.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AppConfig {
    pub root: String,
    pub api_endpoint: String,
    /// If set, the backend wants the frontend to display an error page
    /// instead of the normal router.
    pub error: Option<AppError>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root: "/".to_string(),
            api_endpoint: "/api/v1".to_string(),
            error: None,
        }
    }
}

/// Get the app configuration.
/// In WASM, this reads the inert JSON config block. Otherwise uses defaults.
pub fn get_config() -> AppConfig {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(val) = read_config_value() {
            let root = js_sys::Reflect::get(&val, &"root".into())
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "/".to_string());
            let api_endpoint = js_sys::Reflect::get(&val, &"api_endpoint".into())
                .ok()
                .and_then(|v| v.as_string())
                .or_else(|| {
                    js_sys::Reflect::get(&val, &"apiEndpoint".into())
                        .ok()
                        .and_then(|v| v.as_string())
                })
                .unwrap_or_else(|| "/api/v1".to_string());

            let error = read_error_from_js(&val);

            return AppConfig {
                root,
                api_endpoint,
                error,
            };
        }
    }

    AppConfig::default()
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

/// Try to read the optional `error` object from the JS config.
#[cfg(target_arch = "wasm32")]
fn read_error_from_js(config: &web_sys::wasm_bindgen::JsValue) -> Option<AppError> {
    let err = js_sys::Reflect::get(config, &"error".into()).ok()?;
    if err.is_undefined() || err.is_null() {
        return None;
    }

    let kind = js_sys::Reflect::get(&err, &"kind".into())
        .ok()
        .and_then(|v| v.as_string())?;

    let username = js_sys::Reflect::get(&err, &"username".into())
        .ok()
        .and_then(|v| v.as_string());

    let description = js_sys::Reflect::get(&err, &"description".into())
        .ok()
        .and_then(|v| v.as_string());

    Some(AppError {
        kind,
        username,
        description,
    })
}

/// Resolve the full API base URL based on the current location.
pub fn api_base_url() -> String {
    let config = get_config();

    #[cfg(target_arch = "wasm32")]
    {
        if let Some(win) = web_sys::window() {
            if let Ok(location) = win.location().href() {
                if let Ok(base) = web_sys::Url::new_with_base(&config.api_endpoint, &location) {
                    return base.href();
                }
            }
        }
    }

    config.api_endpoint
}
