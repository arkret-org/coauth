/// Application configuration, loaded from the server-rendered JSON config.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub api_endpoint: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "/_coauth".to_owned(),
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
                .unwrap_or_else(|| "/_coauth".to_string());

            return AppConfig { api_endpoint };
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
