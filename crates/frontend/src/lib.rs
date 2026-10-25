#![allow(clippy::disallowed_methods)]
#![allow(dead_code)]
mod api;
mod config;
mod pages;
mod passkey;
mod post_auth_continuation;
mod translations;
mod ui;
mod utils;

#[cfg(target_arch = "wasm32")]
thread_local! { static APP: std::cell::RefCell<Option<glory::web::WebApp>> = const {std::cell::RefCell::new(None)}; }

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() -> Result<(), wasm_bindgen::JsValue> {
    post_auth_continuation::capture_entry_request();
    translations::apply_locale(translations::initial_locale());
    pages::init_theme();
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or("Missing document")?;
    let root = document
        .get_element_by_id("app")
        .or_else(|| document.get_element_by_id("main"))
        .ok_or("Missing application root")?;
    let app = glory::web::launch_with(root, pages::app)
        .map_err(|error| wasm_bindgen::JsValue::from_str(&error.to_string()))?;
    for selector in [
        "link[href='/assets/sapid.css']",
        "link[href='/assets/main.css']",
    ] {
        if let Some(stylesheet) = document.query_selector(selector)?
            && let Some(parent) = stylesheet.parent_node()
        {
            parent.append_child(&stylesheet)?;
        }
    }
    APP.with(|slot| *slot.borrow_mut() = Some(app));
    Ok(())
}
