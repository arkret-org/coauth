// The workspace-wide clippy policy disallows `reqwest::Client::new`,
// `RequestBuilder::send`, and `chrono::Utc::now`, but those alternatives
// (e.g. `coauth_backend::reqwest_client`, a server-side clock abstraction)
// don't exist for the WASM frontend.
#![allow(clippy::disallowed_methods)]

mod api;
mod components;
mod config;
mod pages;
mod translations;
mod utils;

use dioxus::prelude::*;

use crate::components::language::LanguageToggle;
use crate::components::theme::{ThemeToggle, init_theme};
use crate::config::get_config;
use crate::pages::Route;
use crate::pages::error_pages::ErrorPage;

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    crate::pages::login::preserve_login_query();
    init_theme();
    dioxus::launch(app);
}

fn app() -> Element {
    let cfg = get_config();
    let initial_locale = crate::translations::initial_locale();
    let locale =
        use_context_provider::<crate::translations::LocaleSignal>(|| Signal::new(initial_locale));
    use_effect(move || crate::translations::apply_locale(*locale.read()));

    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        div { class: "display-preferences",
            LanguageToggle {}
            ThemeToggle {}
        }

        if let Some(error) = cfg.error {
            // The backend injected an error state — show the error page
            // instead of the normal SPA routes.
            ErrorPage { error }
        } else {
            Router::<Route> {}
        }
    }
}
