mod api;
mod components;
mod config;
mod pages;
mod utils;

use dioxus::prelude::*;

use crate::{
    components::theme::{ThemeToggle, init_theme},
    config::get_config,
    pages::{Route, error_pages::ErrorPage},
};

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    crate::pages::login::preserve_login_query();
    init_theme();
    dioxus::launch(app);
}

fn app() -> Element {
    let cfg = get_config();

    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        ThemeToggle {}

        if let Some(error) = cfg.error {
            // The backend injected an error state — show the error page
            // instead of the normal SPA routes.
            ErrorPage { error }
        } else {
            Router::<Route> {}
        }
    }
}
