use dioxus::prelude::*;

use crate::api::types::SiteConfig;
use crate::components::loading::LoadingScreen;
use crate::pages::Route;

#[component]
pub fn Plan() -> Element {
    let data =
        use_resource(|| async { crate::api::api_get::<SiteConfig>("/self/site-config").await });
    let nav = navigator();
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            // Defence in depth: the backend already rejects non-https
            // `plan_management_iframe_uri` at config load, but re-check the
            // scheme here before injecting it into `iframe src` so a
            // `javascript:`/`data:` value can never be embedded even if it
            // reached the client through some other path.
            match result
                .plan_management_iframe_uri
                .as_deref()
                .filter(|uri| is_safe_iframe_src(uri))
            {
                Some(uri) => {
                    let uri = uri.to_owned();
                    rsx! {
                        iframe {
                            class: "plan-iframe",
                            title: "Plan management",
                            src: "{uri}",
                            scrolling: "no",
                        }
                    }
                }
                None => {
                    nav.push(Route::AccountOverview {});
                    rsx! {}
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}

/// Only allow an absolute `https://` URL to be injected into the iframe
/// `src`. Rejects `javascript:`, `data:` and any non-https scheme.
fn is_safe_iframe_src(uri: &str) -> bool {
    uri.len() > "https://".len()
        && uri
            .get(.."https://".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}
