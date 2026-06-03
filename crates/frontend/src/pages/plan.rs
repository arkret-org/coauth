use dioxus::prelude::*;

use crate::{api::types::SiteConfig, components::loading::LoadingScreen, pages::Route};

#[component]
pub fn Plan() -> Element {
    let data =
        use_resource(|| async { crate::api::api_get::<SiteConfig>("/self/site-config").await });
    let nav = navigator();
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            if let Some(uri) = &result.plan_management_iframe_uri {
                let uri = uri.clone();
                rsx! {
                    iframe {
                        class: "plan-iframe",
                        title: "Plan management",
                        src: "{uri}",
                        scrolling: "no",
                    }
                }
            } else {
                nav.push(Route::AccountOverview {});
                rsx! {}
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
