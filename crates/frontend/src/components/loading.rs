use dioxus::prelude::*;

#[component]
pub fn LoadingScreen() -> Element {
    rsx! {
        div { class: "loading-screen",
            LoadingSpinner {}
        }
    }
}

#[component]
pub fn LoadingSpinner(inline: Option<bool>) -> Element {
    let class = if inline.unwrap_or(false) {
        "loading-spinner inline"
    } else {
        "loading-spinner"
    };

    rsx! {
        div { class: "{class}" }
    }
}
