use dioxus::prelude::*;

use crate::pages::Route;

#[component]
pub fn Filter(to: Route, enabled: Option<bool>, label: String) -> Element {
    let is_active = enabled.unwrap_or(false);
    let class = if is_active {
        "filter-toggle active"
    } else {
        "filter-toggle"
    };

    rsx! {
        Link { class: "{class}", to: to, "{label}" }
    }
}
