use dioxus::prelude::*;

use crate::utils::format_last_active;

#[component]
pub fn LastActive(datetime: String) -> Element {
    let relative = format_last_active(&datetime);
    rsx! {
        span { title: "{datetime}", class: "text-sm", "{relative}" }
    }
}
