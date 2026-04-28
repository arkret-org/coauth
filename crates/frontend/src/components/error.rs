use dioxus::prelude::*;

use super::layout::Layout;

#[component]
pub fn GenericError(message: Option<String>) -> Element {
    let msg = message.unwrap_or_else(|| "An unexpected error occurred.".to_string());

    rsx! {
        Layout {
            div { class: "flex flex-col gap-6 items-center",
                div { class: "page-heading-icon", "!" }
                p { class: "text-md text-secondary", "{msg}" }
            }
        }
    }
}

#[component]
pub fn NotFound() -> Element {
    rsx! {
        div { class: "flex flex-col gap-6 items-center",
            div { class: "page-heading-icon", "?" }
            p { class: "heading-sm", "Page not found" }
            p { class: "text-md text-secondary",
                "The page you're looking for doesn't exist."
            }
        }
    }
}
