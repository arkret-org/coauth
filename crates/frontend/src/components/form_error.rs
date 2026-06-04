use dioxus::prelude::*;

/// Standard critical-alert block used by forms to surface an error message.
///
/// Replaces the repeated `div.alert.alert-critical > p { ... }` markup. An
/// optional `title` renders an `.alert-title` heading above the message.
#[component]
pub fn FormError(message: String, #[props(default)] title: Option<String>) -> Element {
    rsx! {
        div { class: "alert alert-critical",
            if let Some(title) = title {
                p { class: "alert-title", "{title}" }
            }
            p { "{message}" }
        }
    }
}
