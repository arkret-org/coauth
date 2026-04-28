use dioxus::prelude::*;

#[component]
pub fn CollapsibleSection(title: String, default_open: Option<bool>, children: Element) -> Element {
    let mut is_open = use_signal(|| default_open.unwrap_or(false));
    let icon_class = if is_open() {
        "collapsible-icon open"
    } else {
        "collapsible-icon"
    };
    let content_class = if is_open() {
        "collapsible-content"
    } else {
        "collapsible-content hidden"
    };

    rsx! {
        div { class: "collapsible-section",
            button {
                class: "collapsible-trigger",
                r#type: "button",
                onclick: move |_| is_open.set(!is_open()),
                span { "{title}" }
                span { class: "{icon_class}", "▾" }
            }
            div { class: "{content_class}",
                {children}
            }
        }
    }
}
