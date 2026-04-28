use dioxus::prelude::*;

#[component]
pub fn ExternalLink(href: String, children: Element) -> Element {
    rsx! {
        a { href: "{href}", target: "_blank", rel: "noopener noreferrer",
            {children}
            span { class: "text-xs", " \u{2197}" }
        }
    }
}
