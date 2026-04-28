use dioxus::prelude::*;

#[component]
pub fn PageHeading(icon: Option<String>, title: String, subtitle: Option<String>) -> Element {
    rsx! {
        div { class: "page-heading",
            if let Some(ref icon_text) = icon {
                div { class: "page-heading-icon", "{icon_text}" }
            }
            h2 { class: "heading-sm", "{title}" }
            if let Some(ref sub) = subtitle {
                p { class: "page-heading-subtitle", "{sub}" }
            }
        }
    }
}
