use dioxus::prelude::*;

#[component]
pub fn EmptyState(children: Element) -> Element {
    rsx! {
        div { class: "empty-state", {children} }
    }
}
