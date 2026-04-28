use dioxus::prelude::*;

#[component]
pub fn Dialog(trigger: Element, open: Signal<bool>, children: Element) -> Element {
    rsx! {
        // Trigger element
        div {
            onclick: move |_| open.set(true),
            {trigger}
        }

        // Overlay + content
        if open() {
            div {
                class: "dialog-overlay",
                onclick: move |_| open.set(false),
                div {
                    class: "dialog-content",
                    onclick: move |e| e.stop_propagation(),
                    {children}
                }
            }
        }
    }
}

#[component]
pub fn DialogTitle(children: Element) -> Element {
    rsx! {
        h3 { class: "dialog-title", {children} }
    }
}

#[component]
pub fn DialogClose(open: Signal<bool>, children: Element) -> Element {
    rsx! {
        div {
            onclick: move |_| open.set(false),
            {children}
        }
    }
}
