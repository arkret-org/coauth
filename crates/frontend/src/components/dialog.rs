use dioxus::prelude::*;

/// Modal dialog with a translucent overlay.
///
/// Supports two usage styles:
/// - **Trigger mode**: pass a `trigger` element; clicking it opens the dialog.
/// - **Controlled mode**: omit `trigger` and render the dialog conditionally (or just let it react
///   to the `open` signal) while toggling `open` from the parent.
///
/// An optional `title` renders a standard `.dialog-title` header so call sites
/// don't have to repeat the markup. Remaining content (body + action buttons)
/// goes in `children`.
#[component]
pub fn Dialog(
    open: Signal<bool>,
    #[props(default)] trigger: Option<Element>,
    #[props(default)] title: Option<String>,
    children: Element,
) -> Element {
    rsx! {
        // Optional trigger element
        if let Some(trigger) = trigger {
            div {
                onclick: move |_| open.set(true),
                {trigger}
            }
        }

        // Overlay + content
        if open() {
            div {
                class: "dialog-overlay",
                onclick: move |_| open.set(false),
                div {
                    class: "dialog-content",
                    onclick: move |e| e.stop_propagation(),
                    if let Some(title) = title {
                        h3 { class: "dialog-title", "{title}" }
                    }
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
