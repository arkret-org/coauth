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
    const FOCUS_TRAP_SELECTOR: &str = ".dialog-content[data-focus-trap='dialog']";
    let mut was_open = use_signal(|| false);
    use_effect(move || {
        let is_open = open();
        if is_open == was_open() {
            return;
        }
        if is_open {
            super::focus_trap::activate(FOCUS_TRAP_SELECTOR);
        } else {
            super::focus_trap::restore();
        }
        was_open.set(is_open);
    });
    use_drop(move || {
        if was_open() {
            super::focus_trap::restore();
        }
    });

    let aria_label = title.clone().unwrap_or_else(|| "Dialog".to_owned());

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
                    role: "dialog",
                    aria_modal: "true",
                    aria_label: aria_label,
                    "data-focus-trap": "dialog",
                    tabindex: "-1",
                    onkeydown: move |event| {
                        match event.key() {
                            Key::Escape => open.set(false),
                            Key::Tab => {
                                event.prevent_default();
                                let reverse = event.modifiers().contains(Modifiers::SHIFT);
                                super::focus_trap::cycle(FOCUS_TRAP_SELECTOR, reverse);
                            }
                            _ => {}
                        }
                    },
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
