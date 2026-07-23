//! Browser focus management for modal dialogs.

#[cfg(any(target_arch = "wasm32", test))]
fn next_focus_index(current: Option<usize>, len: usize, reverse: bool) -> Option<usize> {
    if len == 0 {
        return None;
    }

    Some(match (current, reverse) {
        (Some(0) | None, true) => len - 1,
        (Some(index), true) => index - 1,
        (Some(index), false) if index + 1 < len => index + 1,
        (Some(_) | None, false) => 0,
    })
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::RefCell;

    use wasm_bindgen::{JsCast, JsValue};
    use web_sys::{Document, Element, HtmlElement};

    use super::next_focus_index;

    const FOCUSABLE_SELECTOR: &str = concat!(
        "button:not([disabled]):not([tabindex='-1']),",
        "[href]:not([tabindex='-1']),",
        "input:not([disabled]):not([type='hidden']):not([tabindex='-1']),",
        "select:not([disabled]):not([tabindex='-1']),",
        "textarea:not([disabled]):not([tabindex='-1']),",
        "[tabindex]:not([tabindex='-1'])"
    );

    thread_local! {
        static RETURN_FOCUS: RefCell<Vec<HtmlElement>> = const { RefCell::new(Vec::new()) };
    }

    fn document() -> Option<Document> {
        web_sys::window()?.document()
    }

    fn top_dialog(document: &Document, selector: &str) -> Option<HtmlElement> {
        let matches = document.query_selector_all(selector).ok()?;
        let node = matches.item(matches.length().checked_sub(1)?)?;
        node.dyn_into().ok()
    }

    fn focusable_elements(dialog: &Element) -> Vec<HtmlElement> {
        let Ok(nodes) = dialog.query_selector_all(FOCUSABLE_SELECTOR) else {
            return Vec::new();
        };

        (0..nodes.length())
            .filter_map(|index| nodes.item(index))
            .filter_map(|node| node.dyn_into::<HtmlElement>().ok())
            .collect()
    }

    fn same_element(left: &HtmlElement, right: &HtmlElement) -> bool {
        JsValue::from(left.clone()) == JsValue::from(right.clone())
    }

    pub(super) fn activate(selector: &str) {
        let Some(document) = document() else {
            return;
        };

        if let Some(active) = document
            .active_element()
            .and_then(|element| element.dyn_into::<HtmlElement>().ok())
        {
            RETURN_FOCUS.with(|stack| stack.borrow_mut().push(active));
        }

        let Some(dialog) = top_dialog(&document, selector) else {
            return;
        };
        let focusables = focusable_elements(&dialog);
        let target = focusables.first().unwrap_or(&dialog);
        let _ = target.focus();
    }

    pub(super) fn cycle(selector: &str, reverse: bool) {
        let Some(document) = document() else {
            return;
        };
        let Some(dialog) = top_dialog(&document, selector) else {
            return;
        };
        let focusables = focusable_elements(&dialog);
        let current = document
            .active_element()
            .and_then(|element| element.dyn_into::<HtmlElement>().ok())
            .and_then(|active| {
                focusables
                    .iter()
                    .position(|element| same_element(element, &active))
            });

        if let Some(index) = next_focus_index(current, focusables.len(), reverse) {
            let _ = focusables[index].focus();
        } else {
            let _ = dialog.focus();
        }
    }

    pub(super) fn restore() {
        let previous = RETURN_FOCUS.with(|stack| stack.borrow_mut().pop());
        if let Some(previous) = previous
            && previous.is_connected()
        {
            let _ = previous.focus();
        }
    }
}

pub(super) fn activate(selector: &str) {
    #[cfg(target_arch = "wasm32")]
    browser::activate(selector);

    #[cfg(not(target_arch = "wasm32"))]
    let _ = selector;
}

pub(super) fn cycle(selector: &str, reverse: bool) {
    #[cfg(target_arch = "wasm32")]
    browser::cycle(selector, reverse);

    #[cfg(not(target_arch = "wasm32"))]
    let _ = (selector, reverse);
}

pub(super) fn restore() {
    #[cfg(target_arch = "wasm32")]
    browser::restore();
}

#[cfg(test)]
mod tests {
    use super::next_focus_index;

    #[test]
    fn cycles_focus_in_both_directions() {
        assert_eq!(next_focus_index(Some(0), 3, false), Some(1));
        assert_eq!(next_focus_index(Some(2), 3, false), Some(0));
        assert_eq!(next_focus_index(Some(0), 3, true), Some(2));
        assert_eq!(next_focus_index(Some(2), 3, true), Some(1));
        assert_eq!(next_focus_index(None, 3, false), Some(0));
        assert_eq!(next_focus_index(None, 3, true), Some(2));
        assert_eq!(next_focus_index(None, 0, false), None);
    }
}
