use dioxus::prelude::*;

/// Pagination state for cursor-based API pagination.
#[derive(Debug, Clone, PartialEq)]
pub struct PaginationState {
    /// Number of items per page.
    pub page_size: i32,
    /// Current pagination direction and cursor.
    pub direction: PaginationDirection,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PaginationDirection {
    /// Load the last N items (initial/default).
    LastPage,
    /// Load forward: first N items after cursor.
    Forward(String),
    /// Load backward: last N items before cursor.
    Backward(String),
}

impl PaginationState {
    pub fn new(page_size: i32) -> Self {
        Self {
            page_size,
            direction: PaginationDirection::LastPage,
        }
    }

    /// Build the query parameters for this pagination state.
    pub fn to_variables(&self) -> serde_json::Value {
        match &self.direction {
            PaginationDirection::LastPage => {
                serde_json::json!({ "last": self.page_size })
            }
            PaginationDirection::Forward(cursor) => {
                serde_json::json!({ "first": self.page_size, "after": cursor })
            }
            PaginationDirection::Backward(cursor) => {
                serde_json::json!({ "last": self.page_size, "before": cursor })
            }
        }
    }
}

#[component]
pub fn PaginationControls(
    has_previous: bool,
    has_next: bool,
    on_previous: EventHandler<()>,
    on_next: EventHandler<()>,
) -> Element {
    if !has_previous && !has_next {
        return rsx! {};
    }

    rsx! {
        div { class: "pagination-controls",
            button {
                class: "btn btn-secondary btn-sm",
                disabled: !has_previous,
                onclick: move |_| on_previous.call(()),
                "Previous"
            }
            div {}
            button {
                class: "btn btn-secondary btn-sm",
                disabled: !has_next,
                onclick: move |_| on_next.call(()),
                "Next"
            }
        }
    }
}
