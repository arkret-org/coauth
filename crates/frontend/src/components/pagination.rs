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
}

/// The "Show inactive (90+ days)" filter toggle shared by the session list
/// pages. Flipping it also resets pagination back to the first page.
#[component]
pub fn SessionFilterToggle(active: Signal<bool>, pagination: Signal<PaginationState>) -> Element {
    let page_size = pagination.read().page_size;
    rsx! {
        div { class: "flex items-center gap-2",
            button {
                class: if active() { "filter-toggle active" } else { "filter-toggle" },
                onclick: move |_| {
                    active.set(!active());
                    // Reset to the first page when the filter changes.
                    pagination.set(PaginationState::new(page_size));
                },
                "Show inactive (90+ days)"
            }
        }
    }
}

/// Cursor-based pagination controls wired directly to a [`PaginationState`]
/// signal. Shared by the session list pages so the forward/backward cursor
/// bookkeeping isn't duplicated per page.
#[component]
pub fn SessionPaginationControls(
    pagination: Signal<PaginationState>,
    has_previous: bool,
    has_next: bool,
    start_cursor: Option<String>,
    end_cursor: Option<String>,
) -> Element {
    let page_size = pagination.read().page_size;
    rsx! {
        PaginationControls {
            has_previous,
            has_next,
            on_previous: move |()| {
                if let Some(ref cursor) = start_cursor {
                    pagination.set(PaginationState {
                        page_size,
                        direction: PaginationDirection::Backward(cursor.clone()),
                    });
                }
            },
            on_next: move |()| {
                if let Some(ref cursor) = end_cursor {
                    pagination.set(PaginationState {
                        page_size,
                        direction: PaginationDirection::Forward(cursor.clone()),
                    });
                }
            },
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
