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

/// Query string for `/self/viewer`'s session connections.
///
/// `prefix` names the connection the cursor belongs to (`browser` or `app`).
/// The two are not interchangeable: a cursor is a node id and the viewer
/// rejects one of the wrong kind rather than slicing the other list by an
/// unrelated ULID. A node id is `<prefix>:<ulid>`, and `:` is legal in a query
/// component, so it needs no escaping.
#[must_use]
pub fn session_query(prefix: &str, state: &PaginationState, include_ended: bool) -> String {
    let mut query = format!("?session_limit={}", state.page_size);
    match &state.direction {
        PaginationDirection::LastPage => {}
        PaginationDirection::Forward(cursor) => {
            query.push_str(&format!("&{prefix}_after={cursor}"));
        }
        PaginationDirection::Backward(cursor) => {
            query.push_str(&format!("&{prefix}_before={cursor}"));
        }
    }
    if include_ended {
        query.push_str("&include_ended=true");
    }
    query
}

/// The "Show ended sessions" filter toggle shared by the session list pages.
/// Flipping it also resets pagination back to the first page.
///
/// It used to read "Show ended sessions". The storage filter behind it
/// is `active_only` -- whether a session has ended -- and there is no
/// age threshold anywhere in the query, so the old label described a
/// behaviour that did not exist.
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
