use dioxus::prelude::*;

use crate::{
    api::types::ViewerResponse,
    components::{
        browser_session::BrowserSessionCard,
        empty_state::EmptyState,
        loading::LoadingScreen,
        pagination::{PaginationControls, PaginationDirection, PaginationState},
    },
};

#[component]
pub fn BrowserSessions() -> Element {
    let mut show_inactive = use_signal(|| false);
    let mut pagination = use_signal(|| PaginationState::new(6));

    // Reset pagination when filter changes
    let _filter_effect = use_effect(move || {
        let _ = show_inactive();
        pagination.set(PaginationState::new(6));
    });

    let data = use_resource(move || {
        let _inactive = show_inactive();
        let _pag = pagination.read().clone();
        async move {
            // REST /viewer returns all session data combined
            crate::api::api_get::<ViewerResponse>("/viewer").await
        }
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let session = match result.viewer_session.as_browser_session() {
                Some(s) => s,
                None => return rsx! { p { "Not authenticated." } },
            };

            let user = match &session.user {
                Some(u) => u,
                None => return rsx! { p { "User data unavailable." } },
            };

            let browser_sessions: Vec<_> = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.edges.iter().rev().collect::<Vec<_>>())
                .unwrap_or_default();

            let total_count = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.total_count)
                .unwrap_or(0);

            let page_info = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.page_info.clone());

            let has_previous = page_info
                .as_ref()
                .map(|p| p.has_previous_page)
                .unwrap_or(false);
            let has_next = page_info.as_ref().map(|p| p.has_next_page).unwrap_or(false);
            let start_cursor = page_info.as_ref().and_then(|p| p.start_cursor.clone());
            let end_cursor = page_info.as_ref().and_then(|p| p.end_cursor.clone());

            let current_id = &session.id;
            let inactive_active = show_inactive();

            rsx! {
                div { class: "flex flex-col gap-6",
                    h5 { class: "heading-xs", "Browser sessions" }

                    // Inactive session filter toggle
                    div { class: "flex items-center gap-2",
                        button {
                            class: if inactive_active { "filter-toggle active" } else { "filter-toggle" },
                            onclick: move |_| show_inactive.set(!show_inactive()),
                            "Show inactive (90+ days)"
                        }
                    }

                    for edge in browser_sessions.iter() {
                        BrowserSessionCard {
                            key: "{edge.cursor}",
                            session: edge.node.clone(),
                            is_current: *current_id == edge.node.id,
                        }
                    }

                    if total_count == 0 {
                        EmptyState { "No active browser sessions" }
                    }

                    // Pagination controls
                    PaginationControls {
                        has_previous: has_previous,
                        has_next: has_next,
                        on_previous: move |_| {
                            if let Some(ref cursor) = start_cursor {
                                pagination.set(PaginationState {
                                    page_size: 6,
                                    direction: PaginationDirection::Backward(cursor.clone()),
                                });
                            }
                        },
                        on_next: move |_| {
                            if let Some(ref cursor) = end_cursor {
                                pagination.set(PaginationState {
                                    page_size: 6,
                                    direction: PaginationDirection::Forward(cursor.clone()),
                                });
                            }
                        },
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
