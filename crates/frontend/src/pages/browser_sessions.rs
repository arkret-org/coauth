use dioxus::prelude::*;

use crate::api::types::ViewerOutcome;
use crate::components::browser_session::BrowserSessionCard;
use crate::components::empty_state::EmptyState;
use crate::components::loading::LoadingScreen;
use crate::components::pagination::{
    PaginationState, SessionFilterToggle, SessionPaginationControls, session_query,
};

#[component]
pub fn BrowserSessions() -> Element {
    let show_inactive = use_signal(|| false);
    let pagination = use_signal(|| PaginationState::new(6));

    // Re-fetch when the filter toggle or pagination cursor changes. Reading the
    // signals by reference (not clone) is enough to register the dependency.
    let data = use_resource(move || {
        let query = session_query("browser", &pagination.read(), show_inactive());
        async move { crate::api::api_get::<ViewerOutcome>(&format!("/self/viewer{query}")).await }
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let session = match result.viewer_session.as_browser_session() {
                Some(s) => s,
                None => return rsx! { p { "Not authenticated." } },
            };

            let user = match result.viewer.as_user() {
                Some(user) => user,
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
                .map_or(0, |bs| bs.total_count);

            let page_info = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.page_info.clone());

            let has_previous = page_info.as_ref().is_some_and(|p| p.has_previous_page);
            let has_next = page_info.as_ref().is_some_and(|p| p.has_next_page);
            let start_cursor = page_info.as_ref().and_then(|p| p.start_cursor.clone());
            let end_cursor = page_info.as_ref().and_then(|p| p.end_cursor.clone());

            let current_id = &session.id;

            rsx! {
                div { class: "flex flex-col gap-6",
                    h5 { class: "heading-xs", "Browser sessions" }

                    SessionFilterToggle { active: show_inactive, pagination }

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
                    SessionPaginationControls {
                        pagination,
                        has_previous,
                        has_next,
                        start_cursor,
                        end_cursor,
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
