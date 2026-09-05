use dioxus::prelude::*;

use crate::api::types::{AppSession, ViewerOutcome};
use crate::components::empty_state::EmptyState;
use crate::components::loading::LoadingScreen;
use crate::components::oauth_session::OAuthSessionCard;
use crate::components::pagination::{
    PaginationState, SessionFilterToggle, SessionPaginationControls, session_query,
};
use crate::components::separator::{Separator, SeparatorKind};
use crate::pages::Route;

#[component]
pub fn Sessions() -> Element {
    let show_inactive = use_signal(|| false);
    let pagination = use_signal(|| PaginationState::new(6));

    // REST /viewer returns all session data combined, so a single request
    // serves both the browser-session overview and the app-session list.
    // Re-fetch when the filter toggle or pagination cursor changes.
    let sessions = use_resource(move || {
        let query = session_query("app", &pagination.read(), show_inactive());
        async move { crate::api::api_get::<ViewerOutcome>(&format!("/self/viewer{query}")).await }
    });

    let sessions_binding = sessions.read();

    match &*sessions_binding {
        Some(Ok(session_data)) => {
            let session_user = match session_data.viewer.as_user() {
                Some(u) => u,
                None => return rsx! { p { "Not authenticated." } },
            };

            let browser_session_count = session_user
                .browser_sessions
                .as_ref()
                .map_or(0, |bs| bs.total_count);

            let app_sessions: Vec<_> = session_user
                .app_sessions
                .as_ref()
                .map(|s| s.edges.iter().rev().collect::<Vec<_>>())
                .unwrap_or_default();

            let total_count = session_user
                .app_sessions
                .as_ref()
                .map_or(0, |s| s.total_count);

            let page_info = session_user
                .app_sessions
                .as_ref()
                .map(|s| s.page_info.clone());

            let has_previous = page_info.as_ref().is_some_and(|p| p.has_previous_page);
            let has_next = page_info.as_ref().is_some_and(|p| p.has_next_page);
            let start_cursor = page_info.as_ref().and_then(|p| p.start_cursor.clone());
            let end_cursor = page_info.as_ref().and_then(|p| p.end_cursor.clone());

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Sessions" }

                    SessionFilterToggle { active: show_inactive, pagination }

                    // Browser sessions overview
                    div { class: "browser-sessions-overview",
                        Link {
                            class: "session-card compact",
                            to: Route::BrowserSessions {},
                            div { class: "flex items-center justify-between",
                                span { "Browser sessions" }
                                span { class: "text-sm text-secondary", "{browser_session_count} active" }
                            }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // App sessions list
                    for edge in app_sessions.iter() {
                        match &edge.node {
                            AppSession::OAuthSession(session) => rsx! {
                                OAuthSessionCard { key: "{edge.cursor}", session: session.clone() }
                            },
                        }
                    }

                    if total_count == 0 {
                        EmptyState { "No active app sessions" }
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
