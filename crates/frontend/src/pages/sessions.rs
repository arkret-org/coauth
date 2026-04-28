use dioxus::prelude::*;

use crate::{
    api::types::{AppSession, ViewerResponse},
    components::{
        empty_state::EmptyState,
        loading::LoadingScreen,
        oauth2_session::OAuth2SessionCard,
        pagination::{PaginationControls, PaginationDirection, PaginationState},
        separator::{Separator, SeparatorKind},
    },
    pages::Route,
};

#[component]
pub fn Sessions() -> Element {
    let mut show_inactive = use_signal(|| false);
    let mut pagination = use_signal(|| PaginationState::new(6));

    // Reset pagination when filter changes
    let _filter_effect = use_effect(move || {
        let _ = show_inactive();
        pagination.set(PaginationState::new(6));
    });

    let overview =
        use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });

    let sessions = use_resource(move || {
        let _inactive = show_inactive();
        let _pag = pagination.read().clone();
        async move {
            // REST /viewer returns all session data combined
            crate::api::api_get::<ViewerResponse>("/viewer").await
        }
    });

    let overview_binding = overview.read();
    let sessions_binding = sessions.read();

    match (&*overview_binding, &*sessions_binding) {
        (Some(Ok(overview_data)), Some(Ok(session_data))) => {
            let user = match overview_data.viewer.as_user() {
                Some(u) => u,
                None => return rsx! { p { "Not authenticated." } },
            };

            let session_user = match session_data.viewer.as_user() {
                Some(u) => u,
                None => return rsx! { p { "Not authenticated." } },
            };

            let browser_session_count = user
                .browser_sessions
                .as_ref()
                .map(|bs| bs.total_count)
                .unwrap_or(0);

            let app_sessions: Vec<_> = session_user
                .app_sessions
                .as_ref()
                .map(|s| s.edges.iter().rev().collect::<Vec<_>>())
                .unwrap_or_default();

            let total_count = session_user
                .app_sessions
                .as_ref()
                .map(|s| s.total_count)
                .unwrap_or(0);

            let page_info = session_user
                .app_sessions
                .as_ref()
                .map(|s| s.page_info.clone());

            let has_previous = page_info
                .as_ref()
                .map(|p| p.has_previous_page)
                .unwrap_or(false);
            let has_next = page_info.as_ref().map(|p| p.has_next_page).unwrap_or(false);
            let start_cursor = page_info.as_ref().and_then(|p| p.start_cursor.clone());
            let end_cursor = page_info.as_ref().and_then(|p| p.end_cursor.clone());

            let inactive_active = show_inactive();

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Sessions" }

                    // Inactive session filter toggle
                    div { class: "flex items-center gap-2",
                        button {
                            class: if inactive_active { "filter-toggle active" } else { "filter-toggle" },
                            onclick: move |_| show_inactive.set(!show_inactive()),
                            "Show inactive (90+ days)"
                        }
                    }

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
                            AppSession::Oauth2Session(session) => rsx! {
                                OAuth2SessionCard { key: "{edge.cursor}", session: session.clone() }
                            },
                        }
                    }

                    if total_count == 0 {
                        EmptyState { "No active app sessions" }
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
        (Some(Err(e)), _) | (_, Some(Err(e))) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        _ => rsx! { LoadingScreen {} },
    }
}
