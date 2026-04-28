use dioxus::prelude::*;

use crate::{
    api::types::{AppSession, ViewerResponse},
    components::{layout::Layout, loading::LoadingScreen, page_heading::PageHeading},
    pages::Route,
};

#[component]
pub fn DeviceRedirect(route: Vec<String>) -> Element {
    let device_id = route.join("/");
    let nav = navigator();

    let data = use_resource(move || {
        let _device_id = device_id.clone();
        async move {
            // Get the combined viewer data (includes app sessions)
            crate::api::api_get::<ViewerResponse>("/viewer").await
        }
    });

    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let user = match result.viewer.as_user() {
                Some(u) => u,
                None => {
                    return rsx! {
                        Layout {
                            div { class: "flex flex-col gap-10",
                                PageHeading {
                                    icon: "🔒".to_string(),
                                    title: "Not authenticated".to_string(),
                                    subtitle: "Please sign in to view device information.".to_string(),
                                }
                                Link { class: "btn btn-primary", to: Route::Login {},
                                    "Sign in"
                                }
                            }
                        }
                    };
                }
            };

            // Check if we found a session
            if let Some(ref app_sessions) = user.app_sessions {
                if let Some(edge) = app_sessions.edges.first() {
                    let session_id = match &edge.node {
                        AppSession::Oauth2Session(s) => s.id.clone(),
                    };
                    nav.push(Route::SessionDetail { id: session_id });
                    return rsx! { LoadingScreen {} };
                }
            }

            rsx! {
                Layout {
                    div { class: "flex flex-col gap-10",
                        PageHeading {
                            icon: "?".to_string(),
                            title: "Device not found".to_string(),
                            subtitle: "The device you are looking for could not be found.".to_string(),
                        }
                        Link { class: "btn btn-primary", to: Route::Sessions {},
                            "Back to sessions"
                        }
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "flex flex-col gap-10",
                    PageHeading {
                        icon: "!".to_string(),
                        title: "Error".to_string(),
                        subtitle: e.clone(),
                    }
                    Link { class: "btn btn-primary", to: Route::Sessions {},
                        "Back to sessions"
                    }
                }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}
