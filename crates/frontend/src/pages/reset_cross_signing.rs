use dioxus::prelude::*;

use crate::{
    api::types::{AllowCrossSigningResetPayload, ViewerResponse},
    components::{layout::Layout, loading::LoadingScreen, page_heading::PageHeading},
    pages::Route,
};

#[derive(Debug, Clone, PartialEq)]
enum ResetState {
    Loading,
    Confirm,
    InProgress,
    Waiting,
    Success,
    Cancelled,
    Error(String),
}

/// Extract the `deepLink` query parameter from the current URL.
fn get_deep_link_from_url() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(win) = web_sys::window() {
            if let Ok(href) = win.location().href() {
                if let Ok(url) = web_sys::Url::new(&href) {
                    let params = url.search_params();
                    if let Some(val) = params.get("deepLink") {
                        return val == "true";
                    }
                }
            }
        }
    }
    false
}

#[component]
pub fn ResetCrossSigning() -> Element {
    let mut state = use_signal(|| ResetState::Loading);
    let mut user_id = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let deep_link = use_signal(get_deep_link_from_url);

    // Fetch current user
    let _data = use_resource(move || async move {
        let result = crate::api::api_get::<ViewerResponse>("/viewer").await;
        match result {
            Ok(data) => {
                if let Some(user) = data.viewer.as_user() {
                    user_id.set(user.id.clone());
                    state.set(ResetState::Confirm);
                } else {
                    state.set(ResetState::Error("Not authenticated.".to_string()));
                }
            }
            Err(e) => {
                state.set(ResetState::Error(e));
            }
        }
    });

    let current_state = state.read().clone();
    let is_deep_link = *deep_link.read();

    match current_state {
        ResetState::Loading => rsx! { LoadingScreen {} },

        ResetState::Confirm => {
            let subtitle = if is_deep_link {
                "Your Matrix client has requested a reset of your end-to-end encryption keys. This will clear your current encryption keys and force a re-verification of all your sessions. Only proceed if you initiated this from your client."
            } else {
                "This will reset your encryption keys and require re-verification of all your sessions. Only proceed if you know what you're doing."
            };

            rsx! {
                Layout {
                    div { class: "cross-signing-container",
                        PageHeading {
                            icon: "🔐".to_string(),
                            title: "Reset end-to-end encryption".to_string(),
                            subtitle: subtitle.to_string(),
                        }

                        if let Some(ref err) = *error.read() {
                            div { class: "alert alert-critical",
                                p { class: "alert-title", "Error" }
                                p { "{err}" }
                            }
                        }

                        div { class: "flex flex-col gap-4",
                            button {
                                class: "btn btn-destructive btn-lg",
                                onclick: move |_| {
                                    let uid = user_id.read().clone();
                                    state.set(ResetState::InProgress);
                                    error.set(None);
                                    spawn(async move {
                                        let result = crate::api::api_post::<AllowCrossSigningResetPayload>(
                                            "/viewer/cross-signing-reset",
                                            serde_json::json!({ "user_id": uid }),
                                        ).await;
                                        match result {
                                            Ok(_) => {
                                                state.set(ResetState::Waiting);
                                            }
                                            Err(e) => {
                                                error.set(Some(e));
                                                state.set(ResetState::Confirm);
                                            }
                                        }
                                    });
                                },
                                "Reset encryption"
                            }

                            Link { class: "btn btn-tertiary", to: Route::AccountSettings {},
                                "Cancel"
                            }
                        }
                    }
                }
            }
        }

        ResetState::InProgress => rsx! {
            Layout {
                div { class: "cross-signing-container",
                    PageHeading {
                        icon: "⏳".to_string(),
                        title: "Processing...".to_string(),
                        subtitle: "Sending the reset request to the server.".to_string(),
                    }

                    div { class: "loading-screen",
                        div { class: "loading-spinner" }
                    }
                }
            }
        },

        ResetState::Waiting => {
            let waiting_subtitle = if is_deep_link {
                "The reset has been approved. Please return to your Matrix client to complete the process."
            } else {
                "Waiting for the reset to complete. Please approve the reset from your Matrix client."
            };

            rsx! {
                Layout {
                    div { class: "cross-signing-container",
                        PageHeading {
                            icon: "⏳".to_string(),
                            title: "Waiting for approval".to_string(),
                            subtitle: waiting_subtitle.to_string(),
                        }

                        div { class: "loading-screen",
                            div { class: "loading-spinner" }
                        }

                        div { class: "flex flex-col gap-4",
                            button {
                                class: "btn btn-tertiary",
                                onclick: move |_| state.set(ResetState::Cancelled),
                                "Cancel"
                            }
                        }
                    }
                }
            }
        }

        ResetState::Success => rsx! {
            Layout {
                div { class: "cross-signing-container",
                    PageHeading {
                        icon: "✓".to_string(),
                        title: "Encryption reset".to_string(),
                        subtitle: "Your encryption keys have been reset. You will need to re-verify your sessions.".to_string(),
                    }

                    Link { class: "btn btn-primary", to: Route::AccountSettings {},
                        "Done"
                    }
                }
            }
        },

        ResetState::Cancelled => rsx! {
            Layout {
                div { class: "cross-signing-container",
                    PageHeading {
                        icon: "✗".to_string(),
                        title: "Reset cancelled".to_string(),
                        subtitle: "The encryption reset was cancelled. Your encryption keys remain unchanged.".to_string(),
                    }

                    Link { class: "btn btn-primary", to: Route::AccountSettings {},
                        "Back to settings"
                    }
                }
            }
        },

        ResetState::Error(ref msg) => rsx! {
            Layout {
                div { class: "cross-signing-container",
                    PageHeading {
                        icon: "✗".to_string(),
                        title: "Error".to_string(),
                        subtitle: msg.clone(),
                    }

                    Link { class: "btn btn-primary", to: Route::AccountSettings {},
                        "Back to settings"
                    }
                }
            }
        },
    }
}
