//! Full-page error components rendered when the backend injects an error
//! state into the SPA configuration (e.g. account deactivated, locked, or
//! session ended).

use dioxus::prelude::*;

use crate::{components::layout::Layout, config::AppError};

/// Top-level dispatcher: picks the right error page based on `error.kind`.
#[component]
pub fn ErrorPage(error: AppError) -> Element {
    match error.kind.as_str() {
        "account_deactivated" => rsx! {
            AccountDeactivated { username: error.username }
        },
        "account_locked" => rsx! {
            AccountLocked { username: error.username }
        },
        "session_ended" => rsx! {
            SessionEnded {}
        },
        _ => rsx! {
            GenericServerError { description: error.description }
        },
    }
}

// ── Account deactivated ──────────────────────────────────────────────

#[component]
fn AccountDeactivated(username: Option<String>) -> Element {
    rsx! {
        Layout {
            div { class: "flex flex-col gap-6 items-center",
                div { class: "page-heading-icon", "!" }
                h1 { class: "heading-sm", "Account deactivated" }
                p { class: "text-md text-secondary text-center",
                    "This account has been deactivated."
                }
                if let Some(name) = &username {
                    p { class: "text-md text-secondary",
                        "Signed in as {name}"
                    }
                }
                LogoutButton {}
            }
        }
    }
}

// ── Account locked ───────────────────────────────────────────────────

#[component]
fn AccountLocked(username: Option<String>) -> Element {
    rsx! {
        Layout {
            div { class: "flex flex-col gap-6 items-center",
                div { class: "page-heading-icon", "!" }
                h1 { class: "heading-sm", "Account locked" }
                p { class: "text-md text-secondary text-center",
                    "This account has been locked by an administrator."
                }
                if let Some(name) = &username {
                    p { class: "text-md text-secondary",
                        "Signed in as {name}"
                    }
                }
                LogoutButton {}
            }
        }
    }
}

// ── Session ended ────────────────────────────────────────────────────

#[component]
fn SessionEnded() -> Element {
    rsx! {
        Layout {
            div { class: "flex flex-col gap-6 items-center",
                div { class: "page-heading-icon", "!" }
                h1 { class: "heading-sm", "Session ended" }
                p { class: "text-md text-secondary text-center",
                    "Your session was ended remotely. Please sign in again."
                }
                a {
                    class: "btn btn-primary btn-lg",
                    href: "/login",
                    "Sign in"
                }
            }
        }
    }
}

// ── Generic server error ─────────────────────────────────────────────

#[component]
fn GenericServerError(description: Option<String>) -> Element {
    let msg = description.unwrap_or_else(|| "An unexpected error occurred.".to_string());

    rsx! {
        Layout {
            div { class: "flex flex-col gap-6 items-center",
                div { class: "page-heading-icon", "!" }
                h1 { class: "heading-sm", "Error" }
                p { class: "text-md text-secondary text-center", "{msg}" }
                a {
                    class: "btn btn-primary btn-lg",
                    href: "/login",
                    "Back to sign in"
                }
            }
        }
    }
}

// ── Shared logout button ─────────────────────────────────────────────

#[component]
fn LogoutButton() -> Element {
    let nav = navigator();
    let mut signing_out = use_signal(|| false);

    rsx! {
        button {
            class: "btn btn-destructive btn-lg",
            disabled: signing_out(),
            onclick: move |_| {
                let nav = nav.clone();
                signing_out.set(true);
                spawn(async move {
                    // DELETE the current browser session to log out.
                    let _ = crate::api::api_delete::<serde_json::Value>(
                        "/browser-sessions/current",
                    )
                    .await;
                    // Redirect to login regardless of the API result.
                    nav.push(crate::pages::Route::Login {});
                });
            },
            if signing_out() {
                span { class: "loading-spinner inline" }
            }
            "Sign out"
        }
    }
}
