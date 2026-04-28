use dioxus::prelude::*;

use crate::{
    api::types::SecuritySummaryResponse,
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
    pages::Route,
};

/// Security center page.
///
/// Fetches `GET /api/v1/viewer/security` and displays:
/// - Password status (set / not set)
/// - Active sessions count
/// - Verified emails count
/// - Linked providers count
#[component]
pub fn SecurityCenter() -> Element {
    let data = use_resource(|| async {
        crate::api::api_get::<SecuritySummaryResponse>("/viewer/security").await
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(summary)) => {
            let password_label = if summary.has_password {
                "Password is set"
            } else {
                "No password set"
            };

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Security Center" }

                    // Password status
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Password status" }
                        div { class: "flex items-center gap-2",
                            span {
                                class: if summary.has_password { "badge badge-success" } else { "badge badge-warning" },
                                "{password_label}"
                            }
                        }
                        p { class: "text-md text-secondary",
                            "View and manage your account password. Check when it was last changed and update it if needed."
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Active sessions summary
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Active sessions" }
                        p { class: "text-md",
                            "{summary.active_sessions_count} active session(s)"
                        }
                        p { class: "text-md text-secondary",
                            "A summary of your currently active browser and app sessions."
                        }
                        Link {
                            class: "btn btn-secondary btn-sm",
                            to: Route::Sessions {},
                            "Manage sessions"
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Verified emails
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Verified emails" }
                        p { class: "text-md",
                            "{summary.verified_emails_count} verified email(s)"
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Linked providers
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Linked providers" }
                        p { class: "text-md",
                            "{summary.linked_providers_count} linked provider(s)"
                        }
                    }

                    Separator {}
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
