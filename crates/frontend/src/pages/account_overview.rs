use dioxus::prelude::*;

use crate::{
    api::types::{SecuritySummaryResponse, WorkflowInboxResponse},
    components::loading::LoadingScreen,
    pages::Route,
};

/// Account overview page.
///
/// Aggregates key account information from multiple API endpoints into a
/// single dashboard view with links to detail pages:
/// - Security status summary (password, sessions, verified emails, providers)
/// - Contact points summary (email/phone counts)
/// - Identity bindings summary (linked providers count)
/// - Pending workflow count
#[component]
pub fn AccountOverview() -> Element {
    let security = use_resource(|| async {
        crate::api::api_get::<SecuritySummaryResponse>("/viewer/security").await
    });
    let workflows = use_resource(|| async {
        crate::api::api_get::<WorkflowInboxResponse>("/viewer/workflow-inbox").await
    });

    let sec_binding = security.read();
    let wf_binding = workflows.read();

    // Wait for at least the security data before rendering.
    let summary = match &*sec_binding {
        Some(Ok(s)) => s,
        Some(Err(e)) => {
            return rsx! {
                div { class: "alert alert-critical", "{e}" }
            };
        }
        None => {
            return rsx! { LoadingScreen {} };
        }
    };

    let pending_count = match &*wf_binding {
        Some(Ok(wf)) => Some(wf.total),
        Some(Err(_)) => None, // silently degrade
        None => None,
    };

    let password_label = if summary.has_password {
        "Password is set"
    } else {
        "No password set"
    };
    let password_badge_class = if summary.has_password {
        "badge badge-success"
    } else {
        "badge badge-warning"
    };
    let password_tone_class = if summary.has_password {
        "tone-success"
    } else {
        "tone-warning"
    };
    let workflow_badge_class = match pending_count {
        Some(0) => "badge badge-success",
        Some(_) => "badge badge-warning",
        None => "badge badge-neutral",
    };
    let workflow_badge_label = match pending_count {
        Some(0) => "No pending workflows".to_string(),
        Some(count) => format!("{count} workflow(s) pending"),
        None => "Workflow status unavailable".to_string(),
    };
    let workflow_title = match pending_count {
        Some(0) => "No workflows waiting",
        Some(_) => "Pending workflow actions",
        None => "Workflow visibility degraded",
    };
    let workflow_message = match pending_count {
        Some(0) => "Everything looks clear right now. You can stay focused on profile and security hygiene.".to_string(),
        Some(count) => format!("{count} workflow(s) still need attention. Review them before they expire or block follow-up actions."),
        None => "The workflow inbox could not be loaded. You can still open it directly and retry from there.".to_string(),
    };
    rsx! {
        div { class: "overview-shell",
            div { class: "overview-hero",
                div { class: "overview-hero-copy",
                    span { class: "overview-eyebrow", "Control center" }
                    h3 { class: "heading-xs", "Account overview" }
                    p { class: "text-md text-secondary",
                        "Scan account posture, pending work, and the fastest routes to your common account tasks."
                    }
                    div { class: "flex flex-wrap items-center gap-2",
                        span { class: "{password_badge_class}", "{password_label}" }
                        span { class: "{workflow_badge_class}", "{workflow_badge_label}" }
                    }
                }
                div { class: "overview-hero-actions",
                    Link {
                        class: "btn btn-primary btn-sm",
                        to: Route::SecurityCenter {},
                        "Review security"
                    }
                    Link {
                        class: "btn btn-secondary btn-sm",
                        to: Route::Sessions {},
                        "Open devices"
                    }
                }
            }

            div { class: "overview-stat-grid",
                OverviewStatCard {
                    title: "Password",
                    value: password_label.to_string(),
                    note: if summary.has_password {
                        "Password login is available for this account.".to_string()
                    } else {
                        "Add a password to reduce recovery friction and speed up sign-in.".to_string()
                    },
                    action_label: "Open security",
                    action_to: Route::SecurityCenter {},
                    tone_class: password_tone_class,
                }
                OverviewStatCard {
                    title: "Active sessions",
                    value: summary.active_sessions_count.to_string(),
                    note: "Browser and app sessions currently recognized as active.".to_string(),
                    action_label: "Manage sessions",
                    action_to: Route::Sessions {},
                    tone_class: "tone-neutral",
                }
                OverviewStatCard {
                    title: "Linked identities",
                    value: summary.linked_providers_count.to_string(),
                    note: "Connected upstream identity providers available for sign-in.".to_string(),
                    action_label: "Review identities",
                    action_to: Route::IdentityBindings {},
                    tone_class: "tone-neutral",
                }
            }

            div { class: "overview-workflow-banner",
                div { class: "flex flex-col gap-2",
                    p { class: "overview-section-title", "{workflow_title}" }
                    p { class: "text-md text-secondary", "{workflow_message}" }
                }
                Link {
                    class: "btn btn-secondary btn-sm",
                    to: Route::WorkflowInbox {},
                    "View workflows"
                }
            }

            div { class: "flex flex-col gap-2",
                p { class: "overview-section-title", "Quick actions" }
                p { class: "text-sm text-secondary",
                    "Jump directly into the areas users typically revisit after sign-in."
                }
            }

            div { class: "overview-action-grid",
                OverviewActionCard {
                    title: "Security",
                    description: "Password health, session posture, and verified signals.",
                    to: Route::SecurityCenter {},
                }
                OverviewActionCard {
                    title: "Identities",
                    description: "Inspect or detach linked upstream sign-in providers.",
                    to: Route::IdentityBindings {},
                }
                OverviewActionCard {
                    title: "Notifications",
                    description: "Review delivery channels and update messaging preferences.",
                    to: Route::NotificationPreferences {},
                }
                OverviewActionCard {
                    title: "Devices",
                    description: "Rename or revoke browser and OAuth sessions.",
                    to: Route::Sessions {},
                }
                OverviewActionCard {
                    title: "Workflows",
                    description: "Resume pending approvals, recovery, or enrollment steps.",
                    to: Route::WorkflowInbox {},
                }
            }
        }
    }
}

#[component]
fn OverviewStatCard(
    title: &'static str,
    value: String,
    note: String,
    action_label: &'static str,
    action_to: Route,
    tone_class: &'static str,
) -> Element {
    rsx! {
        div { class: "overview-stat-card {tone_class}",
            div { class: "flex flex-col gap-2",
                p { class: "overview-stat-label", "{title}" }
                p { class: "overview-stat-value", "{value}" }
                p { class: "overview-stat-note", "{note}" }
            }
            Link {
                class: "btn btn-secondary btn-sm",
                to: action_to,
                "{action_label}"
            }
        }
    }
}

#[component]
fn OverviewActionCard(title: &'static str, description: &'static str, to: Route) -> Element {
    rsx! {
        Link { class: "overview-action-card", to: to,
            div { class: "flex flex-col gap-2",
                p { class: "overview-action-title", "{title}" }
                p { class: "text-sm text-secondary", "{description}" }
            }
            span { class: "overview-action-arrow", "Open" }
        }
    }
}
