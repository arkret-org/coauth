use dioxus::prelude::*;

use crate::api::types::SecuritySummaryOutcome;
use crate::components::loading::LoadingScreen;
use crate::components::status_badge::StatusBadge;
use crate::pages::Route;

/// Account overview page.
///
/// Aggregates key account information from multiple API endpoints into a
/// single dashboard view with links to detail pages:
/// - Security status summary (password, sessions, verified emails, providers)
/// - Contact points summary (email/phone counts)
/// - Identity bindings summary (linked providers count)
#[component]
pub fn AccountOverview() -> Element {
    let security = use_resource(|| async {
        crate::api::api_get::<SecuritySummaryOutcome>("/self/viewer/security").await
    });

    let sec_binding = security.read();

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

    let password_label = if summary.has_password {
        "Password is set"
    } else {
        "No password set"
    };
    let password_tone_class = if summary.has_password {
        "tone-success"
    } else {
        "tone-warning"
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
                        StatusBadge { ok: summary.has_password, label: password_label.to_owned() }
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
                    value: password_label.to_owned(),
                    note: if summary.has_password {
                        "Password login is available for this account.".to_owned()
                    } else {
                        "Add a password to reduce recovery friction and speed up sign-in.".to_owned()
                    },
                    action_label: "Open security",
                    action_to: Route::SecurityCenter {},
                    tone_class: password_tone_class,
                }
                OverviewStatCard {
                    title: "Active sessions",
                    value: summary.active_sessions_count.to_string(),
                    note: "Browser and app sessions currently recognized as active.".to_owned(),
                    action_label: "Manage sessions",
                    action_to: Route::Sessions {},
                    tone_class: "tone-neutral",
                }
                OverviewStatCard {
                    title: "Linked identities",
                    value: summary.linked_providers_count.to_string(),
                    note: "Connected upstream identity providers available for sign-in.".to_owned(),
                    action_label: "Review identities",
                    action_to: Route::IdentityBindings {},
                    tone_class: "tone-neutral",
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
