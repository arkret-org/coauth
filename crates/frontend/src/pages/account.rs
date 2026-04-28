use dioxus::prelude::*;

use crate::{
    api::types::{PatchViewerProfileResponse, ViewerResponse},
    components::{
        layout::{Layout, LayoutWidth},
        loading::LoadingScreen,
        user_greeting::{EditProfileDialog, UserGreeting},
    },
    pages::Route,
};

/// A sidebar navigation item for the account layout.
#[component]
fn SidebarItem(to: Route, children: Element) -> Element {
    let current_route = use_route::<Route>();
    let is_active = std::mem::discriminant(&current_route) == std::mem::discriminant(&to);
    let active_class = if is_active { " active" } else { "" };

    rsx! {
        Link { class: "sidebar-item{active_class}", to: to, {children} }
    }
}

#[component]
fn SidebarExternalLink(href: String, children: Element) -> Element {
    rsx! {
        a {
            class: "sidebar-item",
            href: "{href}",
            target: "_blank",
            rel: "noopener noreferrer",
            {children}
            span { class: "text-xs", " (external)" }
        }
    }
}

#[component]
pub fn AccountPage() -> Element {
    let data = use_resource(|| async { crate::api::api_get::<ViewerResponse>("/viewer").await });
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let user = match result.viewer.as_user() {
                Some(u) => u,
                None => {
                    let nav = navigator();
                    nav.push(Route::Login {});
                    return rsx! {
                        Layout { p { "Redirecting to login..." } }
                    };
                }
            };

            let matrix = match &user.matrix {
                Some(m) => m.clone(),
                None => {
                    return rsx! {
                        Layout { p { "User data unavailable." } }
                    };
                }
            };
            let profile = user
                .profile
                .clone()
                .unwrap_or(crate::api::types::UserProfile {
                    display_name: matrix.display_name.clone(),
                    avatar_url: None,
                    preferred_locale: None,
                    updated_at: String::new(),
                });

            let has_plan = result.site_config.plan_management_iframe_uri.is_some();
            let admin_portal_url = if user.can_request_admin {
                result.site_config.admin_portal_url.clone()
            } else {
                None
            };
            let display_name_change_allowed = result.site_config.display_name_change_allowed;

            let mut show_edit_dialog = use_signal(|| false);
            let mut current_profile = use_signal(|| profile.clone());
            let mut current_matrix = use_signal(|| matrix.clone());

            rsx! {
                Layout { width: LayoutWidth::Full,
                    div { class: "account-layout",
                        nav { class: "account-sidebar",
                            div { class: "sidebar-profile",
                                UserGreeting {
                                    matrix: current_matrix.read().clone(),
                                    profile: current_profile.read().clone(),
                                    display_name_change_allowed: display_name_change_allowed,
                                    on_edit: move |_| show_edit_dialog.set(true),
                                }
                            }

                            div { class: "sidebar-nav-group",
                                span { class: "sidebar-group-label", "Account" }
                                SidebarItem { to: Route::AccountOverview {}, "Overview" }
                                SidebarItem { to: Route::AccountSettings {}, "Settings" }
                                SidebarItem { to: Route::IdentityBindings {}, "Identities" }
                            }

                            div { class: "sidebar-nav-group",
                                span { class: "sidebar-group-label", "Security" }
                                SidebarItem { to: Route::SecurityCenter {}, "Security" }
                                SidebarItem { to: Route::Sessions {}, "Devices" }
                            }

                            if let Some(admin_portal_url) = admin_portal_url {
                                div { class: "sidebar-nav-group",
                                    span { class: "sidebar-group-label", "Administration" }
                                    SidebarExternalLink { href: admin_portal_url, "Admin Portal" }
                                }
                            }

                            div { class: "sidebar-nav-group",
                                span { class: "sidebar-group-label", "Preferences" }
                                SidebarItem { to: Route::NotificationPreferences {}, "Notifications" }
                                SidebarItem { to: Route::WorkflowInbox {}, "Workflows" }
                                if has_plan {
                                    SidebarItem { to: Route::Plan {}, "Plan" }
                                }
                            }
                        }

                        div { class: "account-content",
                            Outlet::<Route> {}
                            if show_edit_dialog() {
                                EditProfileDialog {
                                    open: show_edit_dialog,
                                    profile: current_profile.read().clone(),
                                    matrix: current_matrix.read().clone(),
                                    on_saved: move |response: PatchViewerProfileResponse| {
                                        current_profile.set(response.profile);
                                        current_matrix.set(response.matrix);
                                    },
                                }
                            }
                        }
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}
