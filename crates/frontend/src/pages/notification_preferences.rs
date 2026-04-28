use dioxus::prelude::*;

use crate::{
    api::types::NotificationPreferencesResponse,
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
};

/// Notification preferences page.
///
/// Fetches `GET /api/v1/viewer/preferences` to obtain channel
/// availability and the user's current per-channel preferences. The user can
/// toggle channels on/off and save via
/// `PATCH /api/v1/viewer/preferences`.
#[component]
pub fn NotificationPreferences() -> Element {
    let data = use_resource(|| async {
        crate::api::api_get::<NotificationPreferencesResponse>("/viewer/preferences").await
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(response)) => {
            rsx! {
                NotificationPreferencesForm {
                    available_channels: response.available_channels.clone(),
                    initial_preferences: response.preferences.clone(),
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}

/// Inner form component that owns signal state for the preference toggles.
#[component]
fn NotificationPreferencesForm(
    available_channels: Vec<crate::api::types::ChannelAvailability>,
    initial_preferences: Vec<crate::api::types::ChannelPreference>,
) -> Element {
    // Mutable copy of preferences the user can toggle.
    let mut preferences = use_signal(|| initial_preferences.clone());
    let mut saving = use_signal(|| false);
    let mut feedback = use_signal(|| None::<Result<String, String>>);

    // Helper: look up whether a channel is enabled in the user's preferences.
    let is_channel_enabled =
        |prefs: &[crate::api::types::ChannelPreference], channel: &str| -> bool {
            prefs
                .iter()
                .find(|p| p.channel == channel)
                .map(|p| p.enabled)
                .unwrap_or(false)
        };

    // Build channel display data.
    let email_available = available_channels
        .iter()
        .any(|c| c.channel == "email" && c.enabled);
    let sms_available = available_channels
        .iter()
        .any(|c| c.channel == "sms" && c.enabled);
    let email_enabled = is_channel_enabled(&preferences.read(), "email");
    let sms_enabled = is_channel_enabled(&preferences.read(), "sms");

    rsx! {
        div { class: "flex flex-col gap-6",
            h3 { class: "heading-xs", "Notification Preferences" }

            // Email channel
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Email notifications" }
                div { class: "flex items-center gap-3",
                    span {
                        class: if email_available { "badge badge-success" } else { "badge badge-warning" },
                        if email_available { "Email delivery configured" } else { "Email delivery not configured" }
                    }
                }
                p { class: "text-md text-secondary",
                    "Enable or disable email notifications for account activity and security alerts."
                }
                label { class: "flex items-center gap-2",
                    input {
                        r#type: "checkbox",
                        checked: email_enabled,
                        disabled: !email_available,
                        onchange: move |e| {
                            let checked = e.checked();
                            let mut prefs = preferences.write();
                            if let Some(p) = prefs.iter_mut().find(|p| p.channel == "email") {
                                p.enabled = checked;
                            }
                        },
                    }
                    span { class: "text-md", "Receive email notifications" }
                }
            }

            Separator { kind: SeparatorKind::Section }

            // SMS channel
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "SMS notifications" }
                div { class: "flex items-center gap-3",
                    span {
                        class: if sms_available { "badge badge-success" } else { "badge badge-warning" },
                        if sms_available { "SMS delivery configured" } else { "SMS delivery not configured" }
                    }
                }
                p { class: "text-md text-secondary",
                    "Enable or disable SMS notifications for account verification and alerts."
                }
                label { class: "flex items-center gap-2",
                    input {
                        r#type: "checkbox",
                        checked: sms_enabled,
                        disabled: !sms_available,
                        onchange: move |e| {
                            let checked = e.checked();
                            let mut prefs = preferences.write();
                            if let Some(p) = prefs.iter_mut().find(|p| p.channel == "sms") {
                                p.enabled = checked;
                            }
                        },
                    }
                    span { class: "text-md", "Receive SMS notifications" }
                }
            }

            Separator { kind: SeparatorKind::Section }

            // Language preference (placeholder)
            div { class: "flex flex-col gap-2",
                h4 { class: "text-md font-semibold", "Language preference" }
                p { class: "text-md text-secondary",
                    "Choose the language for notification messages sent to you. This setting is not yet available."
                }
            }

            Separator { kind: SeparatorKind::Section }

            // Feedback messages
            if let Some(ref result) = *feedback.read() {
                match result {
                    Ok(msg) => rsx! {
                        div { class: "alert alert-success", "{msg}" }
                    },
                    Err(msg) => rsx! {
                        div { class: "alert alert-critical", "{msg}" }
                    },
                }
            }

            // Save button
            button {
                class: "btn btn-primary",
                disabled: saving(),
                onclick: move |_| {
                    let prefs_snapshot: Vec<crate::api::types::ChannelPreference> =
                        preferences.read().clone();
                    saving.set(true);
                    feedback.set(None);
                    spawn(async move {
                        let body = serde_json::json!({
                            "preferences": prefs_snapshot,
                        });
                        let result = crate::api::api_patch::<
                            crate::api::types::UpdateNotificationPreferencesResponse,
                        >("/viewer/preferences", body)
                        .await;
                        saving.set(false);
                        match result {
                            Ok(resp) => {
                                preferences.set(resp.preferences);
                                feedback.set(Some(Ok(
                                    "Preferences saved successfully.".to_string(),
                                )));
                            }
                            Err(e) => {
                                feedback.set(Some(Err(e)));
                            }
                        }
                    });
                },
                if saving() {
                    span { class: "loading-spinner inline" }
                }
                "Save preferences"
            }

            Separator {}
        }
    }
}
