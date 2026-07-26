use dioxus::prelude::*;

use crate::api::types::{
    PasskeyListOutcome, PasskeyMutationOutcome, PasskeySummary, SecuritySummaryOutcome,
};
use crate::components::loading::LoadingScreen;
use crate::components::separator::{Separator, SeparatorKind};
use crate::pages::Route;

/// Security center page.
///
/// Fetches `GET /_coauth/self/viewer/security` and displays:
/// - Password status (set / not set)
/// - Active sessions count
/// - Verified emails count
/// - Linked providers count
#[component]
pub fn SecurityCenter() -> Element {
    let data = use_resource(|| async {
        crate::api::api_get::<SecuritySummaryOutcome>("/self/viewer/security").await
    });
    let mut passkeys = use_resource(|| async {
        crate::api::api_get::<PasskeyListOutcome>("/self/passkeys").await
    });
    let mut new_passkey_label = use_signal(String::new);
    let mut passkey_busy = use_signal(|| false);
    let mut passkey_error = use_signal(|| None::<String>);
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

                    div { class: "flex flex-col gap-3",
                        h4 { class: "text-md font-semibold", "Passkeys" }
                        p { class: "text-md text-secondary",
                            "Passkeys protect this Coauth account from phishing. They do not replace your Arkret DID principal recovery secret or authorize a new long-lived device."
                        }

                        if let Some(message) = passkey_error.read().as_ref() {
                            div {
                                class: "alert alert-critical",
                                role: "alert",
                                "aria-live": "assertive",
                                "{message}"
                            }
                        }

                        match &*passkeys.read() {
                            Some(Ok(outcome)) if outcome.passkeys.is_empty() => rsx! {
                                p { class: "text-md text-secondary", "No passkeys are registered yet." }
                            },
                            Some(Ok(outcome)) => rsx! {
                                div { class: "flex flex-col gap-3",
                                    for passkey in outcome.passkeys.iter() {
                                        PasskeyItem {
                                            key: "{passkey.id}",
                                            passkey: passkey.clone(),
                                            busy: passkey_busy(),
                                            on_busy: move |value| passkey_busy.set(value),
                                            on_changed: move |_| passkeys.restart(),
                                        }
                                    }
                                }
                            },
                            Some(Err(message)) => rsx! {
                                div { class: "alert alert-critical", role: "alert", "{message}" }
                            },
                            None => rsx! { p { class: "text-md text-secondary", "Loading passkeys…" } },
                        }

                        div { class: "form-field",
                            label { class: "form-label", r#for: "new-passkey-label", "New passkey name" }
                            input {
                                id: "new-passkey-label",
                                class: "form-input",
                                r#type: "text",
                                maxlength: "80",
                                placeholder: "For example, Windows Hello",
                                value: "{new_passkey_label}",
                                disabled: passkey_busy(),
                                oninput: move |event| new_passkey_label.set(event.value()),
                            }
                        }
                        button {
                            class: "btn btn-primary btn-sm",
                            r#type: "button",
                            "data-testid": "coauth-add-passkey",
                            disabled: passkey_busy(),
                            "aria-busy": if passkey_busy() { "true" } else { "false" },
                            onclick: move |_| {
                                let label = new_passkey_label
                                    .to_string()
                                    .trim()
                                    .to_owned();
                                let label = (!label.is_empty()).then_some(label);
                                passkey_busy.set(true);
                                passkey_error.set(None);
                                spawn(async move {
                                    match crate::passkey::register(None, label).await {
                                        Ok(_) => {
                                            new_passkey_label.set(String::new());
                                            passkeys.restart();
                                        }
                                        Err(message) => {
                                            passkey_error.set(Some(message));
                                        }
                                    }
                                    passkey_busy.set(false);
                                });
                            },
                            "Add passkey"
                        }
                        p { class: "text-sm text-secondary",
                            "Adding, renaming, or removing a passkey requires a recent sign-in. If this session is too old, sign out and authenticate again first."
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

#[component]
fn PasskeyItem(
    passkey: PasskeySummary,
    busy: bool,
    on_busy: EventHandler<bool>,
    on_changed: EventHandler<()>,
) -> Element {
    let mut label = use_signal(|| passkey.label.clone().unwrap_or_default());
    let mut error = use_signal(|| None::<String>);
    let id_for_rename = passkey.id.clone();
    let id_for_revoke = passkey.id.clone();
    let input_id = format!("passkey-label-{}", passkey.id);
    let backup_label = if passkey.backup_eligible {
        if passkey.backup_state {
            "Synced passkey"
        } else {
            "Sync-capable passkey"
        }
    } else {
        "Device-bound credential"
    };

    rsx! {
        article { class: "flex flex-col gap-2",
            div { class: "flex items-center gap-2",
                strong {
                    "{passkey.label.as_deref().filter(|value| !value.is_empty()).unwrap_or(\"Unnamed passkey\")}"
                }
                span { class: "badge", "{backup_label}" }
                if passkey.user_verified {
                    span { class: "badge badge-success", "User verified" }
                }
            }
            p { class: "text-sm text-secondary",
                "Created {passkey.created_at}"
                if let Some(last_used_at) = passkey.last_used_at.as_ref() {
                    " · Last used {last_used_at}"
                }
            }
            if let Some(message) = error.read().as_ref() {
                div { class: "alert alert-critical", role: "alert", "{message}" }
            }
            div { class: "form-field",
                label { class: "form-label", r#for: "{input_id}", "Passkey name" }
                input {
                    id: "{input_id}",
                    class: "form-input",
                    r#type: "text",
                    maxlength: "80",
                    value: "{label}",
                    disabled: busy,
                    oninput: move |event| label.set(event.value()),
                }
            }
            div { class: "flex gap-2",
                button {
                    class: "btn btn-secondary btn-sm",
                    r#type: "button",
                    disabled: busy,
                    onclick: move |_| {
                        let id = id_for_rename.clone();
                        let value = label.to_string().trim().to_owned();
                        let value = (!value.is_empty()).then_some(value);
                        error.set(None);
                        on_busy.call(true);
                        spawn(async move {
                            let path = format!("/self/passkeys/{id}");
                            match crate::api::api_patch::<PasskeyMutationOutcome>(
                                &path,
                                serde_json::json!({ "label": value }),
                            )
                            .await
                            {
                                Ok(_) => on_changed.call(()),
                                Err(message) => error.set(Some(message)),
                            }
                            on_busy.call(false);
                        });
                    },
                    "Save name"
                }
                button {
                    class: "btn btn-danger btn-sm",
                    r#type: "button",
                    disabled: busy,
                    onclick: move |_| {
                        let id = id_for_revoke.clone();
                        error.set(None);
                        on_busy.call(true);
                        spawn(async move {
                            let path = format!("/self/passkeys/{id}/revoke");
                            match crate::api::api_post::<PasskeyMutationOutcome>(
                                &path,
                                serde_json::json!({}),
                            )
                            .await
                            {
                                Ok(_) => on_changed.call(()),
                                Err(message) => error.set(Some(message)),
                            }
                            on_busy.call(false);
                        });
                    },
                    "Remove"
                }
            }
        }
    }
}
