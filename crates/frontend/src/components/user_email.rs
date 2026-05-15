use dioxus::prelude::*;

use crate::api::types::{RemoveEmailStatus, UserEmail};

#[component]
pub fn UserEmailItem(email: UserEmail, on_removed: Option<EventHandler<String>>) -> Element {
    let is_confirmed = email.confirmed_at.is_some();
    let mut removing = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut confirm_open = use_signal(|| false);
    let email_id = email.id.clone();
    let email_display = email.email.clone();

    rsx! {
        div { class: "user-email",
            div { class: "flex items-center gap-2 flex-1",
                span { class: "email-address", "{email.email}" }
                if email.is_primary {
                    span { class: "email-badge primary", "Primary" }
                }
                if is_confirmed {
                    span { class: "email-badge primary", "Verified" }
                } else {
                    span { class: "email-badge", "Unverified" }
                }
            }

            if let Some(ref err) = *error.read() {
                span { class: "text-critical text-sm", "{err}" }
            }

            if confirm_open() {
                div { class: "flex items-center gap-2",
                    span { class: "text-sm", "Remove {email_display}?" }
                    button {
                        class: "btn btn-destructive btn-sm",
                        disabled: removing(),
                        onclick: {
                            let eid = email_id.clone();
                            move |_| {
                                let eid = eid.clone();
                                removing.set(true);
                                error.set(None);
                                spawn(async move {
                                    let result = crate::api::api_delete::<crate::api::types::RemoveEmailPayload>(
                                        &format!("/user-emails/{eid}"),
                                    ).await;
                                    removing.set(false);
                                    match result {
                                        Ok(data) => match data.status {
                                            RemoveEmailStatus::Removed => {
                                                if let Some(handler) = on_removed {
                                                    handler.call(eid.clone());
                                                }
                                            }
                                            RemoveEmailStatus::NotFound => {
                                                error.set(Some("Email not found.".to_owned()));
                                            }
                                        },
                                        Err(e) => {
                                            error.set(Some(e));
                                        }
                                    }
                                    confirm_open.set(false);
                                });
                            }
                        },
                        if removing() {
                            span { class: "loading-spinner inline" }
                        }
                        "Confirm"
                    }
                    button {
                        class: "btn btn-tertiary btn-sm",
                        disabled: removing(),
                        onclick: move |_| confirm_open.set(false),
                        "Cancel"
                    }
                }
            } else {
                button {
                    class: "btn btn-destructive btn-sm",
                    onclick: move |_| confirm_open.set(true),
                    "Remove"
                }
            }
        }
    }
}

#[component]
pub fn UserEmailList(emails: Vec<UserEmail>, email_change_allowed: bool) -> Element {
    let _ = email_change_allowed;
    let mut items = use_signal(|| emails.clone());

    rsx! {
        div { class: "flex flex-col",
            for email in items.read().iter() {
                UserEmailItem {
                    key: "{email.id}",
                    email: email.clone(),
                    on_removed: move |removed_id: String| {
                        items.write().retain(|item| item.id != removed_id);
                    },
                }
            }
        }
    }
}
