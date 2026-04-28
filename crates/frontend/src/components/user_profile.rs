use dioxus::prelude::*;

#[component]
pub fn AddEmailForm(on_add: Option<EventHandler<String>>) -> Element {
    let mut email_value = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    rsx! {
        form {
            class: "form-root",
            onsubmit: move |e| {
                e.stop_propagation();
                let email = email_value.to_string();
                if email.is_empty() {
                    return;
                }
                submitting.set(true);
                error.set(None);
                let on_add = on_add;
                spawn(async move {
                    let result = crate::api::api_post::<crate::api::types::AddEmailPayload>(
                        "/email-auth/start",
                        serde_json::json!({
                            "email": email,
                            "password": serde_json::Value::Null,
                            "language": "en",
                        }),
                    ).await;
                    submitting.set(false);
                    match result {
                        Ok(data) => {
                            match data.status {
                                crate::api::types::AddEmailStatus::Added => {
                                    email_value.set(String::new());
                                    if let (Some(handler), Some(email_obj)) = (on_add, &data.email) {
                                        handler.call(email_obj.id.clone());
                                    }
                                }
                                crate::api::types::AddEmailStatus::Exists => {
                                    error.set(Some("This email address is already in use.".to_string()));
                                }
                                crate::api::types::AddEmailStatus::Invalid => {
                                    error.set(Some("Invalid email address.".to_string()));
                                }
                                crate::api::types::AddEmailStatus::Denied => {
                                    let violations = data.violations.unwrap_or_default().join(", ");
                                    error.set(Some(format!("Email denied: {violations}")));
                                }
                            }
                        }
                        Err(e) => {
                            error.set(Some(e));
                        }
                    }
                });
            },

            if let Some(ref err) = *error.read() {
                div { class: "alert alert-critical", "{err}" }
            }

            div { class: "flex gap-2 items-end",
                div { class: "form-field flex-1",
                    label { class: "form-label", "Email address" }
                    input {
                        class: "form-input",
                        r#type: "email",
                        required: true,
                        placeholder: "Enter your email",
                        value: "{email_value}",
                        oninput: move |e| email_value.set(e.value()),
                    }
                }
                button {
                    class: "btn btn-primary",
                    r#type: "submit",
                    disabled: submitting(),
                    if submitting() {
                        span { class: "loading-spinner inline" }
                    }
                    "Add"
                }
            }
        }
    }
}
