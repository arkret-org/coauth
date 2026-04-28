use dioxus::prelude::*;

use crate::api::types::{MatrixUser, PatchViewerProfileResponse, UserProfile};

#[component]
pub fn UserGreeting(
    matrix: MatrixUser,
    profile: UserProfile,
    display_name_change_allowed: bool,
    on_edit: EventHandler,
) -> Element {
    let display_name = profile
        .display_name
        .clone()
        .or_else(|| matrix.display_name.clone());
    let initial = display_name
        .as_ref()
        .and_then(|name| name.chars().next())
        .or_else(|| matrix.mxid.chars().nth(1))
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    let avatar_url = profile.avatar_url.clone();

    rsx! {
        div { class: "user-greeting",
            if let Some(ref url) = avatar_url {
                img {
                    class: "user-avatar",
                    src: "{url}",
                    alt: "Avatar",
                }
            } else {
                div { class: "user-avatar", "{initial}" }
            }
            div { class: "user-meta",
                if let Some(display_name) = display_name {
                    span { class: "text-lg font-semibold", "{display_name}" }
                    span { class: "user-mxid", "{matrix.mxid}" }
                } else {
                    span { class: "text-lg font-semibold", "{matrix.mxid}" }
                }
            }
            if display_name_change_allowed {
                button {
                    class: "btn btn-tertiary btn-sm",
                    onclick: move |_| on_edit.call(()),
                    "Edit"
                }
            }
        }
    }
}

#[component]
pub fn EditProfileDialog(
    open: Signal<bool>,
    profile: UserProfile,
    matrix: MatrixUser,
    on_saved: EventHandler<PatchViewerProfileResponse>,
) -> Element {
    let mut display_name_value = use_signal(|| profile.display_name.clone().unwrap_or_default());
    let mut preferred_locale_value =
        use_signal(|| profile.preferred_locale.clone().unwrap_or_default());
    let mut saving = use_signal(|| false);
    let mut uploading_avatar = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut current_avatar_url = use_signal(|| profile.avatar_url.clone());

    let avatar_initial = profile
        .display_name
        .as_ref()
        .or(matrix.display_name.as_ref())
        .and_then(|name| name.chars().next())
        .or_else(|| matrix.mxid.chars().nth(1))
        .unwrap_or('?')
        .to_uppercase()
        .to_string();

    rsx! {
        div {
            class: "dialog-overlay",
            onclick: move |_| open.set(false),
            div {
                class: "dialog-content",
                onclick: move |e| e.stop_propagation(),

                h3 { class: "dialog-title", "Edit profile" }

                // Avatar section with upload
                div { class: "flex flex-col items-center gap-3",
                    if let Some(ref url) = *current_avatar_url.read() {
                        img {
                            class: "user-avatar self-center",
                            style: "width: 88px; height: 88px; object-fit: cover;",
                            src: "{url}",
                            alt: "Avatar",
                        }
                    } else {
                        div { class: "user-avatar self-center",
                            style: "width: 88px; height: 88px; font-size: 32px;",
                            "{avatar_initial}"
                        }
                    }
                    // Hidden file input — clicked programmatically by the
                    // "Upload avatar" button. The change handler reads the
                    // selected file and posts it to /api/v1/viewer/avatar.
                    input {
                        id: "user-greeting-avatar-input",
                        r#type: "file",
                        accept: "image/png,image/jpeg,image/gif,image/webp",
                        style: "display: none;",
                        onchange: move |evt| {
                            uploading_avatar.set(true);
                            error.set(None);
                            // Pull the file out of the DOM input directly via
                            // web_sys (Dioxus's FileEngine path is awkward
                            // when we also need to POST it via FormData).
                            spawn(async move {
                                let _ = evt; // silence unused warning
                                match upload_selected_avatar().await {
                                    Ok(Some(url)) => {
                                        current_avatar_url.set(Some(url));
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        error.set(Some(format!("Avatar upload failed: {e}")));
                                    }
                                }
                                uploading_avatar.set(false);
                            });
                        },
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        r#type: "button",
                        disabled: uploading_avatar(),
                        onclick: move |_| {
                            #[cfg(target_arch = "wasm32")]
                            {
                                use wasm_bindgen::JsCast;
                                if let Some(window) = web_sys::window()
                                    && let Some(document) = window.document()
                                    && let Some(el) = document.get_element_by_id("user-greeting-avatar-input")
                                    && let Ok(input) = el.dyn_into::<web_sys::HtmlInputElement>()
                                {
                                    input.click();
                                }
                            }
                        },
                        if uploading_avatar() {
                            span { class: "loading-spinner inline" }
                            "Uploading..."
                        } else {
                            "Upload avatar"
                        }
                    }
                }

                if let Some(err) = error.read().clone() {
                    div { class: "alert alert-critical",
                        p { class: "alert-title", "Error" }
                        p { "{err}" }
                    }
                }

                form {
                    class: "form-root",
                    onsubmit: move |e| {
                        e.stop_propagation();
                        let display_name = display_name_value.to_string();
                        let preferred_locale = preferred_locale_value.to_string();
                        let avatar_url = current_avatar_url.read().clone();
                        saving.set(true);
                        error.set(None);
                        spawn(async move {
                            let response = crate::api::api_patch::<PatchViewerProfileResponse>(
                                "/viewer/profile",
                                serde_json::json!({
                                    "display_name": if display_name.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(display_name) },
                                    "avatar_url": match avatar_url {
                                        Some(url) => serde_json::Value::String(url),
                                        None => serde_json::Value::Null,
                                    },
                                    "preferred_locale": if preferred_locale.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(preferred_locale) },
                                }),
                            ).await;

                            saving.set(false);
                            match response {
                                Ok(data) => {
                                    on_saved.call(data);
                                    open.set(false);
                                }
                                Err(err_msg) => error.set(Some(err_msg)),
                            }
                        });
                    },

                    div { class: "form-field",
                        label { class: "form-label", "Display name" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            autocomplete: "name",
                            value: "{display_name_value}",
                            oninput: move |e| display_name_value.set(e.value()),
                        }
                        span { class: "form-help", "Your display name is shown to other users." }
                    }

                    div { class: "form-field",
                        label { class: "form-label", "Preferred locale" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            placeholder: "zh-CN",
                            value: "{preferred_locale_value}",
                            oninput: move |e| preferred_locale_value.set(e.value()),
                        }
                        span { class: "form-help", "Used for localized notifications and future profile settings." }
                    }

                    div { class: "form-field",
                        label { class: "form-label", "Matrix ID" }
                        input {
                            class: "form-input",
                            r#type: "text",
                            value: "{matrix.mxid}",
                            readonly: true,
                        }
                    }

                    button {
                        class: "btn btn-primary",
                        r#type: "submit",
                        disabled: saving(),
                        if saving() {
                            span { class: "loading-spinner inline" }
                        }
                        "Save"
                    }
                }

                button {
                    class: "btn btn-tertiary",
                    onclick: move |_| open.set(false),
                    "Cancel"
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn upload_selected_avatar() -> Result<Option<String>, String> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{FormData, HtmlInputElement, Request, RequestCredentials, RequestInit, Response};

    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let document = window.document().ok_or_else(|| "no document".to_string())?;
    let input: HtmlInputElement = document
        .get_element_by_id("user-greeting-avatar-input")
        .and_then(|el| el.dyn_into::<HtmlInputElement>().ok())
        .ok_or_else(|| "file input not found".to_string())?;
    let files = input.files().ok_or_else(|| "no FileList".to_string())?;
    let Some(file) = files.get(0) else {
        return Ok(None);
    };

    if file.size() > 5.0 * 1024.0 * 1024.0 {
        // Reset the input so the same file can be picked again after the
        // user fixes it.
        input.set_value("");
        return Err("File too large (max 5 MB)".to_string());
    }

    let form_data = FormData::new().map_err(|_| "failed to build FormData".to_string())?;
    // Salvo's `req.file("avatar")` only matches multipart entries that
    // include a filename. `append_with_blob` would post the file as a
    // plain field, so we explicitly pass the filename here.
    let filename = {
        let name = file.name();
        if name.is_empty() {
            "avatar".to_string()
        } else {
            name
        }
    };
    form_data
        .append_with_blob_and_filename("avatar", &file, &filename)
        .map_err(|_| "failed to append file".to_string())?;

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_credentials(RequestCredentials::SameOrigin);
    init.set_body(&JsValue::from(form_data));

    let request = Request::new_with_str_and_init("/api/v1/viewer/avatar", &init)
        .map_err(|e| format!("failed to build request: {e:?}"))?;

    let response_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("network error: {e:?}"))?;
    let response: Response = response_value
        .dyn_into()
        .map_err(|_| "invalid Response".to_string())?;

    // Reset so picking the same file again triggers a fresh onchange.
    input.set_value("");

    if !response.ok() {
        let text = JsFuture::from(
            response
                .text()
                .map_err(|e| format!("failed to read body: {e:?}"))?,
        )
        .await
        .map_err(|e| format!("failed to read body: {e:?}"))?;
        return Err(text
            .as_string()
            .unwrap_or_else(|| format!("HTTP {}", response.status())));
    }

    let json_value = JsFuture::from(
        response
            .json()
            .map_err(|e| format!("invalid JSON: {e:?}"))?,
    )
    .await
    .map_err(|e| format!("invalid JSON: {e:?}"))?;

    let avatar_url = js_sys::Reflect::get(&json_value, &JsValue::from_str("avatar_url"))
        .ok()
        .and_then(|v| v.as_string())
        .or_else(|| {
            js_sys::Reflect::get(&json_value, &JsValue::from_str("avatarUrl"))
                .ok()
                .and_then(|v| v.as_string())
        });
    Ok(avatar_url)
}

#[cfg(not(target_arch = "wasm32"))]
async fn upload_selected_avatar() -> Result<Option<String>, String> {
    Err("not supported on this platform".to_string())
}
