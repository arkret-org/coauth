// Copyright (c) 2026 Cokret Authors. Licensed under the Apache License,
// Version 2.0; see LICENSE-APACHE for details.

//! Admin page: edit per-locale display name + description for an
//! OAuth client.
//!
//! This is the round-26 i18n editor backed by `POST
//! /api/admin/v1/oauth/clients/{id}/i18n`. The page renders the existing
//! locale rows (loaded via `GET .../i18n`) and a small form for adding /
//! updating one locale at a time. Submitting an empty `display_name`
//! clears the entry for that locale (matches the backend semantics).

use std::collections::BTreeMap;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    components::{layout::Layout, loading::LoadingScreen},
    config::api_base_url,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct I18nEntry {
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct I18nResponse {
    data: BTreeMap<String, I18nEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct UpsertBody<'a> {
    locale: &'a str,
    display_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

/// Pre-populated dropdown of supported locales. en + zh-CN minimum per
/// round-26 spec; other entries are convenience for admins editing
/// translations against the consent screen renderer.
const SUPPORTED_LOCALES: &[(&str, &str)] = &[
    ("en", "English"),
    ("zh-CN", "简体中文 (zh-CN)"),
    ("zh-Hant", "繁體中文 (zh-Hant)"),
    ("ja", "日本語 (ja)"),
    ("ko", "한국어 (ko)"),
    ("es", "Español (es)"),
    ("fr", "Français (fr)"),
    ("de", "Deutsch (de)"),
];

#[component]
pub fn AdminOAuthClientI18n(id: String) -> Element {
    let client_id = id.clone();
    let mut entries = use_signal(BTreeMap::<String, I18nEntry>::new);
    let mut loading = use_signal(|| true);
    let mut load_error = use_signal(|| Option::<String>::None);
    let mut form_locale = use_signal(|| "en".to_owned());
    let mut form_display_name = use_signal(String::new);
    let mut form_description = use_signal(String::new);
    let mut submit_state = use_signal(|| Option::<Result<String, String>>::None);

    // Initial fetch.
    {
        let client_id = client_id.clone();
        use_effect(move || {
            let client_id = client_id.clone();
            spawn(async move {
                match fetch_entries(&client_id).await {
                    Ok(map) => {
                        entries.set(map);
                        loading.set(false);
                    }
                    Err(err) => {
                        load_error.set(Some(err));
                        loading.set(false);
                    }
                }
            });
        });
    }

    let on_submit = {
        let client_id = client_id.clone();
        move |evt: FormEvent| {
            evt.prevent_default();
            let client_id = client_id.clone();
            let locale = form_locale.read().clone();
            let display_name = form_display_name.read().clone();
            let description = form_description.read().clone();
            spawn(async move {
                submit_state.set(None);
                let desc_opt: Option<&str> = if description.trim().is_empty() {
                    None
                } else {
                    Some(description.as_str())
                };
                let body = UpsertBody {
                    locale: locale.as_str(),
                    display_name: display_name.as_str(),
                    description: desc_opt,
                };
                match upsert_entry(&client_id, &body).await {
                    Ok(map) => {
                        entries.set(map);
                        submit_state.set(Some(Ok(format!("Saved locale {locale}"))));
                    }
                    Err(err) => {
                        submit_state.set(Some(Err(err)));
                    }
                }
            });
        }
    };

    if *loading.read() {
        return rsx! { LoadingScreen {} };
    }

    rsx! {
        Layout {
            div { class: "flex flex-col gap-6",
                h3 { class: "heading-xs", "OAuth Client i18n editor" }
                p { class: "text-sm",
                    "Client ID: "
                    code { "{client_id}" }
                }

                if let Some(err) = load_error.read().clone() {
                    div { class: "alert alert-critical", "{err}" }
                }

                // Existing entries.
                section {
                    h4 { class: "heading-2xs", "Existing locales" }
                    if entries.read().is_empty() {
                        p { class: "text-sm muted", "No localised entries yet." }
                    } else {
                        ul { class: "session-metadata",
                            for (locale , entry) in entries.read().iter() {
                                li {
                                    div { class: "key", "{locale}" }
                                    div { class: "value",
                                        div { strong { "{entry.display_name}" } }
                                        if let Some(desc) = entry.description.as_ref() {
                                            div { class: "muted text-sm", "{desc}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Upsert form.
                section {
                    h4 { class: "heading-2xs", "Add / update entry" }
                    form { onsubmit: on_submit, class: "flex flex-col gap-3",
                        label {
                            span { "Locale" }
                            select {
                                value: "{form_locale.read()}",
                                onchange: move |evt| form_locale.set(evt.value()),
                                for (tag , label) in SUPPORTED_LOCALES.iter() {
                                    option { value: "{tag}", "{label}" }
                                }
                            }
                        }
                        label {
                            span { "Display name" }
                            input {
                                r#type: "text",
                                value: "{form_display_name.read()}",
                                oninput: move |evt| form_display_name.set(evt.value()),
                                placeholder: "Empty value clears this locale",
                            }
                        }
                        label {
                            span { "Description (optional)" }
                            textarea {
                                value: "{form_description.read()}",
                                oninput: move |evt| form_description.set(evt.value()),
                                rows: "3",
                            }
                        }
                        button { r#type: "submit", class: "button primary", "Save" }
                    }

                    match submit_state.read().clone() {
                        Some(Ok(msg)) => rsx! {
                            div { class: "alert alert-success", "{msg}" }
                        },
                        Some(Err(err)) => rsx! {
                            div { class: "alert alert-critical", "{err}" }
                        },
                        None => rsx! {},
                    }
                }
            }
        }
    }
}

async fn fetch_entries(client_id: &str) -> Result<BTreeMap<String, I18nEntry>, String> {
    let url = format!(
        "{}/admin/v1/oauth/clients/{}/i18n",
        api_base_url(),
        client_id
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {} returned {}", url, resp.status()));
    }
    let body: I18nResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    Ok(body.data)
}

async fn upsert_entry(
    client_id: &str,
    body: &UpsertBody<'_>,
) -> Result<BTreeMap<String, I18nEntry>, String> {
    let url = format!(
        "{}/admin/v1/oauth/clients/{}/i18n",
        api_base_url(),
        client_id
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("POST {url} -> {status}: {text}"));
    }
    let resp_body: I18nResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    Ok(resp_body.data)
}
