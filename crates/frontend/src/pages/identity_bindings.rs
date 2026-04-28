use dioxus::prelude::*;

use crate::{
    api::types::{LinkedAccountsResponse, ProvidersResponse},
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
};

/// Identity bindings page.
///
/// Fetches `GET /api/v1/linked-accounts` and displays each linked upstream
/// account with provider name and subject. The "Unlink" button calls
/// `DELETE /api/v1/linked-accounts/{id}` to remove the link.
#[component]
pub fn IdentityBindings() -> Element {
    let mut data = use_resource(|| async {
        crate::api::api_get::<LinkedAccountsResponse>("/linked-accounts").await
    });
    let providers_data = use_resource(|| async {
        crate::api::api_get::<ProvidersResponse>("/auth/providers").await
    });
    let mut feedback: Signal<Option<Result<String, String>>> = use_signal(|| None);
    let mut unlinking_id: Signal<Option<String>> = use_signal(|| None);
    let binding = data.read();

    match &*binding {
        Some(Ok(result)) => {
            let accounts = &result.accounts;
            let account_count = accounts.len();

            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Connected Accounts" }

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

                    // Linked accounts
                    div { class: "flex flex-col gap-2",
                        h4 { class: "text-md font-semibold", "Linked accounts" }
                        p { class: "text-md text-secondary",
                            "External identity providers currently linked to your account. You can sign in with any of these."
                        }
                    }

                    if accounts.is_empty() {
                        p { class: "text-md text-secondary", style: "font-style: italic;",
                            "No external accounts linked."
                        }
                    } else {
                        div { class: "flex flex-col gap-3",
                            for account in accounts.iter() {
                                {
                                    let account_id = account.id.clone();
                                    let display_name = account.human_account_name.clone()
                                        .or_else(|| Some(account.subject.clone()))
                                        .unwrap_or_default();
                                    let provider_label = account.provider_name.clone()
                                        .or_else(|| account.provider_brand.clone())
                                        .unwrap_or_else(|| "External provider".to_string());
                                    let is_unlinking = unlinking_id.read().as_deref() == Some(&account_id);
                                    // Prevent unlinking the last linked account
                                    let can_unlink = account_count > 1;
                                    rsx! {
                                        div {
                                            class: "flex items-center justify-between p-3 rounded-lg border",
                                            div { class: "flex flex-col gap-1",
                                                span { class: "text-md font-semibold", "{provider_label}" }
                                                span { class: "text-sm text-secondary", "{display_name}" }
                                            }
                                            button {
                                                class: "btn btn-destructive btn-sm",
                                                disabled: !can_unlink || unlinking_id.read().is_some(),
                                                title: if !can_unlink { "Cannot unlink last connected account" } else { "Unlink this account" },
                                                onclick: {
                                                    let aid = account_id.clone();
                                                    let label = provider_label.clone();
                                                    move |_| {
                                                        let aid = aid.clone();
                                                        let label = label.clone();
                                                        unlinking_id.set(Some(aid.clone()));
                                                        feedback.set(None);
                                                        spawn(async move {
                                                            let result = crate::api::api_delete::<crate::api::types::UnlinkResponse>(
                                                                &format!("/linked-accounts/{aid}"),
                                                            ).await;
                                                            unlinking_id.set(None);
                                                            match result {
                                                                Ok(_) => {
                                                                    feedback.set(Some(Ok(format!("{label} unlinked."))));
                                                                    data.restart();
                                                                }
                                                                Err(e) => {
                                                                    feedback.set(Some(Err(e)));
                                                                }
                                                            }
                                                        });
                                                    }
                                                },
                                                if is_unlinking { "Unlinking…" } else { "Unlink" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Separator { kind: SeparatorKind::Section }

                    // Link new provider — only shown when at least one configured
                    // provider is not yet linked to this account.
                    if let Some(Ok(providers)) = &*providers_data.read() {
                        {
                            let linked_ids: Vec<String> = accounts
                                .iter()
                                .map(|a| a.provider_id.clone())
                                .collect();
                            let unlinked: Vec<_> = providers
                                .providers
                                .iter()
                                .filter(|p| !linked_ids.contains(&p.id))
                                .collect();
                            if !unlinked.is_empty() {
                                rsx! {
                                    div { class: "flex flex-col gap-2",
                                        h4 { class: "text-md font-semibold", "Link a new provider" }
                                        p { class: "text-md text-secondary",
                                            "Connect an additional external account to enable more sign-in options."
                                        }
                                    }
                                    div { class: "flex flex-wrap gap-2",
                                        for provider in unlinked.iter() {
                                            a {
                                                class: "btn btn-secondary btn-sm",
                                                href: "{provider.authorize_url}",
                                                "Link {provider.human_name.clone().unwrap_or_else(|| provider.id.clone())}"
                                            }
                                        }
                                    }
                                    Separator {}
                                }
                            } else {
                                rsx! {}
                            }
                        }
                    }
                }
            }
        }
        Some(Err(e)) => rsx! {
            div { class: "alert alert-critical", "{e}" }
        },
        None => rsx! { LoadingScreen {} },
    }
}
