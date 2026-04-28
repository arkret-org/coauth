use dioxus::prelude::*;

use crate::{
    api::types::Oauth2ClientDetail,
    components::{layout::Layout, loading::LoadingScreen},
    pages::Route,
};

#[component]
pub fn ClientDetail(id: String) -> Element {
    let id_clone = id.clone();
    let data = use_resource(move || {
        let id = id_clone.clone();
        async move {
            crate::api::api_get::<Oauth2ClientDetail>(&format!("/oauth2-clients/{}", id)).await
        }
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(client)) => rsx! {
            Layout {
                ClientDetailView {
                    client_id: client.client_id.clone(),
                    client_name: client.client_name.clone(),
                    client_uri: client.client_uri.clone(),
                    tos_uri: client.tos_uri.clone(),
                    policy_uri: client.policy_uri.clone(),
                    logo_uri: client.logo_uri.clone(),
                }
            }
        },
        Some(Err(e)) => rsx! {
            Layout {
                div { class: "alert alert-critical", "{e}" }
            }
        },
        None => rsx! { LoadingScreen {} },
    }
}

#[component]
fn ClientDetailView(
    client_id: String,
    client_name: Option<String>,
    client_uri: Option<String>,
    tos_uri: Option<String>,
    policy_uri: Option<String>,
    logo_uri: Option<String>,
) -> Element {
    let name = client_name
        .clone()
        .unwrap_or_else(|| "Unknown client".to_string());

    rsx! {
        div { class: "flex flex-col gap-6",
            // Back link
            Link {
                class: "text-sm",
                to: Route::Sessions {},
                "← Back to sessions"
            }

            // Header with optional logo
            div { class: "flex items-center gap-4",
                if let Some(ref uri) = logo_uri {
                    img {
                        class: "client-logo",
                        src: "{uri}",
                        alt: "{name}",
                    }
                }
                h3 { class: "heading-xs", "{name}" }
            }

            // Client info
            ul { class: "session-metadata",
                li {
                    div { class: "key", "Client ID" }
                    div { class: "value", "{client_id}" }
                }

                if let Some(ref uri) = client_uri {
                    li {
                        div { class: "key", "Client URI" }
                        div { class: "value",
                            a {
                                href: "{uri}",
                                target: "_blank",
                                rel: "noopener noreferrer",
                                "{uri}"
                            }
                        }
                    }
                }

                if let Some(ref uri) = tos_uri {
                    li {
                        div { class: "key", "Terms of Service" }
                        div { class: "value",
                            a {
                                href: "{uri}",
                                target: "_blank",
                                rel: "noopener noreferrer",
                                "{uri}"
                            }
                        }
                    }
                }

                if let Some(ref uri) = policy_uri {
                    li {
                        div { class: "key", "Privacy Policy" }
                        div { class: "value",
                            a {
                                href: "{uri}",
                                target: "_blank",
                                rel: "noopener noreferrer",
                                "{uri}"
                            }
                        }
                    }
                }
            }
        }
    }
}
