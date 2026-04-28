use dioxus::prelude::*;

use crate::{
    api::types::WorkflowInboxResponse,
    components::{
        loading::LoadingScreen,
        separator::{Separator, SeparatorKind},
    },
};

/// Workflow inbox page.
///
/// Fetches `GET /api/v1/viewer/workflow-inbox` and displays a list of
/// pending flow sessions the user needs to act on.
#[component]
pub fn WorkflowInbox() -> Element {
    let data = use_resource(|| async {
        crate::api::api_get::<WorkflowInboxResponse>("/viewer/workflow-inbox").await
    });
    let binding = data.read();

    match &*binding {
        Some(Ok(inbox)) => {
            rsx! {
                div { class: "flex flex-col gap-6",
                    h3 { class: "heading-xs", "Workflow Inbox" }

                    if inbox.pending.is_empty() {
                        p { class: "text-md text-secondary",
                            "No pending workflows. You're all caught up!"
                        }
                    } else {
                        p { class: "text-md",
                            "{inbox.total} pending workflow(s)"
                        }

                        for item in inbox.pending.iter() {
                            div { class: "flex flex-col gap-1",
                                Separator { kind: SeparatorKind::Section }
                                h4 { class: "text-md font-semibold", "{item.flow_title}" }
                                p { class: "text-sm text-secondary",
                                    "Flow: {item.flow_slug} — Stage: {item.current_stage}"
                                }
                                p { class: "text-sm text-secondary",
                                    "Started: {item.started_at}"
                                }
                            }
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
