use dioxus::prelude::*;

use super::session_card::*;
use crate::{
    api::types::{BrowserSession as BrowserSessionData, DeviceType},
    pages::Route,
};

fn session_display_name(session: &BrowserSessionData) -> String {
    if let Some(ref name) = session.display_name {
        return name.clone();
    }
    if let Some(ref ua) = session.user_agent {
        let mut parts = Vec::new();
        if let Some(ref name) = ua.name {
            parts.push(name.clone());
        }
        if let Some(ref model) = ua.model {
            parts.push(model.clone());
        }
        if !parts.is_empty() {
            return parts.join(" - ");
        }
    }
    "Unknown session".to_string()
}

#[component]
pub fn BrowserSessionCard(session: BrowserSessionData, is_current: Option<bool>) -> Element {
    let device_type = session
        .user_agent
        .as_ref()
        .map(|ua| ua.device_type.clone())
        .unwrap_or(DeviceType::Unknown);
    let name = session_display_name(&session);
    let os = session.user_agent.as_ref().and_then(|ua| ua.os.clone());

    rsx! {
        SessionCardRoot {
            SessionCardLinkBody {
                to: Route::SessionDetail { id: session.id.clone() },
                SessionCardHeader { device_type: device_type,
                    SessionCardName { name: name }
                    if let Some(ref os_name) = os {
                        span { class: "text-sm text-secondary", "{os_name}" }
                    }
                }
                SessionCardMetadata {
                    if is_current.unwrap_or(false) {
                        SessionCardInfo { label: "Status".to_string(),
                            span { class: "text-sm", "Current session" }
                        }
                    }
                    if let Some(ref last_active) = session.last_active_at {
                        SessionCardInfo { label: "Last active".to_string(),
                            crate::components::last_active::LastActive { datetime: last_active.clone() }
                        }
                    }
                    if let Some(ref ip) = session.last_active_ip {
                        SessionCardInfo { label: "IP address".to_string(),
                            span { class: "text-sm", "{ip}" }
                        }
                    }
                }
            }
        }
    }
}
