use dioxus::prelude::*;

use super::session_card::*;
use crate::{
    api::types::{DeviceType, Oauth2Session as Oauth2SessionData},
    pages::Route,
};

fn session_display_name(session: &Oauth2SessionData) -> String {
    if let Some(ref name) = session.display_name {
        return name.clone();
    }
    if let Some(ref client) = session.client {
        if let Some(ref name) = client.client_name {
            return name.clone();
        }
        return client.client_id.clone();
    }
    "Unknown app".to_string()
}

#[component]
pub fn OAuth2SessionCard(session: Oauth2SessionData) -> Element {
    let device_type = session
        .user_agent
        .as_ref()
        .map(|ua| ua.device_type.clone())
        .unwrap_or(DeviceType::Unknown);
    let name = session_display_name(&session);
    let client_name = session
        .client
        .as_ref()
        .and_then(|c| c.client_name.clone())
        .unwrap_or_else(|| "Unknown client".to_string());
    let logo_uri = session.client.as_ref().and_then(|c| c.logo_uri.clone());

    rsx! {
        SessionCardRoot {
            SessionCardLinkBody {
                to: Route::SessionDetail { id: session.id.clone() },
                SessionCardHeader { device_type: device_type,
                    SessionCardName { name: name }
                    SessionCardClient { name: client_name, logo_uri: logo_uri }
                }
                SessionCardMetadata {
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
