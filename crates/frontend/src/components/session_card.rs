use dioxus::prelude::*;

use crate::{api::types::DeviceType, pages::Route};

#[component]
pub fn SessionCardRoot(children: Element) -> Element {
    rsx! {
        section { class: "session-card-root", {children} }
    }
}

#[component]
pub fn SessionCardBody(
    compact: Option<bool>,
    disabled: Option<bool>,
    children: Element,
) -> Element {
    let mut class = "session-card".to_string();
    if compact.unwrap_or(false) {
        class.push_str(" compact");
    }
    if disabled.unwrap_or(false) {
        class.push_str(" disabled");
    }

    rsx! {
        div { class: "{class}", {children} }
    }
}

#[component]
pub fn SessionCardLinkBody(
    to: Route,
    compact: Option<bool>,
    disabled: Option<bool>,
    children: Element,
) -> Element {
    let mut class = "session-card".to_string();
    if compact.unwrap_or(false) {
        class.push_str(" compact");
    }
    if disabled.unwrap_or(false) {
        class.push_str(" disabled");
    }

    rsx! {
        Link { class: "{class}", to: to, {children} }
    }
}

#[component]
pub fn SessionCardHeader(device_type: DeviceType, children: Element) -> Element {
    let icon = match device_type {
        DeviceType::Pc => "🖥",
        DeviceType::Mobile => "📱",
        DeviceType::Unknown => "❓",
    };

    rsx! {
        header { class: "card-header",
            div { class: "device-icon", "{icon}" }
            div { class: "content", {children} }
        }
    }
}

#[component]
pub fn SessionCardName(name: String) -> Element {
    rsx! {
        div { class: "session-name", "{name}" }
    }
}

#[component]
pub fn SessionCardClient(name: String, logo_uri: Option<String>) -> Element {
    rsx! {
        div { class: "session-client",
            div { class: "client-avatar",
                if let Some(ref uri) = logo_uri {
                    img { src: "{uri}", alt: "{name}" }
                } else {
                    {name.chars().next().unwrap_or('?').to_uppercase().to_string()}
                }
            }
            "{name}"
        }
    }
}

#[component]
pub fn SessionCardMetadata(children: Element) -> Element {
    rsx! {
        ul { class: "session-metadata", {children} }
    }
}

#[component]
pub fn SessionCardInfo(label: String, children: Element) -> Element {
    rsx! {
        li {
            div { class: "key", "{label}" }
            div { class: "value", {children} }
        }
    }
}

#[component]
pub fn SessionCardAction(children: Element) -> Element {
    rsx! {
        div { class: "session-action", {children} }
    }
}
