use dioxus::prelude::*;

use crate::api::types::SiteConfig;

#[component]
pub fn Footer(site_config: SiteConfig) -> Element {
    let has_links = site_config.policy_uri.is_some() || site_config.tos_uri.is_some();

    rsx! {
        footer { class: "legal-footer",
            if has_links {
                nav {
                    if let Some(ref policy_uri) = site_config.policy_uri {
                        a { href: "{policy_uri}", title: "Link to the service privacy policy",
                            "Privacy policy"
                        }
                    }
                    if site_config.policy_uri.is_some() && site_config.tos_uri.is_some() {
                        span { class: "dot-separator", "•" }
                    }
                    if let Some(ref tos_uri) = site_config.tos_uri {
                        a { href: "{tos_uri}", title: "Link to the service terms and conditions",
                            "Terms and conditions"
                        }
                    }
                }
            }
            if let Some(ref imprint) = site_config.imprint {
                p { class: "imprint", "{imprint}" }
            }
        }
    }
}
