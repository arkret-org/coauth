mod account;
mod approvals;
mod auth;
mod registration;
mod security;
mod sessions;
use crate::api::types::SiteConfig;
use crate::translations::{self, UiLocale};
use crate::ui::{self, *};

pub fn init_theme() {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        let stored = window
            .local_storage()
            .ok()
            .flatten()
            .and_then(|storage| storage.get_item("coauth_theme").ok().flatten());
        let dark = stored.as_deref() == Some("dark")
            || stored.is_none()
                && window
                    .match_media("(prefers-color-scheme: dark)")
                    .ok()
                    .flatten()
                    .is_some_and(|query| query.matches());
        if let Some(root) = window.document().and_then(|doc| doc.document_element()) {
            let _ = root.set_attribute("data-theme", if dark { "dark" } else { "light" });
        }
    }
}
fn preferences(scope: &Scope) -> View {
    let dark = scope.cage({
        #[cfg(target_arch = "wasm32")]
        {
            web_sys::window()
                .and_then(|window| window.document())
                .and_then(|doc| doc.document_element())
                .and_then(|root| root.get_attribute("data-theme"))
                .as_deref()
                == Some("dark")
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            false
        }
    });
    let theme = ui::reactive(dark, move |_, is_dark| {
        button(
            if is_dark { "🌙 Dark" } else { "🔴 Light" },
            "theme-toggle",
            move || {
                dark.revise(|value| *value = !*value);
                #[cfg(target_arch = "wasm32")]
                if let Some(window) = web_sys::window() {
                    let value = if dark.get_untracked() {
                        "dark"
                    } else {
                        "light"
                    };
                    if let Some(root) = window.document().and_then(|doc| doc.document_element()) {
                        let _ = root.set_attribute("data-theme", value);
                    }
                    if let Ok(Some(storage)) = window.local_storage() {
                        let _ = storage.set_item("coauth_theme", value);
                    }
                }
            },
        )
    });
    let mut buttons = vec![];
    for (locale, label) in [(UiLocale::En, "EN"), (UiLocale::Zh, "中文")] {
        let weak = scope.downgrade();
        buttons.push(button(
            label,
            if translations::initial_locale() == locale {
                "language-option active"
            } else {
                "language-option"
            },
            move || {
                translations::set_locale(locale);
                translations::set_account_locale(Some(locale));
                if let Some(scope) = weak.upgrade() {
                    let _ = scope.owner().spawn(async move {
                        let _ = crate::api::api_patch::<serde_json::Value>(
                            "/self/viewer/profile",
                            serde_json::json!({"preferred_locale":locale.code()}),
                        )
                        .await;
                        #[cfg(target_arch = "wasm32")]
                        if let Some(window) = web_sys::window() {
                            let _ = window.location().reload();
                        }
                    });
                }
            },
        ));
    }
    block(
        "display-preferences",
        vec![block("language-toggle", buttons), theme],
    )
}
pub fn app(scope: &Scope) -> View {
    let path: String = {
        #[cfg(target_arch = "wasm32")]
        {
            web_sys::window()
                .and_then(|w| w.location().pathname().ok())
                .unwrap_or_else(|| "/".into())
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            "/login".into()
        }
    };
    let account = matches!(
        path.as_str(),
        "/" | "/settings"
            | "/sessions"
            | "/sessions/browsers"
            | "/security"
            | "/notifications"
            | "/identities"
            | "/plan"
    );
    let content = if account {
        account::shell(scope, path.clone())
    } else {
        layout(scope, route(scope, &path), false)
    };
    block("coauth-application", vec![preferences(scope), content])
}
pub fn layout(scope: &Scope, body: View, full: bool) -> View {
    let site = ui::resource(scope, || {
        crate::api::api_get::<SiteConfig>("/self/site-config")
    });
    block(
        if full {
            "layout-container full"
        } else {
            "layout-container"
        },
        vec![
            body,
            block(
                "layout-footer-region",
                vec![ui::reactive(site.data, |_, result| {
                    let Some(Ok(site)) = result else {
                        return block("legal-footer", vec![]);
                    };
                    let mut links = vec![];
                    if let Some(uri) = site.policy_uri {
                        links.push(link("Privacy policy", uri, ""));
                    }
                    if let Some(uri) = site.tos_uri {
                        if !links.is_empty() {
                            links.push(copy("dot-separator", "•"));
                        }
                        links.push(link("Terms and conditions", uri, ""));
                    }
                    let mut body = vec![block("legal-links", links)];
                    if let Some(imprint) = site.imprint {
                        body.push(copy("imprint", imprint));
                    }
                    block("legal-footer", body)
                })],
            ),
        ],
    )
}
pub fn route(scope: &Scope, path: &str) -> View {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["login"] => auth::login(scope),
        ["register"] => registration::entry(scope),
        ["register", "steps", id, kind] => {
            registration::step(scope, (*id).to_owned(), (*kind).to_owned())
        }
        ["recover"] => auth::recovery_start(scope),
        ["recover", "progress", id] => auth::recovery_progress(scope, (*id).to_owned()),
        ["password", "change"] => auth::password_change(scope),
        ["password", "change", "success"] => stack(vec![
            heading(1, "heading-xs", "Password changed"),
            plain("Your account password has been changed successfully."),
            link("Back to account", "/", "btn btn-primary"),
        ]),
        ["password", "recovery"] => auth::password_recovery(scope),
        ["oauth", "approval", id] => approvals::approval(scope, (*id).to_owned(), false),
        ["link"] => approvals::device_link(scope),
        ["device", id] => approvals::approval(scope, (*id).to_owned(), true),
        ["emails", id, "verify"] => auth::email_verify(scope, (*id).to_owned()),
        ["emails", _, "in-use"] => stack(vec![
            heading(1, "heading-xs", "Email address already in use"),
            plain("This email address is already associated with another account."),
            link("Back to settings", "/settings", "btn btn-primary"),
        ]),
        ["sessions", "browsers"] => sessions::list(scope, true),
        ["sessions", id] => sessions::detail(scope, (*id).to_owned()),
        ["clients", id] => approvals::client(scope, (*id).to_owned()),
        ["admin", "oauth-clients", id, "i18n"] => approvals::client_i18n(scope, (*id).to_owned()),
        ["upstream", "link", id] => approvals::upstream(scope, (*id).to_owned()),
        ["devices", rest @ ..] => {
            let id = rest.join("/");
            let data = ui::resource(scope, move || {
                let path = format!("/self/viewer?session_limit=1&app_device={}", encode(&id));
                async move { crate::api::api_get::<crate::api::types::ViewerOutcome>(&path).await }
            });
            ui::resource_body(data, |_, response| {
                let Some(user) = response.viewer.as_user() else {
                    return stack(vec![
                        note(
                            "Not authenticated",
                            "Please sign in to view device information.",
                        ),
                        link("Sign in", "/login", "btn btn-primary"),
                    ]);
                };
                if let Some(edge) = user
                    .app_sessions
                    .as_ref()
                    .and_then(|sessions| sessions.edges.first())
                {
                    let crate::api::types::AppSession::OAuthSession(session) = &edge.node;
                    let _ = go(&format!("/sessions/{}", encode(&session.id)));
                    return copy("loading-screen", "Redirecting…");
                }
                stack(vec![
                    note(
                        "Device not found",
                        "The device you are looking for could not be found.",
                    ),
                    link("Back to sessions", "/sessions", "btn btn-primary"),
                ])
            })
        }
        [""] => account::overview(scope),
        ["settings"] => account::settings(scope),
        ["sessions"] => sessions::list(scope, false),
        ["security"] => security::page(scope),
        ["identities"] => account::identities(scope),
        ["notifications"] => account::notifications(scope),
        ["plan"] => account::plan(scope),
        _ => empty(
            "Page not found",
            "The requested account page does not exist.",
        ),
    }
}
pub fn auth_card(title: impl Into<String>, children: Vec<View>) -> View {
    let mut body = vec![heading(1, "heading-md login-title", title)];
    body.extend(children);
    block("login-page", vec![block("login-container", body)])
}
