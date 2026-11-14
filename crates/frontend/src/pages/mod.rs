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
#[derive(Clone, Copy)]
struct PreparedLocale {
    locale: UiLocale,
    account_saved: bool,
}
#[derive(Clone, Copy)]
struct LanguageChange {
    locale: UiLocale,
    ready: bool,
}
fn apply_language(prepared: PreparedLocale) {
    translations::set_locale(prepared.locale);
    translations::set_account_locale(prepared.account_saved.then_some(prepared.locale));
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        // An explicit choice supersedes the incoming OIDC display hint.
        if let Ok(search) = window.location().search()
            && let Ok(parameters) = web_sys::UrlSearchParams::new_with_str(&search)
            && parameters.has("ui_locales")
        {
            parameters.delete("ui_locales");
            let query = parameters.to_string().as_string().unwrap_or_default();
            if window.location().set_search(&query).is_ok() {
                return;
            }
        }
        let _ = window.location().reload();
    }
}
fn prepare_language(
    scope: &Scope,
    locale: UiLocale,
    busy: Cage<bool>,
    error: Cage<String>,
    prepared: Cage<Option<PreparedLocale>>,
    pending: Cage<Option<LanguageChange>>,
    discard_revision: Option<u64>,
) {
    if busy.get_untracked() {
        return;
    }
    busy.revise(|value| *value = true);
    error.revise(String::clear);
    let owner = scope.downgrade();
    let result = scope.owner().spawn(async move {
        let result: std::result::Result<PreparedLocale, String> = async {
            let viewer =
                crate::api::api_get::<crate::api::types::ViewerOutcome>("/self/viewer").await?;
            let account_saved = viewer.viewer.as_user().is_some();
            if account_saved {
                let response =
                    crate::api::api_patch::<crate::api::types::PatchViewerProfileOutcome>(
                        "/self/viewer/profile",
                        serde_json::json!({"preferred_locale":locale.code()}),
                    )
                    .await?;
                if response
                    .profile
                    .preferred_locale
                    .as_deref()
                    .and_then(UiLocale::from_tag)
                    != Some(locale)
                {
                    return Err(translations::t("coauth-language-not-accepted"));
                }
            }
            Ok(PreparedLocale {
                locale,
                account_saved,
            })
        }
        .await;
        if owner.upgrade().is_none() {
            return;
        }
        busy.revise(|value| *value = false);
        match result {
            Ok(value) => {
                prepared.revise(|current| *current = Some(value));
                if crate::drafts::state() == crate::drafts::State::Clean
                    || (crate::drafts::state() == crate::drafts::State::Unsaved
                        && discard_revision == Some(crate::drafts::revision()))
                {
                    apply_language(value);
                } else {
                    pending.revise(|current| {
                        *current = Some(LanguageChange {
                            locale,
                            ready: true,
                        })
                    });
                }
            }
            Err(message) => error.revise(|value| {
                *value = translations::t_with("coauth-language-save-failed", &[("error", &message)])
            }),
        }
    });
    if let Err(message) = result {
        busy.revise(|value| *value = false);
        error.revise(|value| *value = message.to_string());
    }
}
fn request_language(
    scope: &Scope,
    locale: UiLocale,
    busy: Cage<bool>,
    error: Cage<String>,
    prepared: Cage<Option<PreparedLocale>>,
    pending: Cage<Option<LanguageChange>>,
) {
    let ready = prepared
        .get_untracked()
        .is_some_and(|value| value.locale == locale);
    match crate::drafts::state() {
        crate::drafts::State::Busy => {
            error.revise(|value| *value = translations::t("coauth-language-operation-pending"))
        }
        crate::drafts::State::Unsaved => {
            pending.revise(|value| *value = Some(LanguageChange { locale, ready }))
        }
        crate::drafts::State::Clean if ready => {
            if let Some(value) = prepared.get_untracked() {
                apply_language(value);
            }
        }
        crate::drafts::State::Clean => {
            prepare_language(scope, locale, busy, error, prepared, pending, None)
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
            translations::t(if is_dark {
                "coauth-theme-dark"
            } else {
                "coauth-theme-light"
            }),
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
    let busy = scope.cage(false);
    let error = scope.cage(String::new());
    let prepared = scope.cage(None::<PreparedLocale>);
    let pending = scope.cage(None::<LanguageChange>);
    let mut buttons: Vec<View> = vec![];
    for (locale, label) in [(UiLocale::En, "EN"), (UiLocale::Zh, "中文")] {
        let owner = scope.downgrade();
        buttons.push(Box::new(
            sapid::button()
                .unstyled()
                .class(if translations::initial_locale() == locale {
                    "language-option active"
                } else {
                    "language-option"
                })
                .label(label)
                .pressed(translations::initial_locale() == locale)
                .enabled(scope.bond(move || !busy.get()))
                .on_press(move || {
                    if translations::initial_locale() == locale
                        && prepared.get_untracked().is_none()
                    {
                        return;
                    }
                    if let Some(scope) = owner.upgrade() {
                        request_language(&scope, locale, busy, error, prepared, pending);
                    }
                }),
        ));
    }
    let owner = scope.downgrade();
    let confirmation: View = Box::new(
        sapid::alert_dialog(format!("language-change-{}", scope.id().slot()))
            .unstyled()
            .class("account-confirm-dialog language-change-dialog")
            .show_trigger(false)
            .label(translations::t("coauth-language-change-title"))
            .title(translations::t("coauth-language-change-title"))
            .description(translations::t("coauth-language-change-description"))
            .cancel_label(translations::t("coauth-language-keep-editing"))
            .confirm_label(translations::t("coauth-language-apply-reload"))
            .confirm_variant(sapid::ButtonVariant::Danger)
            .open(pending.map(|value| value.is_some()))
            .on_open_change(move |open| {
                if !open {
                    pending.revise(|value| *value = None);
                }
            })
            .on_confirm(move || {
                let Some(change) = pending.get_untracked() else {
                    return;
                };
                if crate::drafts::state() == crate::drafts::State::Busy {
                    error.revise(|value| {
                        *value = translations::t("coauth-language-operation-pending")
                    });
                } else if change.ready {
                    if let Some(value) = prepared.get_untracked() {
                        apply_language(value);
                    }
                } else if let Some(scope) = owner.upgrade() {
                    prepare_language(
                        &scope,
                        change.locale,
                        busy,
                        error,
                        prepared,
                        pending,
                        Some(crate::drafts::revision()),
                    );
                }
            }),
    );
    let ready_notice = ui::reactive(prepared, |_, value| match value {
        Some(value) => copy(
            "language-ready-notice",
            translations::t(if value.account_saved {
                "coauth-language-saved-pending-reload"
            } else {
                "coauth-language-ready-pending-reload"
            }),
        ),
        None => block("", vec![]),
    });
    block(
        "display-preferences",
        vec![
            block("language-toggle", buttons),
            theme,
            confirmation,
            block(
                "language-feedback",
                vec![
                    Box::new(
                        view()
                            .role(Role::Status)
                            .class(busy.map(|value| {
                                if *value {
                                    "language-save-status".to_owned()
                                } else {
                                    "language-save-status is-empty".to_owned()
                                }
                            }))
                            .fill(text().content(busy.map(|value| {
                                if *value {
                                    translations::t("coauth-language-saving")
                                } else {
                                    String::new()
                                }
                            }))),
                    ),
                    Box::new(
                        view()
                            .role(Role::Alert)
                            .class(error.map(|value| {
                                if value.is_empty() {
                                    "language-save-error is-empty".to_owned()
                                } else {
                                    "language-save-error".to_owned()
                                }
                            }))
                            .fill(text().content(error)),
                    ),
                    ready_notice,
                ],
            ),
        ],
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
    let path = crate::config::get_config().route_path(&path).to_owned();
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
    block(
        "coauth-application",
        vec![
            if account {
                block("", vec![])
            } else {
                preferences(scope)
            },
            content,
        ],
    )
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
                        links.push(link_to_url(
                            crate::translations::t("ui-privacy-policy"),
                            uri,
                            "",
                        ));
                    }
                    if let Some(uri) = site.tos_uri {
                        if !links.is_empty() {
                            links.push(copy("dot-separator", "•"));
                        }
                        links.push(link_to_url(
                            crate::translations::t("ui-terms-and-conditions"),
                            uri,
                            "",
                        ));
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
            heading(
                1,
                "heading-xs",
                crate::translations::t("ui-password-changed"),
            ),
            plain(crate::translations::t(
                "ui-your-account-sign-in-password-has-changed-arkret-d59ff863",
            )),
            link(
                crate::translations::t("ui-back-to-account"),
                "/",
                "btn btn-primary",
            ),
        ]),
        ["password", "recovery"] => auth::password_recovery(scope),
        ["oauth", "approval", id] => approvals::approval(scope, (*id).to_owned(), false),
        ["link"] => approvals::device_link(scope),
        ["device", id] => approvals::approval(scope, (*id).to_owned(), true),
        ["emails", id, "verify"] => auth::email_verify(scope, (*id).to_owned()),
        ["emails", _, "in-use"] => stack(vec![
            heading(
                1,
                "heading-xs",
                crate::translations::t("ui-email-address-already-in-use"),
            ),
            plain(crate::translations::t(
                "ui-this-email-address-is-already-associated-with-another-account",
            )),
            link(
                crate::translations::t("ui-back-to-settings"),
                "/settings",
                "btn btn-primary",
            ),
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
                            crate::translations::t("ui-not-authenticated-76d1efbe"),
                            crate::translations::t("ui-please-sign-in-to-view-device-information"),
                        ),
                        link(
                            crate::translations::t("ui-sign-in"),
                            "/login",
                            "btn btn-primary",
                        ),
                    ]);
                };
                if let Some(edge) = user
                    .app_sessions
                    .as_ref()
                    .and_then(|sessions| sessions.edges.first())
                {
                    let crate::api::types::AppSession::OAuthSession(session) = &edge.node;
                    let _ = go(&format!("/sessions/{}", encode(&session.id)));
                    return copy("loading-screen", crate::translations::t("ui-redirecting"));
                }
                stack(vec![
                    note(
                        crate::translations::t("ui-device-not-found"),
                        crate::translations::t(
                            "ui-the-device-you-are-looking-for-could-not-be-found",
                        ),
                    ),
                    link(
                        crate::translations::t("ui-back-to-sessions-3740d2ce"),
                        "/sessions",
                        "btn btn-primary",
                    ),
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
            &crate::translations::t("ui-page-not-found"),
            &crate::translations::t("ui-the-requested-account-page-does-not-exist"),
        ),
    }
}
pub fn auth_card(title: impl Into<String>, children: Vec<View>) -> View {
    let mut body = vec![heading(1, "heading-md login-title", title)];
    body.extend(children);
    block("login-page", vec![block("login-container", body)])
}
