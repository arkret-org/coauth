// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

//! The server's single answer to "which language is this response in?".
//!
//! Every tier is resolved by [`arkret_locale`], the same crate the SPA and
//! inkson link, so a request rendered here and a page rendered in the browser
//! cannot disagree. This module only decides *what to feed it* from a Salvo
//! request; the precedence rules live in the shared crate.
//!
//! Two implementations were removed to get here: a hand-written
//! `Accept-Language` header parser with its own q-value sorting
//! (`salvo_utils::language_detection`), and a `zh-CN → zh-Hans` fixup that
//! existed only because ICU's automatic fallback chain does not make that hop.
//! Folding region variants onto the base language up front makes both
//! unnecessary.

use coauth_i18n::{Locale, LocaleSources, UiLocale, icu_locale_for, resolve};
use http::header::ACCEPT_LANGUAGE;
use salvo::prelude::*;

pub const UI_LOCALE_COOKIE_KEY: &str = "arkret.ui.locale.v1";

/// The locale selected in coauth's browser UI during the current flow.
///
/// This cookie deliberately carries only the closed `en` / `zh` vocabulary;
/// it is not an authentication credential. The OAuth approval handler reads it
/// only after authenticating the browser session and persists it on that
/// session's account.
#[must_use]
pub fn selected_ui_locale(req: &Request) -> Option<UiLocale> {
    req.cookies()
        .get(UI_LOCALE_COOKIE_KEY)
        .and_then(|cookie| selected_ui_locale_value(cookie.value()))
}

fn selected_ui_locale_value(value: &str) -> Option<UiLocale> {
    match value {
        "en" => Some(UiLocale::En),
        "zh" => Some(UiLocale::Zh),
        _ => None,
    }
}

/// The browser's stated language preferences, verbatim.
///
/// Returned as the raw header value rather than a parsed list because
/// [`UiLocale::from_tag_list`] already understands `Accept-Language` syntax,
/// weights included. A non-UTF-8 header is treated as absent: it cannot
/// express a preference we could honour, and rejecting the request over a
/// cosmetic header would be worse than falling through to the next tier.
fn accept_language(req: &Request) -> Option<&str> {
    req.headers().get(ACCEPT_LANGUAGE)?.to_str().ok()
}

/// The UI locale for a request, given whatever the caller knows.
///
/// * `account` — the signed-in user's stored `preferred_locale`, when the
///   handler has already loaded it. Pass `None` when there is no session or
///   the account has not been resolved yet; it is a tier, not a requirement.
/// * `requested` — an explicit request carried with the navigation, in
///   practice the OIDC `ui_locales` parameter.
#[must_use]
pub fn preferred_ui_locale(
    req: &Request,
    account: Option<&str>,
    requested: Option<&str>,
) -> UiLocale {
    resolve(&LocaleSources {
        account,
        requested,
        // A server request has no view of the browser's device cache; the SPA
        // applies that tier itself once it boots.
        device_cache: None,
        platform: accept_language(req),
    })
}

/// [`preferred_ui_locale`] as the ICU locale the templates and formatters use.
#[must_use]
pub fn preferred_language(req: &Request, _depot: &Depot) -> Locale {
    icu_locale_for(preferred_ui_locale(req, None, None))
}

/// Choose a UI locale using explicit OIDC `ui_locales` candidates first,
/// followed by the browser's `Accept-Language` preferences.
#[must_use]
pub fn preferred_language_with_requested(
    req: &Request,
    _depot: &Depot,
    requested: Option<&str>,
) -> Locale {
    icu_locale_for(preferred_ui_locale(req, None, requested))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_accept_language(value: &str) -> Request {
        let mut req = Request::default();
        req.headers_mut()
            .insert(ACCEPT_LANGUAGE, value.parse().expect("test header value"));
        req
    }

    #[test]
    fn accept_language_weights_are_honoured() {
        let req = request_with_accept_language("en;q=0.4, zh-CN;q=0.9");
        assert_eq!(preferred_ui_locale(&req, None, None), UiLocale::Zh);
    }

    #[test]
    fn ui_locales_outranks_the_browser_header() {
        let req = request_with_accept_language("en-US,en;q=0.9");
        assert_eq!(preferred_ui_locale(&req, None, Some("zh-CN")), UiLocale::Zh);
    }

    #[test]
    fn the_account_preference_outranks_ui_locales() {
        let req = request_with_accept_language("en-US");
        assert_eq!(
            preferred_ui_locale(&req, Some("zh"), Some("en")),
            UiLocale::Zh
        );
    }

    #[test]
    fn an_unsupported_header_falls_through_to_english() {
        let req = request_with_accept_language("fr-FR,fr;q=0.9,de;q=0.8");
        assert_eq!(preferred_ui_locale(&req, None, None), UiLocale::En);
    }

    #[test]
    fn no_header_at_all_is_english() {
        assert_eq!(
            preferred_ui_locale(&Request::default(), None, None),
            UiLocale::En
        );
    }

    #[test]
    fn zh_cn_resolves_without_the_old_zh_hans_expansion() {
        let req = request_with_accept_language("zh-CN,zh;q=0.9");
        assert_eq!(preferred_language(&req, &Depot::new()).to_string(), "zh");
    }

    #[test]
    fn browser_locale_cookie_accepts_only_the_shared_vocabulary() {
        assert_eq!(selected_ui_locale_value("en"), Some(UiLocale::En));
        assert_eq!(selected_ui_locale_value("zh"), Some(UiLocale::Zh));
        assert_eq!(selected_ui_locale_value("zh-CN"), None);
        assert_eq!(selected_ui_locale_value("fr"), None);
        assert_eq!(selected_ui_locale_value(""), None);
    }
}
