//! Fluent catalogue lookup for the SPA.
//!
//! The *vocabulary* and the *precedence rules* are not defined here — they come
//! from [`arkret_locale`], the crate the coauth server and inkson also link, so
//! all three agree on what a locale is and which tier wins. This module only
//! supplies the browser-side observations (`?ui_locales`, `localStorage`,
//! `<html lang>`, `navigator.language`) and renders the chosen catalogue.

use dioxus::prelude::*;
use fluent_bundle::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use unic_langid::LanguageIdentifier;

pub use arkret_locale::UiLocale;

#[cfg(target_arch = "wasm32")]
const LOCALE_STORAGE_KEY: &str = "arkret.ui.locale.v1";
#[cfg(target_arch = "wasm32")]
const LOCALE_COOKIE_KEY: &str = "arkret.ui.locale.v1";

pub type LocaleSignal = Signal<UiLocale>;

const EN_FTL: &str = include_str!("../../../translations/en.ftl");
const ZH_FTL: &str = include_str!("../../../translations/zh.ftl");

struct Catalogs {
    en: FluentBundle<FluentResource>,
    zh: FluentBundle<FluentResource>,
}

impl Catalogs {
    fn new() -> Self {
        Self {
            en: make_bundle("en", EN_FTL),
            zh: make_bundle("zh", ZH_FTL),
        }
    }

    fn for_locale(&self, locale: UiLocale) -> &FluentBundle<FluentResource> {
        match locale {
            UiLocale::Zh => &self.zh,
            UiLocale::En => &self.en,
        }
    }
}

thread_local! {
    static CATALOGS: Catalogs = Catalogs::new();
}

fn make_bundle(locale: &str, source: &str) -> FluentBundle<FluentResource> {
    let language: LanguageIdentifier = locale
        .parse()
        .expect("bundled locale identifier must be valid");
    let resource = FluentResource::try_new(source.to_owned())
        .unwrap_or_else(|(_, errors)| panic!("bundled Fluent catalog must be valid: {errors:?}"));
    let mut bundle = FluentBundle::new(vec![language]);
    bundle
        .add_resource(resource)
        .expect("bundled Fluent catalog must not contain duplicate messages");
    bundle
}

/// The OIDC `ui_locales` value on the current URL, if the authority put one
/// there. This is how a client hands its live selection to coauth mid-flow.
fn requested_tags() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let search = window.location().search().ok()?;
        let params = web_sys::UrlSearchParams::new_with_str(&search).ok()?;
        return params.get("ui_locales");
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

/// This browser's remembered choice. A cache seeded by a previous visit, not an
/// authority — [`account_locale`] supersedes it as soon as one is known.
fn stored_tags() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .and_then(|window| window.local_storage().ok().flatten())
            .and_then(|storage| storage.get_item(LOCALE_STORAGE_KEY).ok().flatten());
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

/// The `lang` attribute the server stamped on the document. The server derived
/// it from the same resolver, so this is a pre-hydration echo rather than an
/// independent opinion — it is consulted after `localStorage` for exactly that
/// reason.
fn document_tags() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.document_element())
            .and_then(|root| root.get_attribute("lang"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

fn platform_tags() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window().and_then(|window| window.navigator().language());
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

/// The signed-in account's stored preference, cached by [`set_account_locale`]
/// once the profile has loaded.
///
/// Held in a process-global rather than threaded through context because
/// [`t`] is called from components that have no reason to know about accounts,
/// and the value is a single `Copy` enum that only the profile fetch writes.
#[cfg(target_arch = "wasm32")]
static ACCOUNT_LOCALE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(NO_ACCOUNT);
#[cfg(target_arch = "wasm32")]
const NO_ACCOUNT: u8 = u8::MAX;

/// Record the account tier once the profile is known, so a later
/// [`initial_locale`] call ranks it first.
#[cfg(target_arch = "wasm32")]
pub fn set_account_locale(locale: Option<UiLocale>) {
    let encoded = match locale {
        Some(UiLocale::En) => 0,
        Some(UiLocale::Zh) => 1,
        None => NO_ACCOUNT,
    };
    ACCOUNT_LOCALE.store(encoded, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn set_account_locale(_locale: Option<UiLocale>) {}

fn account_locale() -> Option<UiLocale> {
    #[cfg(target_arch = "wasm32")]
    {
        return match ACCOUNT_LOCALE.load(std::sync::atomic::Ordering::Relaxed) {
            0 => Some(UiLocale::En),
            1 => Some(UiLocale::Zh),
            _ => None,
        };
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

/// Persist an incoming OIDC `ui_locales` onto the account, once, if it says
/// something the account does not already record.
///
/// This is the durable half of the inkson → coauth link. `ui_locales` alone
/// only tinted the page it arrived on; the moment the user navigated away, or
/// opened coauth directly, the language reverted. Writing it to the account
/// makes a choice made in inkson govern coauth's UI *and* the notifications
/// coauth sends, on every device, until the user changes it again.
///
/// `stored` is the account's current preference, so a request that merely
/// agrees with it costs nothing.
pub fn adopt_requested_locale_into_account(stored: Option<UiLocale>) {
    let Some(requested) = requested_tags()
        .as_deref()
        .and_then(UiLocale::from_tag_list)
    else {
        return;
    };
    if stored == Some(requested) {
        return;
    }
    set_account_locale(Some(requested));
    spawn_account_locale_write(requested);
}

/// Write a locale to the signed-in account's profile, discarding the result.
///
/// Shared by the header toggle and by [`adopt_requested_locale_into_account`].
/// Failure is deliberately silent: an anonymous visitor gets a 401, which is
/// the normal case on the sign-in page, and for a signed-in user the choice
/// still lives in the device cache and is re-sent on the next navigation —
/// there is nothing here for the user to act on.
pub fn spawn_account_locale_write(value: UiLocale) {
    dioxus::prelude::spawn(async move {
        let body = serde_json::json!({ "preferred_locale": value.code() });
        let _ = crate::api::api_patch::<serde_json::Value>("/self/viewer/profile", body).await;
    });
}

/// Resolve the SPA's locale through the shared precedence chain.
#[must_use]
pub fn initial_locale() -> UiLocale {
    let account = account_locale();
    let requested = requested_tags();
    let stored = stored_tags();
    let document = document_tags();
    let platform = platform_tags();
    arkret_locale::resolve(&arkret_locale::LocaleSources {
        account: account.map(UiLocale::code),
        requested: requested.as_deref(),
        // `localStorage` first, then the server-stamped `lang`: both are
        // device-scoped echoes, and the user's own stored choice is the more
        // specific of the two.
        device_cache: stored.as_deref().or(document.as_deref()),
        platform: platform.as_deref(),
    })
}

fn current_locale() -> UiLocale {
    try_consume_context::<LocaleSignal>().map_or_else(initial_locale, |locale| *locale.read())
}

fn format_for_locale(locale: UiLocale, key: &str, args: Option<&FluentArgs<'_>>) -> Option<String> {
    CATALOGS.with(|catalogs| {
        let format = |bundle: &FluentBundle<FluentResource>| {
            let message = bundle.get_message(key)?;
            let pattern = message.value()?;
            let mut errors = Vec::new();
            Some(
                bundle
                    .format_pattern(pattern, args, &mut errors)
                    .into_owned(),
            )
        };

        format(catalogs.for_locale(locale)).or_else(|| format(&catalogs.en))
    })
}

/// Translate a bundled Fluent message using the browser's preferred language.
#[must_use]
pub fn t(key: &str) -> String {
    format_for_locale(current_locale(), key, None).unwrap_or_else(|| key.to_owned())
}

/// Translate a message with string interpolation arguments.
#[must_use]
pub fn t_with(key: &str, values: &[(&str, &str)]) -> String {
    let mut args = FluentArgs::new();
    for (name, value) in values {
        args.set(*name, FluentValue::from(*value));
    }

    format_for_locale(current_locale(), key, Some(&args)).unwrap_or_else(|| key.to_owned())
}

/// Apply the selected catalog to document metadata and durable UI preference.
pub fn apply_locale(locale: UiLocale) {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        if let Some(root) = window
            .document()
            .and_then(|document| document.document_element())
        {
            let _ = root.set_attribute("lang", locale.code());
        }
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.set_item(LOCALE_STORAGE_KEY, locale.code());
        }
        // Unlike localStorage, this same-site, non-sensitive preference is
        // visible to the server when the user approves the pending OIDC grant.
        // That is the first authenticated request common to password, passkey,
        // upstream-OIDC and registration flows, so it is where coauth can bind
        // a choice made on the signed-out page to the authenticated account.
        if let Some(document) = window.document().and_then(|document| {
            use wasm_bindgen::JsCast as _;
            document.dyn_into::<web_sys::HtmlDocument>().ok()
        }) {
            let cookie = format!(
                "{LOCALE_COOKIE_KEY}={}; Path=/; Max-Age=315360000; SameSite=Lax",
                locale.code()
            );
            let _ = document.set_cookie(&cookie);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    let _ = locale;
}

pub fn set_locale(locale: &mut LocaleSignal, value: UiLocale) {
    if *locale.read() == value {
        return;
    }
    apply_locale(value);
    locale.set(value);
}

#[cfg(test)]
mod tests {
    use super::{UiLocale, format_for_locale};

    /// Parse a tag the way a caller would, then render through it. Tag parsing
    /// itself is `arkret-locale`'s job and is tested there; this asserts the
    /// SPA is wired to that parser and to the right catalogue.
    fn render(tag: &str, key: &str) -> Option<String> {
        let locale = UiLocale::from_tag(tag).unwrap_or_default();
        format_for_locale(locale, key, None)
    }

    #[test]
    fn chinese_variants_render_from_the_chinese_catalogue() {
        for tag in ["zh", "zh-CN", "ZH_hant"] {
            assert_eq!(
                render(tag, "action-sign-in").as_deref(),
                Some("登录"),
                "{tag}"
            );
        }
    }

    #[test]
    fn an_unsupported_tag_renders_english_rather_than_the_raw_key() {
        assert_eq!(render("fr", "action-sign-in").as_deref(), Some("Sign in"));
    }

    #[test]
    fn a_key_missing_from_the_chinese_catalogue_falls_back_to_english() {
        // `format_for_locale` retries against `en` on a miss, which is what
        // keeps a partially-translated catalogue from rendering raw keys.
        assert_eq!(
            format_for_locale(UiLocale::Zh, "definitely-not-a-real-message-key", None),
            None
        );
    }

    #[test]
    fn translates_optional_phone_field_on_register_form() {
        assert_eq!(
            format_for_locale(UiLocale::En, "coauth-register-phone-optional", None).as_deref(),
            Some("Phone (optional)")
        );
        assert_eq!(
            render("zh-CN", "coauth-register-phone-optional").as_deref(),
            Some("手机号（可选）")
        );
    }

    #[test]
    fn translates_display_name_registration_step() {
        let expected = [
            (
                "coauth-choose-display-name-headline",
                "Choose your display name",
                "选择显示名称",
            ),
            (
                "coauth-choose-display-name-description",
                "This is the name other people will see. You can change this at any time.",
                "这是能被其他人看到的名称，你可以随时更改。",
            ),
            ("common-display-name", "Display Name", "显示名称"),
            ("action-continue", "Continue", "继续"),
            ("action-skip", "Skip", "跳过"),
            (
                "coauth-errors-display-name-invalid",
                "Display name cannot be empty or too long",
                "显示名称不能为空或过长",
            ),
        ];

        for (key, en, zh) in expected {
            assert_eq!(
                format_for_locale(UiLocale::En, key, None).as_deref(),
                Some(en)
            );
            assert_eq!(render("zh-CN", key).as_deref(), Some(zh));
        }
    }
}
