use dioxus::prelude::*;
use fluent_bundle::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use unic_langid::LanguageIdentifier;

#[cfg(target_arch = "wasm32")]
const LOCALE_STORAGE_KEY: &str = "arkret.ui.locale.v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UiLocale {
    #[default]
    En,
    Zh,
}

impl UiLocale {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Zh => "zh",
        }
    }
}

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

    fn for_locale(&self, locale: &str) -> &FluentBundle<FluentResource> {
        if locale_is_chinese(locale) {
            &self.zh
        } else {
            &self.en
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

fn locale_is_chinese(locale: &str) -> bool {
    locale
        .split(['-', '_'])
        .next()
        .is_some_and(|language| language.eq_ignore_ascii_case("zh"))
}

#[cfg(any(target_arch = "wasm32", test))]
fn supported_locale(locale: &str) -> Option<UiLocale> {
    locale.split_ascii_whitespace().find_map(|tag| {
        if locale_is_chinese(tag) {
            Some(UiLocale::Zh)
        } else if tag
            .split(['-', '_'])
            .next()
            .is_some_and(|language| language.eq_ignore_ascii_case("en"))
        {
            Some(UiLocale::En)
        } else {
            None
        }
    })
}

fn requested_locale() -> Option<UiLocale> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let search = window.location().search().ok()?;
        let params = web_sys::UrlSearchParams::new_with_str(&search).ok()?;
        return params
            .get("ui_locales")
            .as_deref()
            .and_then(supported_locale);
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

fn stored_locale() -> Option<UiLocale> {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .and_then(|window| window.local_storage().ok().flatten())
            .and_then(|storage| storage.get_item(LOCALE_STORAGE_KEY).ok().flatten())
            .as_deref()
            .and_then(supported_locale);
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

fn document_locale() -> Option<UiLocale> {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .and_then(|window| window.document())
            .and_then(|document| document.document_element())
            .and_then(|root| root.get_attribute("lang"))
            .as_deref()
            .and_then(supported_locale);
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

fn browser_locale() -> Option<UiLocale> {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .and_then(|window| window.navigator().language())
            .as_deref()
            .and_then(supported_locale);
    }

    #[cfg(not(target_arch = "wasm32"))]
    None
}

#[must_use]
pub fn initial_locale() -> UiLocale {
    requested_locale()
        .or_else(stored_locale)
        .or_else(document_locale)
        .or_else(browser_locale)
        .unwrap_or_default()
}

fn current_locale() -> UiLocale {
    try_consume_context::<LocaleSignal>().map_or_else(initial_locale, |locale| *locale.read())
}

fn format_for_locale(locale: &str, key: &str, args: Option<&FluentArgs<'_>>) -> Option<String> {
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
    format_for_locale(current_locale().code(), key, None).unwrap_or_else(|| key.to_owned())
}

/// Translate a message with string interpolation arguments.
#[must_use]
pub fn t_with(key: &str, values: &[(&str, &str)]) -> String {
    let mut args = FluentArgs::new();
    for (name, value) in values {
        args.set(*name, FluentValue::from(*value));
    }

    format_for_locale(current_locale().code(), key, Some(&args)).unwrap_or_else(|| key.to_owned())
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
    use super::{UiLocale, format_for_locale, locale_is_chinese, supported_locale};

    #[test]
    fn selects_chinese_variants_and_falls_back_to_english() {
        assert!(locale_is_chinese("zh-CN"));
        assert!(locale_is_chinese("ZH_hant"));
        assert!(!locale_is_chinese("en-US"));
        assert_eq!(supported_locale("fr zh-CN en"), Some(UiLocale::Zh));
        assert_eq!(supported_locale("fr en-US"), Some(UiLocale::En));

        assert_eq!(
            format_for_locale("zh-CN", "action-sign-in", None).as_deref(),
            Some("登录")
        );
        assert_eq!(
            format_for_locale("fr", "action-sign-in", None).as_deref(),
            Some("Sign in")
        );
    }

    #[test]
    fn translates_optional_phone_field_on_register_form() {
        assert_eq!(
            format_for_locale("en", "coauth-register-phone-optional", None).as_deref(),
            Some("Phone (optional)")
        );
        assert_eq!(
            format_for_locale("zh-CN", "coauth-register-phone-optional", None).as_deref(),
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
            assert_eq!(format_for_locale("en", key, None).as_deref(), Some(en));
            assert_eq!(format_for_locale("zh-CN", key, None).as_deref(), Some(zh));
        }
    }
}
