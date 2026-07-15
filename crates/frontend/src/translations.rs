use fluent_bundle::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use unic_langid::LanguageIdentifier;

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

fn current_locale() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        return web_sys::window()
            .and_then(|window| window.navigator().language())
            .unwrap_or_else(|| "en".to_owned());
    }

    #[cfg(not(target_arch = "wasm32"))]
    "en".to_owned()
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
    format_for_locale(&current_locale(), key, None).unwrap_or_else(|| key.to_owned())
}

/// Translate a message with string interpolation arguments.
#[must_use]
pub fn t_with(key: &str, values: &[(&str, &str)]) -> String {
    let mut args = FluentArgs::new();
    for (name, value) in values {
        args.set(*name, FluentValue::from(*value));
    }

    format_for_locale(&current_locale(), key, Some(&args)).unwrap_or_else(|| key.to_owned())
}

/// Keep the document language metadata aligned with the selected catalog.
pub fn init_document_language() {
    #[cfg(target_arch = "wasm32")]
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        let locale = current_locale();
        let language = if locale_is_chinese(&locale) {
            "zh"
        } else {
            "en"
        };
        let _ = root.set_attribute("lang", language);
    }
}

#[cfg(test)]
mod tests {
    use super::{format_for_locale, locale_is_chinese};

    #[test]
    fn selects_chinese_variants_and_falls_back_to_english() {
        assert!(locale_is_chinese("zh-CN"));
        assert!(locale_is_chinese("ZH_hant"));
        assert!(!locale_is_chinese("en-US"));

        assert_eq!(
            format_for_locale("zh-CN", "action-sign-in", None).as_deref(),
            Some("登录")
        );
        assert_eq!(
            format_for_locale("fr", "action-sign-in", None).as_deref(),
            Some("Sign in")
        );
    }
}
