//! Bridge between the workspace's UI-locale vocabulary and ICU.
//!
//! [`arkret_locale::UiLocale`] answers *which language the user is in* — one
//! decision, shared with the SPA and with inkson. `icu_locid::Locale` is what
//! the Fluent bundles and the ICU date/number formatters are keyed on. Keeping
//! them separate means the decision has exactly one implementation while ICU
//! stays responsible for formatting.
//!
//! Nothing in this module makes a choice. It is a total, infallible mapping
//! from the closed product set onto the tags the `.ftl` catalogues are named
//! after, which is why it cannot fail and returns no `Option`.

use arkret_locale::UiLocale;
use icu_locid::{Locale, locale};

/// The ICU locale that carries a [`UiLocale`]'s translations.
///
/// The returned tag matches a bundled catalogue name (`translations/en.ftl`,
/// `translations/zh.ftl`), so `Translator::has_locale` is guaranteed to accept
/// it — the previous code had to guess and then walk a fallback chain, and its
/// hand-written `zh-CN → zh-Hans` special case existed only because that guess
/// could miss.
#[must_use]
pub fn icu_locale_for(ui: UiLocale) -> Locale {
    match ui {
        UiLocale::En => locale!("en"),
        UiLocale::Zh => locale!("zh"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_product_locale_maps_to_a_bundled_catalogue_tag() {
        for ui in arkret_locale::SUPPORTED {
            let icu = icu_locale_for(ui);
            assert_eq!(icu.to_string(), ui.code());
        }
    }

    #[test]
    fn chinese_region_variants_no_longer_need_a_fallback_hop() {
        // `zh-CN` used to be expanded to `zh-Hans` by hand because ICU's
        // automatic chain does not make that hop. Folding to the base tag up
        // front removes the need for that special case entirely.
        let ui = UiLocale::from_tag("zh-CN").expect("zh-CN is a supported variant");
        assert_eq!(icu_locale_for(ui), locale!("zh"));
    }
}
