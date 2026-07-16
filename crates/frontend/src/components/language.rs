use dioxus::prelude::*;

use crate::translations::{LocaleSignal, UiLocale};

#[component]
pub fn LanguageToggle() -> Element {
    let mut locale = use_context::<LocaleSignal>();
    let active = *locale.read();

    rsx! {
        div {
            class: "language-toggle",
            role: "group",
            "aria-label": crate::translations::t("common-language"),
            button {
                class: if active == UiLocale::En { "language-option active" } else { "language-option" },
                r#type: "button",
                lang: "en",
                "aria-pressed": if active == UiLocale::En { "true" } else { "false" },
                title: "English",
                onclick: move |_| crate::translations::set_locale(&mut locale, UiLocale::En),
                "EN"
            }
            button {
                class: if active == UiLocale::Zh { "language-option active" } else { "language-option" },
                r#type: "button",
                lang: "zh",
                "aria-pressed": if active == UiLocale::Zh { "true" } else { "false" },
                title: "中文",
                onclick: move |_| crate::translations::set_locale(&mut locale, UiLocale::Zh),
                "中文"
            }
        }
    }
}
