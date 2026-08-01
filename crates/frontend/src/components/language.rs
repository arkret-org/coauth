use dioxus::prelude::*;

use crate::translations::{LocaleSignal, UiLocale};

/// The header language switch.
///
/// Switching does two things, and the second one is the point: it applies the
/// change locally *and* persists it to the signed-in account. Before this, the
/// toggle only wrote `localStorage`, so a user who switched here found inkson
/// still in the old language — the two applications had no channel between
/// them in this direction at all.
///
/// The write is fire-and-forget by design. A signed-out visitor has no account
/// to write to, and a failed write must not undo a change the user can plainly
/// see took effect; the device cache still carries the choice, and the next
/// successful profile save reconciles it.
#[component]
pub fn LanguageToggle() -> Element {
    let mut locale = use_context::<LocaleSignal>();
    let active = *locale.read();

    let mut select = move |value: UiLocale| {
        if *locale.peek() == value {
            return;
        }
        crate::translations::set_locale(&mut locale, value);
        persist_to_account(value);
    };

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
                onclick: move |_| select(UiLocale::En),
                "EN"
            }
            button {
                class: if active == UiLocale::Zh { "language-option active" } else { "language-option" },
                r#type: "button",
                lang: "zh",
                "aria-pressed": if active == UiLocale::Zh { "true" } else { "false" },
                title: "中文",
                onclick: move |_| select(UiLocale::Zh),
                "中文"
            }
        }
    }
}

/// Store the choice on the account so every other client picks it up.
///
/// Also updates the SPA's cached account tier, so a later re-resolution does
/// not briefly fall back to the device cache while the request is in flight.
fn persist_to_account(value: UiLocale) {
    crate::translations::set_account_locale(Some(value));
    crate::translations::spawn_account_locale_write(value);
}
