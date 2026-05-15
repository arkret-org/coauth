use dioxus::prelude::*;

const THEME_STORAGE_KEY: &str = "coauth_theme";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThemeMode {
    Light,
    Dark,
}

impl ThemeMode {
    fn as_str(self) -> &'static str {
        match self {
            ThemeMode::Light => "light",
            ThemeMode::Dark => "dark",
        }
    }

    fn next(self) -> Self {
        match self {
            ThemeMode::Light => ThemeMode::Dark,
            ThemeMode::Dark => ThemeMode::Light,
        }
    }
}

fn system_prefers_dark() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };

    window
        .match_media("(prefers-color-scheme: dark)")
        .ok()
        .flatten()
        .is_some_and(|query| query.matches())
}

fn read_stored_theme() -> ThemeMode {
    let Some(window) = web_sys::window() else {
        return if system_prefers_dark() {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        };
    };

    if let Ok(Some(storage)) = window.local_storage()
        && let Ok(Some(value)) = storage.get_item(THEME_STORAGE_KEY)
    {
        return match value.as_str() {
            "dark" => ThemeMode::Dark,
            "light" => ThemeMode::Light,
            _ => {
                if system_prefers_dark() {
                    ThemeMode::Dark
                } else {
                    ThemeMode::Light
                }
            }
        };
    }

    if system_prefers_dark() {
        ThemeMode::Dark
    } else {
        ThemeMode::Light
    }
}

fn apply_theme(theme: ThemeMode) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(document) = window.document() else {
        return;
    };
    let Some(element) = document.document_element() else {
        return;
    };

    let _ = element.set_attribute("data-theme", theme.as_str());

    if let Ok(Some(storage)) = window.local_storage() {
        let _ = storage.set_item(THEME_STORAGE_KEY, theme.as_str());
    }
}

pub fn init_theme() {
    apply_theme(read_stored_theme());
}

#[component]
pub fn ThemeToggle() -> Element {
    let mut theme = use_signal(read_stored_theme);

    rsx! {
        button {
            class: "theme-toggle",
            r#type: "button",
            title: "Toggle light or night theme",
            "aria-label": "Toggle light or night theme",
            onclick: move |_| {
                let next = theme().next();
                apply_theme(next);
                theme.set(next);
            },
            span { class: "theme-toggle-mark" }
            span { class: "theme-toggle-label",
                if theme() == ThemeMode::Dark {
                    "Night"
                } else {
                    "Light"
                }
            }
        }
    }
}
