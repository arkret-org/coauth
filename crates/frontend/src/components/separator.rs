use dioxus::prelude::*;

#[derive(PartialEq, Clone, Default)]
pub enum SeparatorKind {
    #[default]
    Default,
    Section,
}

#[component]
pub fn Separator(kind: Option<SeparatorKind>) -> Element {
    let kind = kind.unwrap_or_default();
    let class = match kind {
        SeparatorKind::Default => "separator",
        SeparatorKind::Section => "separator section",
    };

    rsx! {
        hr { class: "{class}" }
    }
}
