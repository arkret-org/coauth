use dioxus::prelude::*;

/// A success/warning status pill.
///
/// `ok == true` renders `.badge.badge-success`, otherwise `.badge.badge-warning`.
/// Replaces the repeated inline `if ok { "badge badge-success" } else { ... }`
/// ternaries scattered across the account pages.
#[component]
pub fn StatusBadge(ok: bool, label: String) -> Element {
    let class = if ok {
        "badge badge-success"
    } else {
        "badge badge-warning"
    };
    rsx! {
        span { class: "{class}", "{label}" }
    }
}
