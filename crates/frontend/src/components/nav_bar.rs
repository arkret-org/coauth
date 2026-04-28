use dioxus::prelude::*;

use crate::pages::Route;

#[component]
pub fn NavBar(children: Element) -> Element {
    rsx! {
        nav { class: "nav-bar",
            ul { class: "nav-bar-items",
                {children}
            }
        }
    }
}

#[component]
pub fn NavItem(to: Route, children: Element) -> Element {
    let current_route = use_route::<Route>();
    let is_active = std::mem::discriminant(&current_route) == std::mem::discriminant(&to);
    let active_class = if is_active { " active" } else { "" };

    rsx! {
        li { class: "nav-item{active_class}",
            Link { to: to, {children} }
        }
    }
}
