use dioxus::prelude::*;

use crate::{
    components::{layout::Layout, page_heading::PageHeading},
    pages::Route,
};

#[component]
pub fn EmailInUse(id: String) -> Element {
    rsx! {
        Layout {
            div { class: "flex flex-col gap-10",
                PageHeading {
                    icon: "✉".to_owned(),
                    title: "Email already in use".to_owned(),
                    subtitle: "This email address is already associated with another account.".to_owned(),
                }
                Link { class: "btn btn-primary", to: Route::AccountSettings {},
                    "Back to settings"
                }
            }
        }
    }
}
