use dioxus::prelude::*;

use crate::components::layout::Layout;
use crate::components::page_heading::PageHeading;
use crate::pages::Route;

#[component]
pub fn PasswordChangeSuccess() -> Element {
    rsx! {
        Layout {
            div { class: "flex flex-col gap-10",
                PageHeading {
                    icon: "✓".to_owned(),
                    title: "Password changed".to_owned(),
                    subtitle: "Your password has been changed successfully.".to_owned(),
                }
                Link { class: "btn btn-primary", to: Route::AccountSettings {},
                    "Back to settings"
                }
            }
        }
    }
}
