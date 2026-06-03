use dioxus::prelude::*;

/// Password strength level.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PasswordStrength {
    Empty,
    Weak,
    Fair,
    Good,
    Strong,
}

impl PasswordStrength {
    fn label(&self) -> &'static str {
        match self {
            PasswordStrength::Empty => "",
            PasswordStrength::Weak => "Weak",
            PasswordStrength::Fair => "Fair",
            PasswordStrength::Good => "Good",
            PasswordStrength::Strong => "Strong",
        }
    }

    fn color(&self) -> &'static str {
        match self {
            PasswordStrength::Empty => "transparent",
            PasswordStrength::Weak => "#e53e3e",
            PasswordStrength::Fair => "#dd6b20",
            PasswordStrength::Good => "#38a169",
            PasswordStrength::Strong => "#2b6cb0",
        }
    }

    /// Width percentage of the strength bar.
    fn width_percent(&self) -> u8 {
        match self {
            PasswordStrength::Empty => 0,
            PasswordStrength::Weak => 25,
            PasswordStrength::Fair => 50,
            PasswordStrength::Good => 75,
            PasswordStrength::Strong => 100,
        }
    }
}

/// Estimate password strength based on length and character variety.
fn estimate_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength::Empty;
    }

    let len = password.len();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let variety_count = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&v| v)
        .count();

    // Score based on length and variety
    if len < 8 {
        PasswordStrength::Weak
    } else if len < 12 {
        if variety_count >= 3 {
            PasswordStrength::Good
        } else {
            PasswordStrength::Fair
        }
    } else if len < 16 {
        if variety_count >= 3 {
            PasswordStrength::Strong
        } else {
            PasswordStrength::Good
        }
    } else {
        // 16+ characters
        if variety_count >= 2 {
            PasswordStrength::Strong
        } else {
            PasswordStrength::Good
        }
    }
}

#[component]
pub fn PasswordCreationDoubleInput(
    new_password: Signal<String>,
    new_password_again: Signal<String>,
    force_invalid: Option<bool>,
) -> Element {
    let show_new_password = use_signal(|| false);
    let show_confirm_password = use_signal(|| false);
    let passwords_match =
        new_password.read().eq(&*new_password_again.read()) || new_password_again.read().is_empty();
    let show_mismatch = !passwords_match && !new_password_again.read().is_empty();
    let force_invalid = force_invalid.unwrap_or(false);

    let password_val = new_password.read().clone();
    let strength = estimate_strength(&password_val);

    rsx! {
        div { class: "form-field",
            label { class: "form-label", "New password" }
            div { class: "password-input-wrapper",
                input {
                    class: if force_invalid { "form-input invalid" } else { "form-input" },
                    r#type: if show_new_password() { "text" } else { "password" },
                    autocomplete: "new-password",
                    required: true,
                    value: "{new_password}",
                    oninput: move |e| new_password.set(e.value()),
                }
                PasswordVisibilityToggle { visible: show_new_password }
            }
            if force_invalid {
                span { class: "form-error", "Password does not meet the requirements." }
            }

            // Password strength indicator
            if strength != PasswordStrength::Empty {
                div {
                    style: "margin-top: 6px;",
                    // Strength bar background
                    div {
                        style: "height: 4px; border-radius: 2px; background-color: #e2e8f0; overflow: hidden;",
                        // Filled portion
                        div {
                            style: "height: 100%; border-radius: 2px; transition: width 0.3s ease, background-color 0.3s ease; width: {strength.width_percent()}%; background-color: {strength.color()};",
                        }
                    }
                    // Strength label
                    span {
                        style: "font-size: 0.75rem; color: {strength.color()}; margin-top: 2px; display: inline-block;",
                        "{strength.label()}"
                    }
                }
            }
        }
        div { class: "form-field",
            label { class: "form-label", "Confirm new password" }
            div { class: "password-input-wrapper",
                input {
                    class: if show_mismatch { "form-input invalid" } else { "form-input" },
                    r#type: if show_confirm_password() { "text" } else { "password" },
                    autocomplete: "new-password",
                    required: true,
                    value: "{new_password_again}",
                    oninput: move |e| new_password_again.set(e.value()),
                }
                PasswordVisibilityToggle { visible: show_confirm_password }
            }
            if show_mismatch {
                span { class: "form-error", "Passwords do not match." }
            }
        }
    }
}

#[component]
fn PasswordVisibilityToggle(visible: Signal<bool>) -> Element {
    let label = if visible() {
        "Hide password"
    } else {
        "Show password"
    };

    rsx! {
        button {
            class: "password-toggle",
            r#type: "button",
            title: "{label}",
            "aria-label": "{label}",
            onclick: move |_| visible.set(!visible()),
            svg {
                class: "password-toggle-icon",
                xmlns: "http://www.w3.org/2000/svg",
                width: "20",
                height: "20",
                view_box: "0 0 24 24",
                fill: "none",
                stroke: "currentColor",
                stroke_width: "2",
                stroke_linecap: "round",
                stroke_linejoin: "round",
                if visible() {
                    path { d: "M17.94 17.94A10.07 10.07 0 0 1 12 20C7 20 2.73 16.89 1 12A18.45 18.45 0 0 1 5.06 5.06" }
                    path { d: "M9.9 4.24A9.12 9.12 0 0 1 12 4C17 4 21.27 7.11 23 12A18.5 18.5 0 0 1 19.42 16.42" }
                    path { d: "M14.12 14.12A3 3 0 0 1 9.88 9.88" }
                    path { d: "M1 1L23 23" }
                } else {
                    path { d: "M1 12S5 4 12 4S23 12 23 12S19 20 12 20S1 12 1 12Z" }
                    circle { ck: "12", cy: "12", r: "3" }
                }
            }
        }
    }
}

#[component]
pub fn AccountManagementPasswordPreview() -> Element {
    rsx! {
        div { class: "password-preview",
            div {
                span { class: "password-dots", "••••••••" }
            }
            Link {
                class: "btn btn-secondary btn-sm",
                to: crate::pages::Route::PasswordChange {},
                "Change password"
            }
        }
    }
}
