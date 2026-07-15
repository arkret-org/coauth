use dioxus::prelude::*;

/// Password strength level.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PasswordStrength {
    VeryWeak,
    Weak,
    Fair,
    Good,
    Strong,
}

impl PasswordStrength {
    fn label_key(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "coauth-password-strength-very-weak",
            PasswordStrength::Weak => "coauth-password-strength-weak",
            PasswordStrength::Fair => "coauth-password-strength-fair",
            PasswordStrength::Good => "coauth-password-strength-good",
            PasswordStrength::Strong => "coauth-password-strength-strong",
        }
    }

    fn color(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "#c53030",
            PasswordStrength::Weak => "#e53e3e",
            PasswordStrength::Fair => "#dd6b20",
            PasswordStrength::Good => "#2f855a",
            PasswordStrength::Strong => "#2b6cb0",
        }
    }

    /// Width percentage of the strength bar.
    fn width_percent(&self) -> u8 {
        match self {
            PasswordStrength::VeryWeak => 20,
            PasswordStrength::Weak => 40,
            PasswordStrength::Fair => 60,
            PasswordStrength::Good => 80,
            PasswordStrength::Strong => 100,
        }
    }

    fn from_score(score: u8) -> Self {
        match score {
            0 => Self::VeryWeak,
            1 => Self::Weak,
            2 => Self::Fair,
            3 => Self::Good,
            _ => Self::Strong,
        }
    }
}

/// Score a password with the same zxcvbn algorithm used by the backend.
fn password_score(password: &str) -> Option<u8> {
    if password.is_empty() {
        return None;
    }

    Some(u8::from(zxcvbn::zxcvbn(password, &[]).score()))
}

#[component]
pub fn PasswordCreationDoubleInput(
    new_password: Signal<String>,
    new_password_again: Signal<String>,
    force_invalid: Option<bool>,
) -> Element {
    let password_policy = use_resource(|| async {
        crate::api::api_get::<crate::api::types::SiteConfig>("/self/site-config").await
    });
    let show_new_password = use_signal(|| false);
    let show_confirm_password = use_signal(|| false);
    let passwords_match =
        new_password.read().eq(&*new_password_again.read()) || new_password_again.read().is_empty();
    let show_mismatch = !passwords_match && !new_password_again.read().is_empty();
    let force_invalid = force_invalid.unwrap_or(false);

    let password_val = new_password.read().clone();
    let score = password_score(&password_val);
    let strength = score.map(PasswordStrength::from_score);
    let policy_binding = password_policy.read();
    let minimum_complexity = policy_binding
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|config| config.minimum_password_complexity);
    let meets_requirement = score
        .zip(minimum_complexity)
        .map(|(score, minimum)| score >= minimum);
    let strength_label = strength.map(|value| crate::translations::t(value.label_key()));
    let requirement_label = meets_requirement.map(|meets| {
        if meets {
            crate::translations::t("coauth-password-strength-meets-requirement")
        } else {
            crate::translations::t("coauth-password-strength-too-weak")
        }
    });

    rsx! {
        div { class: "form-field",
            label { class: "form-label", r#for: "new-password", {crate::translations::t("coauth-change-password-new")} }
            div { class: "password-input-wrapper",
                input {
                    id: "new-password",
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
            if let (Some(strength), Some(strength_label), Some(score)) = (strength, strength_label, score) {
                div { class: "password-strength",
                    // Strength bar background
                    div {
                        class: "password-strength-track",
                        role: "progressbar",
                        "aria-label": "Password strength",
                        "aria-valuemin": "0",
                        "aria-valuemax": "4",
                        "aria-valuenow": "{score}",
                        // Filled portion — width and color are data-driven.
                        div {
                            class: "password-strength-fill",
                            style: "width: {strength.width_percent()}%; background-color: {strength.color()};",
                        }
                    }
                    // Strength label
                    span {
                        class: "password-strength-label",
                        style: "color: {strength.color()};",
                        "aria-live": "polite",
                        "{strength_label}"
                        if let Some(requirement_label) = requirement_label {
                            " — {requirement_label}"
                        }
                    }
                }
            }
        }
        div { class: "form-field",
            label { class: "form-label", r#for: "confirm-new-password", {crate::translations::t("coauth-change-password-confirm")} }
            div { class: "password-input-wrapper",
                input {
                    id: "confirm-new-password",
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

#[cfg(test)]
mod tests {
    use super::{PasswordStrength, password_score};

    #[test]
    fn uses_zxcvbn_score_for_unicode_passphrases() {
        let password = "correct 马 battery staple";
        let expected = u8::from(zxcvbn::zxcvbn(password, &[]).score());

        assert_eq!(password_score(password), Some(expected));
        assert_eq!(password_score(""), None);
    }

    #[test]
    fn maps_all_zxcvbn_scores_to_strength_labels() {
        assert_eq!(
            PasswordStrength::from_score(0).label_key(),
            "coauth-password-strength-very-weak"
        );
        assert_eq!(
            PasswordStrength::from_score(1).label_key(),
            "coauth-password-strength-weak"
        );
        assert_eq!(
            PasswordStrength::from_score(2).label_key(),
            "coauth-password-strength-fair"
        );
        assert_eq!(
            PasswordStrength::from_score(3).label_key(),
            "coauth-password-strength-good"
        );
        assert_eq!(
            PasswordStrength::from_score(4).label_key(),
            "coauth-password-strength-strong"
        );
    }
}

#[component]
pub fn PasswordVisibilityToggle(visible: Signal<bool>) -> Element {
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
                    circle { cx: "12", cy: "12", r: "3" }
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
