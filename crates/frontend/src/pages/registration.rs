use super::auth_card;
use crate::api::types::*;
use crate::api::{self};
use crate::translations::t;
use crate::ui::{self, *};

fn registration_contact_missing(
    required: bool,
    phone_enabled: bool,
    email: &str,
    phone: &str,
) -> bool {
    required && email.trim().is_empty() && (!phone_enabled || phone.trim().is_empty())
}

fn registration_contact_message_key(phone_enabled: bool) -> &'static str {
    if phone_enabled {
        "coauth-register-contact-required"
    } else {
        "coauth-register-email-required"
    }
}

pub fn entry(scope: &Scope) -> View {
    let providers = ui::resource(scope, || {
        api::api_get::<ProvidersOutcome>("/account/auth/providers")
    });
    ui::resource_body(providers, |scope, providers| {
        let mut body = vec![];
        if providers.password_registration_enabled {
            let state = Action::new(scope);
            let contact_required = providers.password_registration_contact_required;
            let phone_enabled = providers.phone_verification_enabled;
            let contact_message_key = registration_contact_message_key(phone_enabled);
            let action = crate::post_auth_continuation::current()
                .or_else(crate::post_auth_continuation::load);
            if contact_required {
                body.push(copy("text-secondary", t(contact_message_key)));
            }
            let mut fields = vec![
                Field::new(scope, t("common-handle"), "")
                    .required()
                    .placeholder(crate::translations::t("ui-choose-a-username")),
                Field::new(scope, t("common-email-address"), "").email(),
            ];
            if phone_enabled {
                fields.push(Field::new(scope, t("coauth-register-phone-optional"), ""));
            }
            let password_index = fields.len();
            fields.push(
                Field::new(scope, crate::translations::t("ui-new-password"), "")
                    .new_password()
                    .required(),
            );
            fields.push(
                Field::new(scope, crate::translations::t("ui-confirm-password"), "")
                    .password()
                    .required(),
            );
            body.push(ui::form(
                scope,
                "register",
                fields,
                t("action-create-account"),
                "btn btn-primary btn-block",
                state,
                move |values| {
                    let action = action.clone();
                    async move {
                        let phone = if phone_enabled { values[2].trim() } else { "" };
                        if registration_contact_missing(
                            contact_required,
                            phone_enabled,
                            &values[1],
                            phone,
                        ) {
                            return Err(t(contact_message_key));
                        }
                        super::auth::validate_passwords(
                            &values[password_index],
                            &values[password_index + 1],
                        )?;
                        let response = api::api_post::<RegisterOutcome>(
                            "/account/auth/register",
                            RegisterInput {
                                handle: values[0].trim().into(),
                                email: (!values[1].trim().is_empty())
                                    .then(|| values[1].trim().into()),
                                phone: (phone_enabled && !phone.is_empty()).then(|| phone.into()),
                                password: values[password_index].clone(),
                                password_confirm: values[password_index + 1].clone(),
                                captcha_token: None,
                                post_auth_action: action,
                            },
                        )
                        .await?;
                        if response.status != "success" {
                            let fallback = crate::translations::t("ui-registration-failed");
                            let code = response.error.as_deref().unwrap_or(&fallback);
                            return Err(if code == "email_or_phone_required" {
                                t(contact_message_key)
                            } else {
                                error_message(code)
                            });
                        }
                        let id = response.id.ok_or(crate::translations::t(
                            "ui-registration-did-not-provide-an-id",
                        ))?;
                        next_step(&id, response.next_step.as_deref())?;
                        Ok(None)
                    }
                },
            ));
        }
        if !providers.providers.is_empty() {
            body.push(copy("login-divider", t("coauth-login-separator")));
            body.push(block(
                "login-providers",
                providers
                    .providers
                    .into_iter()
                    .map(|provider| {
                        link(
                            crate::translations::t_with(
                                "coauth-login-continue-with-provider",
                                &[("provider", &provider.human_name.unwrap_or(provider.id))],
                            ),
                            provider.authorize_url,
                            "btn btn-secondary btn-block",
                        )
                    })
                    .collect(),
            ));
        }
        if !providers.password_registration_enabled {
            body.push(copy(
                "text-secondary",
                crate::translations::t("ui-password-registration-is-not-available"),
            ));
        }
        body.push(block(
            "login-register",
            vec![
                plain(crate::translations::t("ui-already-have-an-account")),
                link(t("action-sign-in"), "/login", "link"),
            ],
        ));
        auth_card(t("coauth-register-create-account-heading"), body)
    })
}
pub fn step(scope: &Scope, id: String, kind: String) -> View {
    match kind.as_str() {
        "verify-email" => verify(scope, id, false),
        "verify-phone" => verify(scope, id, true),
        "display-name" => display_name(scope, id),
        "finish" => finish(scope, id),
        _ => empty(
            &crate::translations::t("ui-registration-step-not-found"),
            &crate::translations::t("ui-return-to-registration-and-try-again"),
        ),
    }
}
fn verify(scope: &Scope, id: String, phone: bool) -> View {
    let request = id.clone();
    let data = ui::resource(scope, move || {
        let path = format!("/account/auth/register/{}", encode(&request));
        async move { api::api_get::<RegisterStatusOutcome>(&path).await }
    });
    let reload = data.clone();
    ui::resource_body(data, move |scope, status| {
        let state = Action::new(scope);
        let request = id.clone();
        let code = Field::new(scope, crate::translations::t("ui-verification-code"), "")
            .required()
            .placeholder(crate::translations::t("ui-6-digit-code"));
        let mut body = vec![copy(
            "text-secondary",
            if phone {
                crate::translations::t(
                    "ui-we-sent-a-verification-code-to-your-phone-number-15050432",
                )
                .into()
            } else {
                format!(
                    "Enter the verification code sent to {}.",
                    status
                        .pending_email
                        .as_deref()
                        .map_or_else(|| "your email address".into(), mask_email)
                )
            },
        )];
        body.push(ui::form(
            scope,
            "registration-verify",
            vec![code],
            crate::translations::t("ui-verify"),
            "btn btn-primary btn-block",
            state,
            move |values| {
                let id = request.clone();
                async move {
                    let path = format!(
                        "/account/auth/register/{}/{}",
                        encode(&id),
                        if phone {
                            "verify-phone"
                        } else {
                            "verify-email"
                        }
                    );
                    let response =
                        api::api_post::<StepOutcome>(&path, serde_json::json!({"code":values[0]}))
                            .await?;
                    if response.status != "success" {
                        return Err(error_message(response.error.as_deref().unwrap_or(
                            &crate::translations::t("ui-invalid-verification-code"),
                        )));
                    }
                    next_step(&id, response.next_step.as_deref())?;
                    Ok(None)
                }
            },
        ));
        let request = id.clone();
        body.push(ui::action(
            scope,
            &crate::translations::t("ui-resend-code"),
            "btn btn-secondary btn-block",
            state,
            move || {
                let path = format!(
                    "/account/auth/register/{}/resend-verification",
                    encode(&request)
                );
                async move {
                    let response =
                        api::api_post::<ResendEmailAuthCodePayload>(&path, serde_json::json!({}))
                            .await?;
                    if !matches!(response.status.as_str(), "resent" | "success") {
                        return Err(error_message(&response.status));
                    }
                    Ok(Some(
                        crate::translations::t("ui-a-new-verification-code-has-been-sent").into(),
                    ))
                }
            },
        ));
        if !phone {
            let request = id.clone();
            let reload = reload.clone();
            let change_state = Action::new(scope);
            let form =
                ui::form(
                    scope,
                    "registration-change-email",
                    vec![
                        Field::new(
                            scope,
                            crate::translations::t("ui-email-address"),
                            status.pending_email.unwrap_or_default(),
                        )
                        .email()
                        .required(),
                    ],
                    crate::translations::t("ui-update-email"),
                    "btn btn-primary btn-block",
                    change_state,
                    move |values| {
                        let path =
                            format!("/account/auth/register/{}/change-email", encode(&request));
                        let reload = reload.clone();
                        async move {
                            let response = api::api_post::<ChangeRegistrationEmailOutcome>(
                                &path,
                                serde_json::json!({"email":values[0]}),
                            )
                            .await?;
                            if response.status != "updated" {
                                return Err(error_message(response.error.as_deref().unwrap_or(
                                    &crate::translations::t("ui-email-update-failed"),
                                )));
                            }
                            reload.reload();
                            Ok(Some(
                                crate::translations::t(
                                    "ui-your-email-has-been-updated-and-a-new-code-has-been-sent",
                                )
                                .into(),
                            ))
                        }
                    },
                );
            body.push(ui::disclosure(
                scope,
                "change-email",
                &crate::translations::t("ui-change-email-address"),
                form,
                false,
            ));
        }
        auth_card(
            if phone {
                crate::translations::t("ui-verify-your-phone")
            } else {
                crate::translations::t("ui-verify-your-email")
            },
            body,
        )
    })
}
fn display_name(scope: &Scope, id: String) -> View {
    let state = Action::new(scope);
    let submit_id = id.clone();
    let skip_id = id.clone();
    auth_card(
        t("coauth-choose-display-name-headline"),
        vec![
            copy(
                "text-secondary",
                t("coauth-choose-display-name-description"),
            ),
            ui::form(
                scope,
                "registration-display-name",
                vec![Field::new(scope, t("common-display-name"), "").required()],
                t("action-continue"),
                "btn btn-primary btn-block",
                state,
                move |values| {
                    let id = submit_id.clone();
                    async move {
                        let response = api::api_post::<StepOutcome>(
                            &format!("/account/auth/register/{}/display-name", encode(&id)),
                            serde_json::json!({"display_name":values[0]}),
                        )
                        .await?;
                        if response.status != "success" {
                            return Err(error_message(response.error.as_deref().unwrap_or(
                                &crate::translations::t("ui-unable-to-save-display-name"),
                            )));
                        }
                        next_step(&id, Some("finish"))?;
                        Ok(None)
                    }
                },
            ),
            ui::action(
                scope,
                &t("action-skip"),
                "btn btn-tertiary btn-block",
                state,
                move || {
                    let id = skip_id.clone();
                    async move {
                        let response = api::api_post::<StepOutcome>(
                            &format!("/account/auth/register/{}/display-name", encode(&id)),
                            serde_json::json!({"skip":true}),
                        )
                        .await?;
                        if response.status != "success" {
                            return Err(error_message(
                                response
                                    .error
                                    .as_deref()
                                    .unwrap_or(&crate::translations::t("ui-unable-to-continue")),
                            ));
                        }
                        next_step(&id, Some("finish"))?;
                        Ok(None)
                    }
                },
            ),
        ],
    )
}
fn finish(scope: &Scope, id: String) -> View {
    let status = ui::resource(scope, || {
        api::api_get::<BootstrapAdminStatus>("/self/bootstrap-admin-status")
    });
    ui::resource_body(status, move |scope, status| {
        let state = Action::new(scope);
        let submit_id = id.clone();
        if status.setup_required {
            auth_card(
                &crate::translations::t("ui-create-your-account"),
                vec![
                    copy(
                        "text-secondary",
                        crate::translations::t(
                            "ui-if-you-are-claiming-the-initial-administrator-ac-2d2597e2",
                        ),
                    ),
                    ui::form(
                        scope,
                        "registration-finish",
                        vec![
                            Field::new(
                                scope,
                                crate::translations::t("ui-bootstrap-admin-token-optional"),
                                "",
                            )
                            .password(),
                        ],
                        crate::translations::t("ui-create-account-798ca2ce"),
                        "btn btn-primary btn-block",
                        state,
                        move |values| {
                            let id = submit_id.clone();
                            async move {
                                complete(
                                    &id,
                                    (!values[0].trim().is_empty()).then(|| values[0].trim().into()),
                                )
                                .await
                            }
                        },
                    ),
                ],
            )
        } else {
            let request = id.clone();
            state.run(
                &scope.downgrade(),
                async move { complete(&request, None).await },
            );
            auth_card(
                &crate::translations::t("ui-create-your-account"),
                vec![
                    plain(crate::translations::t("ui-completing-registration")),
                    state.messages(),
                    ui::action(
                        scope,
                        &crate::translations::t("ui-try-again"),
                        "btn btn-secondary btn-block",
                        state,
                        move || {
                            let id = submit_id.clone();
                            async move { complete(&id, None).await }
                        },
                    ),
                ],
            )
        }
    })
}
async fn complete(id: &str, token: Option<String>) -> Outcome {
    let response = api::api_post::<StepOutcome>(
        &format!("/account/auth/register/{}/finish", encode(id)),
        serde_json::json!({"bootstrap_admin_token":token}),
    )
    .await?;
    if response.status != "success" {
        return Err(error_message(response.error.as_deref().unwrap_or(
            &crate::translations::t("ui-could-not-complete-registration"),
        )));
    }
    if let Some(action) = response.post_auth_action {
        crate::post_auth_continuation::save(&action);
    }
    ui::auth_success()
}
fn next_step(id: &str, next: Option<&str>) -> std::result::Result<(), String> {
    let step = match next {
        Some("verify_email") => "verify-email",
        Some("verify_phone") => "verify-phone",
        Some("display_name") => "display-name",
        _ => "finish",
    };
    go(&format!("/register/steps/{}/{step}", encode(id)))
}
fn mask_email(email: &str) -> String {
    let trimmed = email.trim();
    match trimmed.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            format!("{}***@{domain}", local.chars().take(2).collect::<String>())
        }
        _ => trimmed.into(),
    }
}
fn error_message(code: &str) -> String {
    match code {
        "handle_invalid" => t("coauth-register-handle-invalid"),
        "email_or_phone_required" => t("coauth-register-contact-required"),
        "invalid_code" => crate::translations::t("ui-incorrect-code-please-try-again").into(),
        "invalid_display_name" => t("coauth-errors-display-name-invalid"),
        "rate_limited" => crate::translations::t("ui-please-wait-a-moment-and-try-again").into(),
        "registration_already_completed" => {
            crate::translations::t("ui-this-registration-has-already-been-completed").into()
        }
        "email_already_verified" => {
            crate::translations::t("ui-this-email-has-already-been-verified").into()
        }
        "email_invalid" => crate::translations::t("ui-please-enter-a-valid-email-address").into(),
        "email_in_use" => crate::translations::t("ui-this-email-is-already-in-use").into(),
        "bootstrap_admin_token_invalid" => {
            crate::translations::t("ui-that-admin-bootstrap-token-is-not-valid-clear-th-be50dd67")
                .into()
        }
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn email_mask_preserves_domain() {
        assert_eq!(mask_email("alice@example.test"), "al***@example.test");
        assert_eq!(mask_email("a@example.test"), "a***@example.test");
        assert_eq!(mask_email("unavailable"), "unavailable");
    }

    #[test]
    fn required_contact_ignores_a_phone_when_verification_is_disabled() {
        assert!(registration_contact_missing(
            true,
            false,
            "",
            "+12025550123"
        ));
        assert!(registration_contact_missing(
            true,
            false,
            " ",
            "+12025550123"
        ));
        assert!(!registration_contact_missing(
            true,
            false,
            "alice@example.com",
            ""
        ));
        assert!(!registration_contact_missing(
            true,
            true,
            "",
            "+12025550123"
        ));
        assert!(registration_contact_missing(true, true, " ", " "));
    }

    #[test]
    fn optional_contact_stays_optional_with_either_phone_policy() {
        for phone_enabled in [false, true] {
            assert!(!registration_contact_missing(false, phone_enabled, "", ""));
        }
    }
}
