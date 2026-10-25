use super::auth_card;
use crate::api::types::*;
use crate::api::{self};
use crate::translations::t;
use crate::ui::{self, *};

pub fn entry(scope: &Scope) -> View {
    let providers = ui::resource(scope, || {
        api::api_get::<ProvidersOutcome>("/account/auth/providers")
    });
    ui::resource_body(providers, |scope, providers| {
        let mut body = vec![];
        if providers.password_registration_enabled {
            let state = Action::new(scope);
            let action = crate::post_auth_continuation::current()
                .or_else(crate::post_auth_continuation::load);
            body.push(ui::form(
                scope,
                "register",
                vec![
                    Field::new(scope, t("common-handle"), "")
                        .required()
                        .placeholder("Choose a username"),
                    Field::new(scope, t("common-email-address"), "").email(),
                    Field::new(scope, t("coauth-register-phone-optional"), ""),
                    Field::new(scope, "New password", "").password().required(),
                    Field::new(scope, "Confirm password", "")
                        .password()
                        .required(),
                ],
                t("action-create-account"),
                "btn btn-primary btn-block",
                state,
                move |values| {
                    let action = action.clone();
                    async move {
                        super::auth::validate_passwords(&values[3], &values[4])?;
                        let response = api::api_post::<RegisterOutcome>(
                            "/account/auth/register",
                            RegisterInput {
                                handle: values[0].trim().into(),
                                email: (!values[1].trim().is_empty())
                                    .then(|| values[1].trim().into()),
                                phone: (!values[2].trim().is_empty())
                                    .then(|| values[2].trim().into()),
                                password: values[3].clone(),
                                password_confirm: values[4].clone(),
                                captcha_token: None,
                                post_auth_action: action,
                            },
                        )
                        .await?;
                        if response.status != "success" {
                            return Err(error_message(
                                response.error.as_deref().unwrap_or("Registration failed."),
                            ));
                        }
                        let id = response.id.ok_or("Registration did not provide an ID")?;
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
                            format!(
                                "Continue with {}",
                                provider.human_name.unwrap_or(provider.id)
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
                "Password registration is not available.",
            ));
        }
        body.push(block(
            "login-register",
            vec![
                plain("Already have an account?"),
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
            "Registration step not found",
            "Return to registration and try again.",
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
        let code = Field::new(scope, "Verification code", "")
            .required()
            .placeholder("6-digit code");
        let mut body = vec![copy(
            "text-secondary",
            if phone {
                "We sent a verification code to your phone number. Please enter it below.".into()
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
            "Verify",
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
                        return Err(error_message(
                            response
                                .error
                                .as_deref()
                                .unwrap_or("Invalid verification code."),
                        ));
                    }
                    next_step(&id, response.next_step.as_deref())?;
                    Ok(None)
                }
            },
        ));
        let request = id.clone();
        body.push(ui::action(
            scope,
            "Resend code",
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
                    Ok(Some("A new verification code has been sent.".into()))
                }
            },
        ));
        if !phone {
            let request = id.clone();
            let reload = reload.clone();
            let change_state = Action::new(scope);
            let form = ui::form(
                scope,
                "registration-change-email",
                vec![
                    Field::new(
                        scope,
                        "Email address",
                        status.pending_email.unwrap_or_default(),
                    )
                    .email()
                    .required(),
                ],
                "Update email",
                "btn btn-primary btn-block",
                change_state,
                move |values| {
                    let path = format!("/account/auth/register/{}/change-email", encode(&request));
                    let reload = reload.clone();
                    async move {
                        let response = api::api_post::<ChangeRegistrationEmailOutcome>(
                            &path,
                            serde_json::json!({"email":values[0]}),
                        )
                        .await?;
                        if response.status != "updated" {
                            return Err(error_message(
                                response.error.as_deref().unwrap_or("Email update failed."),
                            ));
                        }
                        reload.reload();
                        Ok(Some(
                            "Your email has been updated and a new code has been sent.".into(),
                        ))
                    }
                },
            );
            body.push(ui::disclosure(
                scope,
                "change-email",
                "Change email address",
                form,
                false,
            ));
        }
        auth_card(
            if phone {
                "Verify your phone"
            } else {
                "Verify your email"
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
                            return Err(error_message(
                                response
                                    .error
                                    .as_deref()
                                    .unwrap_or("Unable to save display name."),
                            ));
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
                                response.error.as_deref().unwrap_or("Unable to continue."),
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
                "Create your account",
                vec![
                    copy(
                        "text-secondary",
                        "If you are claiming the initial administrator account, enter the bootstrap token below. Leave it blank to continue as a regular user, or enter the correct token to claim the first administrator account.",
                    ),
                    ui::form(
                        scope,
                        "registration-finish",
                        vec![Field::new(scope, "Bootstrap admin token (optional)", "").password()],
                        "Create account",
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
                "Create your account",
                vec![
                    plain("Completing registration…"),
                    state.messages(),
                    ui::action(
                        scope,
                        "Try again",
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
        return Err(error_message(
            response
                .error
                .as_deref()
                .unwrap_or("Could not complete registration."),
        ));
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
    match code{
    "invalid_code"=>"Incorrect code. Please try again.".into(),"invalid_display_name"=>t("coauth-errors-display-name-invalid"),"rate_limited"=>"Please wait a moment and try again.".into(),"registration_already_completed"=>"This registration has already been completed.".into(),"email_already_verified"=>"This email has already been verified.".into(),"email_invalid"=>"Please enter a valid email address.".into(),"email_in_use"=>"This email is already in use.".into(),"bootstrap_admin_token_invalid"=>"That admin bootstrap token is not valid. Clear the field to continue as a regular user, or enter the correct token to claim the first administrator account.".into(),other=>other.into(),}
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
}
