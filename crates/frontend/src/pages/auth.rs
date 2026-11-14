use super::auth_card;
use crate::api::types::*;
use crate::api::{self};
use crate::translations::t;
use crate::ui::{self, *};

pub fn login(scope: &Scope) -> View {
    let query = {
        #[cfg(target_arch = "wasm32")]
        {
            web_sys::window()
                .and_then(|w| w.location().search().ok())
                .unwrap_or_default()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            String::new()
        }
    };
    let request_query = query.clone();
    let providers = ui::resource(scope, move || {
        let path = format!("/account/auth/providers{request_query}");
        async move { api::api_get::<ProvidersOutcome>(&path).await }
    });
    let retry = providers.clone();
    ui::reactive(providers.data, move |scope, result| {
        let (providers, error) = match result {
            Some(Ok(value)) => (value, None),
            Some(Err(error)) => (
                ProvidersOutcome {
                    providers: vec![],
                    password_login_enabled: true,
                    passkey_login_enabled: false,
                    password_registration_enabled: false,
                    password_registration_contact_required: true,
                    phone_verification_enabled: false,
                    account_recovery_allowed: true,
                    login_hint: None,
                    current_account: None,
                },
                Some(error),
            ),
            None => return copy("loading-screen", crate::translations::t("ui-loading")),
        };
        let mut body = vec![];
        if let Some(error) = error {
            body.push(alert(error, false));
            let retry = retry.clone();
            body.push(button(
                crate::translations::t("ui-try-again"),
                "btn btn-secondary",
                move || {
                    retry.reload();
                },
            ));
        }
        body.push(login_form(scope, providers, query.clone()));
        block("", body)
    })
}
fn login_form(scope: &Scope, providers: ProvidersOutcome, query: String) -> View {
    let initial = providers.login_hint.clone().unwrap_or_default();
    let fixed_hint = !initial.trim().is_empty();
    let identifier = Field::new(scope, t("common-handle"), initial)
        .required()
        .placeholder(t("coauth-login-handle-or-email"));
    let handle = identifier.value;
    let password = Field::new(scope, t("common-password"), "")
        .password()
        .required();
    let password_value = password.value;
    let step = scope.cage(fixed_hint);
    let state = Action::new(scope);
    let mut children = vec![];
    if providers.password_login_enabled || providers.passkey_login_enabled {
        let password_enabled = providers.password_login_enabled;
        let passkey_enabled = providers.passkey_login_enabled;
        let current = providers.current_account.clone();
        children.push(ui::reactive(step,move |scope,password_step|{
            let mut body=vec![];
            if !password_step {
                if let Some(account)=current.as_ref().filter(|account|{
                    let hint=handle.get_untracked();hint.is_empty()||account.username.eq_ignore_ascii_case(&hint)||account.handle.eq_ignore_ascii_case(&hint)
                }){
                    let username=account.username.clone();let label=account.display_name.as_deref().filter(|value|!value.trim().is_empty()).unwrap_or(&account.handle).to_owned();
                    body.push(button(crate::translations::t_with("ui-continue-as", &[("name", &label)]),"btn btn-secondary btn-block login-current-account-button",move ||{handle.revise(|v|v.clone_from(&username));password_value.revise(String::clear);step.revise(|v|*v=true);}));
                    body.push(copy("login-divider",t("coauth-login-separator")));
                }
                body.push(ui::form(scope,"login-identifier",vec![identifier.clone()],t("action-continue"),"btn btn-primary btn-block",state,move |values|async move{
                    if values[0].trim().is_empty(){return Err(t("coauth-errors-identifier-required"))}password_value.revise(String::clear);step.revise(|v|*v=true);Ok(None)
                }));
            }else{
                body.push(block("login-selected-account",vec![copy("login-selected-avatar",handle.get_untracked().chars().next().map_or("?".into(),|c|c.to_uppercase().to_string())),block("login-selected-copy",vec![copy("login-selected-label",crate::translations::t("ui-selected-account")),copy("font-semibold",handle.get_untracked())])]));
                if password_enabled{
                    body.push(ui::form(scope,"login-password",vec![password.clone()],t("action-sign-in"),"btn btn-primary btn-block",state,move |values|async move{
                        let response=api::api_post::<LoginOutcome>("/account/auth/login",serde_json::json!({"handle":handle.get_untracked(),"password":values[0]})).await?;
                        if response.status=="success"{ui::auth_success()}else{Err(login_error(response.error.as_deref().unwrap_or("login_failed")))}
                    }));
                }
                if passkey_enabled{
                    body.push(ui::action(scope,&crate::translations::t("ui-sign-in-with-a-passkey"),"btn btn-secondary btn-block",state,move ||async move{crate::passkey::authenticate(handle.get_untracked()).await?;ui::auth_success()}));
                }
                if !fixed_hint{body.push(button(t("coauth-approval-use-another-account"),"btn btn-tertiary btn-block",move ||{password_value.revise(String::clear);state.feedback.revise(|v|*v=None);step.revise(|v|*v=false);}));}
                if providers.account_recovery_allowed{body.push(link(t("coauth-login-forgot-password"),"/recover","link login-links"));}
            }
            block("form-root",body)
        }));
    }
    if !providers.providers.is_empty() && providers.password_login_enabled {
        children.push(copy("login-divider", t("coauth-login-separator")));
    }
    let links = providers
        .providers
        .iter()
        .map(|provider| {
            let name = provider
                .human_name
                .clone()
                .unwrap_or_else(|| provider.id.clone());
            let target = if query.is_empty() {
                provider.authorize_url.clone()
            } else {
                format!(
                    "{}{}{}",
                    provider.authorize_url,
                    if provider.authorize_url.contains('?') {
                        "&"
                    } else {
                        "?"
                    },
                    query.trim_start_matches('?')
                )
            };
            link_to_url(
                crate::translations::t_with(
                    "coauth-login-continue-with-provider",
                    &[("provider", &name)],
                ),
                target,
                "btn btn-secondary btn-block",
            )
        })
        .collect();
    children.push(block("login-providers", links));
    if !providers.password_login_enabled && providers.providers.is_empty() {
        children.push(copy(
            "alert alert-warning",
            t("coauth-login-no-login-methods"),
        ));
    }
    if providers.password_registration_enabled {
        children.push(block(
            "login-register",
            vec![
                plain(t("coauth-login-call-to-register")),
                link(
                    t("action-create-account"),
                    format!("/register{query}"),
                    "link",
                ),
            ],
        ));
    }
    auth_card(t("coauth-login-headline"), children)
}
fn login_error(code: &str) -> String {
    match code {
        "invalid_credentials" => t("coauth-errors-invalid-credentials"),
        "rate_limited" => t("coauth-errors-rate-limit-exceeded"),
        "account_deactivated" => t("coauth-errors-account-deactivated"),
        "account_locked" => t("coauth-errors-account-locked"),
        "password_login_disabled" => t("coauth-errors-password-login-disabled"),
        "login_failed" => t("coauth-errors-login-failed"),
        other => other.into(),
    }
}
pub fn recovery_start(scope: &Scope) -> View {
    let state = Action::new(scope);
    let email = Field::new(scope, t("common-email-address"), "")
        .email()
        .required();
    auth_card(
        &crate::translations::t("ui-recover-account-sign-in"),
        vec![
            copy(
                "recovery-stage",
                crate::translations::t("ui-step-1-of-3-request-a-sign-in-recovery-link"),
            ),
            copy(
                "text-secondary",
                crate::translations::t(
                    "ui-this-flow-restores-account-sign-in-it-does-not-r-06eaf49f",
                ),
            ),
            copy(
                "text-secondary",
                crate::translations::t(
                    "ui-enter-the-email-address-associated-with-your-acc-28865110",
                ),
            ),
            ui::form(
                scope,
                "recovery-start",
                vec![email],
                crate::translations::t("ui-send-recovery-email"),
                "btn btn-primary btn-block",
                state,
                |values| async move {
                    let response = api::api_post::<RecoveryStartOutcome>(
                        "/account/auth/recovery",
                        serde_json::json!({"email":values[0]}),
                    )
                    .await?;
                    if response.status == "success" {
                        let id = response.id.ok_or(crate::translations::t(
                            "ui-recovery-response-did-not-provide-a-progress-id",
                        ))?;
                        go(&format!("/recover/progress/{}", encode(&id)))?;
                        Ok(None)
                    } else {
                        Err(response.error.unwrap_or_else(|| {
                            crate::translations::t("ui-unable-to-start-recovery").into()
                        }))
                    }
                },
            ),
            link(
                crate::translations::t("ui-back-to-sign-in"),
                "/login",
                "link",
            ),
        ],
    )
}
pub fn recovery_progress(scope: &Scope, id: String) -> View {
    let request = id.clone();
    let data = ui::resource(scope, move || {
        let path = format!("/account/auth/recovery/{}", encode(&request));
        async move { api::api_get::<RecoveryStatusOutcome>(&path).await }
    });
    ui::resource_body(data, move |scope, response| {
        let mut body = vec![copy(
            "recovery-stage",
            crate::translations::t("ui-step-2-of-3-open-the-link-in-your-email"),
        )];
        match response.status.as_str() {
            "consumed" => body.push(copy(
                "alert alert-info",
                crate::translations::t("ui-this-recovery-link-has-already-been-used"),
            )),
            "disabled" => body.push(copy(
                "alert alert-warning",
                crate::translations::t("ui-account-recovery-is-not-available"),
            )),
            _ => {
                body.push(copy(
                    "text-secondary",
                    crate::translations::t_with(
                        "ui-recovery-email-address",
                        &[("email", &response.email)],
                    ),
                ));
                let request = id.clone();
                let state = Action::new(scope);
                body.push(state.messages());
                body.push(ui::action(
                    scope,
                    &crate::translations::t("ui-resend-recovery-email"),
                    "btn btn-secondary btn-block",
                    state,
                    move || {
                        let path = format!("/account/auth/recovery/{}/resend", encode(&request));
                        async move {
                            api::api_post::<serde_json::Value>(&path, serde_json::json!({}))
                                .await?;
                            Ok(Some(
                                crate::translations::t("ui-recovery-email-resent").into(),
                            ))
                        }
                    },
                ));
            }
        }
        body.push(link(
            crate::translations::t("ui-back-to-sign-in"),
            "/login",
            "link",
        ));
        auth_card(&crate::translations::t("ui-check-your-email"), body)
    })
}
pub fn password_change(scope: &Scope) -> View {
    let viewer = ui::resource(scope, || api::api_get::<ViewerOutcome>("/self/viewer"));
    ui::resource_body(viewer, move |scope, response| {
        let Some(user) = response.viewer.as_user() else {
            let _ = go("/login");
            return plain(crate::translations::t("ui-redirecting-to-login"));
        };
        let id = user.id.clone();
        let fields = vec![
            Field::new(scope, t("coauth-change-password-current"), "")
                .password()
                .required(),
            Field::new(scope, crate::translations::t("ui-new-password"), "")
                .new_password()
                .required(),
            Field::new(scope, crate::translations::t("ui-confirm-new-password"), "")
                .password()
                .required(),
        ];
        let state = Action::new(scope);
        stack(vec![
            note(
                t("coauth-change-password-heading"),
                t("coauth-change-password-description"),
            ),
            ui::form(
                scope,
                "password-change",
                fields,
                crate::translations::t("ui-change-password"),
                "btn btn-primary",
                state,
                move |values| {
                    let id = id.clone();
                    async move {
                        validate_passwords(&values[1], &values[2])?;
                        let response=api::api_post::<SetPasswordPayload>("/viewer/password",serde_json::json!({"user_id":id,"current_password":values[0],"new_password":values[1]})).await?;
                        match response.status {
                            SetPasswordStatus::Allowed => {
                                go("/password/change/success")?;
                                Ok(None)
                            }
                            other => Err(password_error(&other)),
                        }
                    }
                },
            ),
            link(
                crate::translations::t("ui-cancel"),
                "/settings",
                "btn btn-tertiary",
            ),
        ])
    })
}
pub fn password_recovery(scope: &Scope) -> View {
    let ticket = get_query("ticket").unwrap_or_default();
    if ticket.is_empty() {
        return auth_card(
            &crate::translations::t("ui-reset-password"),
            vec![
                alert(
                    crate::translations::t("ui-no-recovery-ticket-found-in-the-url"),
                    false,
                ),
                link(
                    crate::translations::t("ui-start-a-new-recovery"),
                    "/recover",
                    "btn btn-primary",
                ),
            ],
        );
    }
    let request = ticket.clone();
    let data = ui::resource(scope, move || {
        let path = format!("/account/password-recovery/{}", encode(&request));
        async move { api::api_get::<RecoveryTicketStatusOutcome>(&path).await }
    });
    let reload = data.clone();
    ui::resource_body(data, move |scope, response| {
        let state = Action::new(scope);
        let mut children = vec![
            copy(
                "recovery-stage",
                crate::translations::t("ui-step-3-of-3-set-a-new-sign-in-password"),
            ),
            copy(
                "text-secondary",
                crate::translations::t(
                    "ui-changing-this-password-restores-this-sign-in-met-ebdc1ad5",
                ),
            ),
        ];
        if response.status == "valid" {
            let ticket = ticket.clone();
            let reload = reload.clone();
            children.push(ui::form(
                scope,
                "password-recovery",
                vec![
                    Field::new(scope, crate::translations::t("ui-new-password"), "")
                        .new_password()
                        .required(),
                    Field::new(scope, crate::translations::t("ui-confirm-new-password"), "")
                        .password()
                        .required(),
                ],
                crate::translations::t("ui-reset-password"),
                "btn btn-primary btn-block",
                state,
                move |values| {
                    let ticket = ticket.clone();
                    let reload = reload.clone();
                    async move {
                        validate_passwords(&values[0], &values[1])?;
                        let response = api::api_post::<SetPasswordPayload>(
                            "/account/password-recovery/set",
                            serde_json::json!({"ticket":ticket,"new_password":values[0]}),
                        )
                        .await?;
                        match response.status {
                            SetPasswordStatus::Allowed => {
                                go("/password/change/success")?;
                                Ok(None)
                            }
                            SetPasswordStatus::ExpiredRecoveryTicket
                            | SetPasswordStatus::RecoveryTicketAlreadyUsed
                            | SetPasswordStatus::NoSuchRecoveryTicket => {
                                reload.reload();
                                Err(password_error(&response.status))
                            }
                            other => Err(password_error(&other)),
                        }
                    }
                },
            ));
        } else {
            children.push(alert(
                match response.status.as_str() {
                    "expired" => crate::translations::t("ui-this-recovery-link-has-expired"),
                    "consumed" => {
                        crate::translations::t("ui-this-recovery-link-has-already-been-used")
                    }
                    "disabled" => crate::translations::t("ui-account-recovery-is-not-available"),
                    _ => crate::translations::t("ui-invalid-recovery-ticket"),
                },
                false,
            ));
            if response.status == "expired" {
                let ticket = ticket.clone();
                children.push(state.messages());
                children.push(ui::action(
                    scope,
                    &crate::translations::t("ui-send-a-new-recovery-email"),
                    "btn btn-secondary btn-block",
                    state,
                    move || {
                        let ticket = ticket.clone();
                        async move {
                            let response = api::api_post::<ResendRecoveryEmailPayload>(
                                "/account/password-recovery/resend",
                                serde_json::json!({"ticket":ticket}),
                            )
                            .await?;
                            if let Some(url) = response.progress_url {
                                go_to_url(&url)?;
                                Ok(None)
                            } else {
                                Ok(Some(
                                    crate::translations::t(
                                        "ui-recovery-email-sent-check-your-inbox",
                                    )
                                    .into(),
                                ))
                            }
                        }
                    },
                ));
            }
        }
        children.push(copy(
            "text-sm text-secondary",
            crate::translations::t("ui-changing-your-account-password-does-not-reset-de-de98128d"),
        ));
        children.push(link(
            crate::translations::t("ui-back-to-sign-in"),
            "/login",
            "link",
        ));
        auth_card(&crate::translations::t("ui-reset-password"), children)
    })
}
pub fn email_verify(scope: &Scope, id: String) -> View {
    let request = id.clone();
    let data = ui::resource(scope, move || {
        let path = format!("/account/email-auth/{}", encode(&request));
        async move { api::api_get::<UserEmailAuthentication>(&path).await }
    });
    let reload = data.clone();
    ui::resource_body(data, move |scope, response| {
        if response.completed_at.is_some() {
            return auth_card(
                &crate::translations::t("ui-email-verified"),
                vec![
                    copy(
                        "alert alert-success",
                        crate::translations::t("ui-your-email-address-has-been-verified"),
                    ),
                    link(
                        crate::translations::t("ui-back-to-settings"),
                        "/settings",
                        "btn btn-primary",
                    ),
                ],
            );
        }
        let mut children = vec![copy(
            "text-secondary",
            crate::translations::t_with("ui-verification-sent-to", &[("email", &response.email)]),
        )];
        let state = Action::new(scope);
        let request = id.clone();
        let reload = reload.clone();
        children.push(ui::form(
            scope,
            "email-verify",
            vec![Field::new(scope, crate::translations::t("ui-verification-code"), "").required()],
            crate::translations::t("ui-verify-email"),
            "btn btn-primary btn-block",
            state,
            move |values| {
                let path = format!("/account/email-auth/{}/complete", encode(&request));
                let reload = reload.clone();
                async move {
                    let response = api::api_post::<CompleteEmailAuthPayload>(
                        &path,
                        serde_json::json!({"code":values[0]}),
                    )
                    .await?;
                    match response.status {
                        CompleteEmailAuthStatus::Completed => {
                            reload.reload();
                            Ok(None)
                        }
                        CompleteEmailAuthStatus::InvalidCode => {
                            Err(crate::translations::t("ui-invalid-verification-code").into())
                        }
                        CompleteEmailAuthStatus::NotFound => {
                            Err(crate::translations::t("ui-verification-not-found").into())
                        }
                    }
                }
            },
        ));
        let request = id.clone();
        children.push(ui::action(
            scope,
            &crate::translations::t("ui-resend-code"),
            "btn btn-secondary btn-block",
            state,
            move || {
                let path = format!("/account/email-auth/{}/resend", encode(&request));
                async move {
                    api::api_post::<ResendEmailAuthCodePayload>(&path, serde_json::json!({}))
                        .await?;
                    Ok(Some(
                        crate::translations::t("ui-verification-code-sent").into(),
                    ))
                }
            },
        ));
        children.push(link(
            crate::translations::t("ui-back-to-settings"),
            "/settings",
            "link",
        ));
        auth_card(&crate::translations::t("ui-verify-your-email"), children)
    })
}
pub fn validate_passwords(password: &str, confirmation: &str) -> std::result::Result<(), String> {
    if password.is_empty() {
        Err(crate::translations::t("ui-password-is-required").into())
    } else if password != confirmation {
        Err(crate::translations::t("ui-passwords-do-not-match").into())
    } else {
        Ok(())
    }
}
fn password_error(status: &SetPasswordStatus) -> String {
    match status {
        SetPasswordStatus::WrongPassword => {
            crate::translations::t("ui-current-password-is-incorrect")
        }
        SetPasswordStatus::InvalidNewPassword => {
            crate::translations::t("ui-new-password-does-not-meet-the-requirements")
        }
        SetPasswordStatus::AccountLocked => {
            crate::translations::t("ui-this-account-is-locked-and-cannot-be-recovered")
        }
        SetPasswordStatus::PasswordChangesDisabled => {
            crate::translations::t("ui-password-changes-are-not-available")
        }
        SetPasswordStatus::DeviceTrustRecoveryRequired => {
            crate::translations::t("ui-password-recovery-cannot-reset-device-trust-use-f02e4d34")
        }
        SetPasswordStatus::ExpiredRecoveryTicket => {
            crate::translations::t("ui-this-recovery-link-has-expired")
        }
        SetPasswordStatus::RecoveryTicketAlreadyUsed => {
            crate::translations::t("ui-this-recovery-link-has-already-been-used")
        }
        SetPasswordStatus::NoSuchRecoveryTicket => {
            crate::translations::t("ui-invalid-recovery-ticket")
        }
        _ => crate::translations::t("ui-an-error-occurred-while-changing-your-password"),
    }
    .into()
}
