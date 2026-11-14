use std::collections::BTreeMap;

use coauth_account_types::{UpstreamLinkActionOutcome, UpstreamLinkState};
use serde::{Deserialize, Serialize};

use super::auth_card;
use crate::api::types::*;
use crate::api::{self};
use crate::ui::{self, *};

#[cfg(target_arch = "wasm32")]
fn submit_consent_form(grant: &str, action: &str, csrf: &str) -> std::result::Result<(), String> {
    use web_sys::wasm_bindgen::JsCast as _;
    let window =
        web_sys::window().ok_or(crate::translations::t("ui-browser-window-unavailable"))?;
    let url = format!(
        "{}/self/oauth/authorization-grants/{grant}/decision",
        crate::config::api_base_url()
    );
    let document = window
        .document()
        .ok_or(crate::translations::t("ui-browser-document-unavailable"))?;
    let form = document
        .create_element("form")
        .map_err(|_| crate::translations::t("ui-could-not-create-callback-form"))?
        .dyn_into::<web_sys::HtmlFormElement>()
        .map_err(|_| crate::translations::t("ui-invalid-callback-form"))?;
    form.set_method("post");
    form.set_action(&url);
    for (name, value) in [("action", action), ("csrf_token", csrf)] {
        let input = document
            .create_element("input")
            .map_err(|_| crate::translations::t("ui-could-not-create-callback-field"))?
            .dyn_into::<web_sys::HtmlInputElement>()
            .map_err(|_| crate::translations::t("ui-invalid-callback-field"))?;
        input.set_type("hidden");
        input.set_name(name);
        input.set_value(value);
        form.append_child(&input)
            .map_err(|_| crate::translations::t("ui-could-not-append-callback-field"))?;
    }
    document
        .body()
        .ok_or(crate::translations::t("ui-browser-body-unavailable"))?
        .append_child(&form)
        .map_err(|_| crate::translations::t("ui-could-not-mount-callback-form"))?;
    form.submit()
        .map_err(|_| crate::translations::t("ui-could-not-submit-callback-form"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn submit_consent_form(
    _grant: &str,
    _action: &str,
    _csrf: &str,
) -> std::result::Result<(), String> {
    Err(crate::translations::t("ui-consent-form-submission-requires-a-browser").to_owned())
}

async fn authorization_decision(
    id: &str,
    action: &str,
    csrf_token: Option<String>,
    form_post: bool,
) -> Outcome {
    let csrf_token = csrf_token.ok_or(crate::translations::t(
        "ui-missing-authorization-continuation-restart-sign-in",
    ))?;
    if form_post {
        submit_consent_form(id, action, &csrf_token)?;
        return Ok(None);
    }
    let path = format!("/self/oauth/authorization-grants/{}/decision", encode(id));
    let response = api::api_post::<OAuthApprovalSubmitOutcome>(
        &path,
        serde_json::json!({"action": action, "csrf_token": csrf_token}),
    )
    .await?;
    if response.error.as_deref() == Some("not_authenticated") {
        go(&format!(
            "/login?kind=continue_authorization_grant&id={}",
            encode(id)
        ))?;
        return Ok(None);
    }
    if response.status != "success" {
        return Err(response
            .error
            .unwrap_or_else(|| crate::translations::t("ui-authorization-failed").into()));
    }
    if !matches!(
        response.response_mode.as_deref(),
        Some("query" | "fragment")
    ) {
        return Err(crate::translations::t("ui-unsupported-callback-mode").into());
    }
    go_to_url(
        &response
            .redirect_url
            .ok_or(crate::translations::t("ui-no-redirect-url-in-response"))?,
    )?;
    Ok(None)
}

pub fn approval(scope: &Scope, id: String, device: bool) -> View {
    let prefix = if device {
        "/self/device-grants"
    } else {
        "/self/oauth/authorization-grants"
    };
    let request = id.clone();
    let source = ui::resource(scope, move || {
        let path = format!("{prefix}/{}/decision", encode(&request));
        async move { api::api_get::<ApprovalDataOutcome>(&path).await }
    });
    let state = Action::new(scope);
    let done = scope.cage(None::<String>);
    ui::resource_body(source, move |scope, response| {
        if response.error.as_deref() == Some("not_authenticated") {
            let kind = if device {
                "continue_device_code_grant"
            } else {
                "continue_authorization_grant"
            };
            let _ = go(&format!("/login?kind={kind}&id={}", encode(&id)));
            return plain(crate::translations::t("ui-redirecting-to-login"));
        }
        if response.policy_violation {
            return auth_card(
                &crate::translations::t("ui-access-denied"),
                vec![alert(
                    crate::translations::t("ui-this-authorization-request-was-denied-by-policy"),
                    false,
                )],
            );
        }
        let decision_csrf = response.csrf_token.clone();
        let decision_form_post = response.response_mode.as_deref() == Some("form_post");
        let name = response
            .client
            .client_name
            .unwrap_or(response.client.client_id);
        let grant = id.clone();
        let mut body = vec![];
        if let Some(url) = response.client.logo_uri {
            body.push(Box::new(image().class("client-logo").source(url).alt(name.clone())) as View);
        }
        body.push(copy(
            "text-secondary",
            format!(
                "{}{} wants to access your account as {}",
                name,
                if device { " on a new device" } else { "" },
                response.user.principal_address
            ),
        ));
        if !device && !response.scope.is_empty() {
            let items = response
                .scope
                .split_whitespace()
                .map(scope_description)
                .map(|description| sapid::text_list_item().fill(plain(description)))
                .collect::<Vec<_>>();
            body.push(block(
                "approval-scopes",
                vec![
                    copy(
                        "form-label",
                        crate::translations::t("ui-this-will-allow-the-application-to"),
                    ),
                    Box::new(sapid::text_list().unstyled().items(items)),
                ],
            ));
        }
        body.push(state.messages());
        let request = grant.clone();
        let csrf = decision_csrf.clone();
        body.push(ui::action(
            scope,
            if device { "Approve" } else { "Allow" },
            "btn btn-primary btn-block",
            state,
            move || {
                let id = request.clone();
                let csrf = csrf.clone();
                async move {
                    if device {
                        let path = format!("{prefix}/{}/decision", encode(&id));
                        let response = api::api_post::<DeviceApprovalOutcome>(
                            &path,
                            serde_json::json!({"action":"approve"}),
                        )
                        .await?;
                        if response.status != "fulfilled" {
                            return Err(crate::translations::t_with(
                                "ui-unexpected-status",
                                &[("status", &response.status.to_string())],
                            ));
                        }
                        done.revise(|value| {
                            *value = Some(
                                crate::translations::t(
                                    "ui-device-authorized-successfully-you-can-now-use-the-device",
                                )
                                .into(),
                            );
                        });
                        Ok(None)
                    } else {
                        authorization_decision(&id, "approve", csrf, decision_form_post).await
                    }
                }
            },
        ));
        if device {
            let request = grant.clone();
            body.push(ui::action(
                scope,
                &crate::translations::t("ui-deny"),
                "btn btn-secondary btn-block",
                state,
                move || {
                    let path = format!("{prefix}/{}/decision", encode(&request));
                    async move {
                        let response = api::api_post::<DeviceApprovalOutcome>(
                            &path,
                            serde_json::json!({"action":"deny"}),
                        )
                        .await?;
                        if response.status != "rejected" {
                            return Err(crate::translations::t_with(
                                "ui-unexpected-status",
                                &[("status", &response.status.to_string())],
                            ));
                        }
                        done.revise(|value| {
                            *value = Some(
                                crate::translations::t("ui-device-authorization-was-rejected")
                                    .into(),
                            );
                        });
                        Ok(None)
                    }
                },
            ));
        } else {
            let request = grant.clone();
            body.push(ui::action(
                scope,
                &crate::translations::t("ui-deny"),
                "btn btn-secondary btn-block",
                state,
                move || {
                    let id = request.clone();
                    let csrf = decision_csrf.clone();
                    async move {
                        authorization_decision(&id, "deny", csrf, decision_form_post).await
                    }
                },
            ));
        }
        if let Some(uri) = response.client.client_uri {
            body.push(link(
                crate::translations::t_with("ui-about-client", &[("name", &name)]),
                uri,
                "link",
            ));
        }
        let title = if device {
            crate::translations::t("ui-authorize-device").into()
        } else {
            crate::translations::t_with("ui-authorize-client", &[("name", &name)])
        };
        let pending = std::cell::RefCell::new(Some(auth_card(title, body)));
        ui::reactive(done, move |_, message| match message {
            Some(message) => auth_card(
                &crate::translations::t("ui-device-authorization"),
                vec![
                    copy("alert alert-info", message),
                    link(
                        crate::translations::t("ui-go-to-account"),
                        "/settings",
                        "btn btn-primary btn-block",
                    ),
                ],
            ),
            None => pending
                .borrow_mut()
                .take()
                .unwrap_or_else(|| plain(crate::translations::t("ui-waiting-for-authorization"))),
        })
    })
}
pub fn device_link(scope: &Scope) -> View {
    let state = Action::new(scope);
    auth_card(
        &crate::translations::t("ui-link-a-device"),
        vec![
            copy(
                "text-secondary",
                crate::translations::t(
                    "ui-enter-the-code-displayed-on-the-device-you-want-to-link",
                ),
            ),
            ui::form(
                scope,
                "device-link",
                vec![
                    Field::new(scope, crate::translations::t("ui-device-code"), "")
                        .required()
                        .placeholder(crate::translations::t("ui-abcd-efgh")),
                ],
                crate::translations::t("ui-continue"),
                "btn btn-primary btn-block",
                state,
                |values| async move {
                    let response = api::api_get::<DeviceLinkOutcome>(&format!(
                        "/device-link?code={}",
                        encode(&values[0])
                    ))
                    .await?;
                    if response.status != "valid" {
                        return Err(crate::translations::t(
                            "ui-invalid-or-expired-code-please-try-again",
                        )
                        .into());
                    }
                    let id = response.grant_id.ok_or(crate::translations::t(
                        "ui-device-response-did-not-provide-a-grant-id",
                    ))?;
                    go(&format!("/device/{}", encode(&id)))?;
                    Ok(None)
                },
            ),
            link(crate::translations::t("ui-back-to-account"), "/", "link"),
        ],
    )
}
pub fn client(scope: &Scope, id: String) -> View {
    let source = ui::resource(scope, move || {
        let path = format!("/self/oauth-clients/{}", encode(&id));
        async move { api::api_get::<OAuthClientDetail>(&path).await }
    });
    ui::resource_body(source, |_, client| {
        let name = client
            .client_name
            .unwrap_or_else(|| crate::translations::t("ui-unknown-client").into());
        let mut head = vec![];
        if let Some(uri) = client.logo_uri {
            head.push(Box::new(image().class("client-logo").source(uri).alt(name.clone())) as View);
        }
        head.push(heading(1, "heading-xs", name));
        let mut rows = vec![block(
            "metadata-row",
            vec![
                copy("key", crate::translations::t("ui-client-id")),
                copy("value", client.client_id),
            ],
        )];
        for (label, uri) in [
            (crate::translations::t("ui-client-uri"), client.client_uri),
            (
                crate::translations::t("ui-terms-of-service"),
                client.tos_uri,
            ),
            (
                crate::translations::t("ui-privacy-policy-506ff394"),
                client.policy_uri,
            ),
        ] {
            if let Some(uri) = uri {
                rows.push(block(
                    "metadata-row",
                    vec![copy("key", label), link(uri.clone(), uri, "value link")],
                ));
            }
        }
        stack(vec![
            link(
                crate::translations::t("ui-back-to-sessions"),
                "/sessions",
                "text-sm",
            ),
            block("flex items-center gap-4", head),
            block("session-metadata", rows),
        ])
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct I18nEntry {
    display_name: String,
    #[serde(default)]
    description: Option<String>,
}
#[derive(Clone, Deserialize)]
struct I18nOutcome {
    data: BTreeMap<String, I18nEntry>,
}
pub fn client_i18n(scope: &Scope, id: String) -> View {
    let request = id.clone();
    let source = ui::resource(scope, move || {
        let path = format!("/local/admin/oauth/clients/{}/i18n", encode(&request));
        async move { api::api_get::<I18nOutcome>(&path).await }
    });
    let reload = source.clone();
    let state = Action::new(scope);
    let entries = ui::resource_body(source, |_, response| {
        let rows = response
            .data
            .into_iter()
            .map(|(locale, entry)| {
                block(
                    "metadata-row",
                    vec![
                        copy("key", locale),
                        block(
                            "value",
                            vec![
                                copy("font-semibold", entry.display_name),
                                copy(
                                    "text-sm text-secondary",
                                    entry.description.unwrap_or_default(),
                                ),
                            ],
                        ),
                    ],
                )
            })
            .collect();
        block("session-metadata", rows)
    });
    let form = ui::form(
        scope,
        "client-i18n",
        vec![
            Field::new(scope, crate::translations::t("ui-locale"), "en").choices([
                ("en", "English".to_owned()),
                (
                    "zh-CN",
                    crate::translations::t("ui-chinese-simplified-zh-cn"),
                ),
                (
                    "zh-Hant",
                    crate::translations::t("ui-chinese-traditional-zh-hant"),
                ),
                ("ja", crate::translations::t("ui-japanese-ja")),
                ("ko", crate::translations::t("ui-korean-ko")),
                ("es", crate::translations::t("ui-espa-ol-es")),
                ("fr", crate::translations::t("ui-fran-ais-fr")),
                ("de", crate::translations::t("ui-deutsch-de")),
            ]),
            Field::new(scope, crate::translations::t("ui-display-name"), "")
                .placeholder(crate::translations::t("ui-empty-value-clears-this-locale")),
            Field::new(scope, crate::translations::t("ui-description-optional"), ""),
        ],
        crate::translations::t("ui-save"),
        "btn btn-primary",
        state,
        move |values| {
            let path = format!("/local/admin/oauth/clients/{}/i18n", encode(&id));
            let reload = reload.clone();
            async move {
                api::api_post::<I18nOutcome>(&path,serde_json::json!({"locale":values[0],"display_name":values[1],"description":(!values[2].trim().is_empty()).then(||values[2].clone())})).await?;
                reload.reload();
                Ok(Some(crate::translations::t_with(
                    "ui-saved-locale",
                    &[("locale", &values[0])],
                )))
            }
        },
    );
    stack(vec![
        heading(
            1,
            "heading-xs",
            crate::translations::t("ui-oauth-client-i18n-editor"),
        ),
        heading(
            2,
            "heading-2xs",
            crate::translations::t("ui-existing-locales"),
        ),
        entries,
        heading(
            2,
            "heading-2xs",
            crate::translations::t("ui-add-update-entry"),
        ),
        form,
    ])
}
pub fn upstream(scope: &Scope, id: String) -> View {
    let request = id.clone();
    let source = ui::resource(scope, move || {
        let path = format!("/self/upstream-oauth/link/{}", encode(&request));
        async move { api::api_get::<UpstreamLinkState>(&path).await }
    });
    ui::resource_body(source, move |scope, response| match response {
        UpstreamLinkState::Redirect { redirect_url } => {
            let _ = go_to_url(&redirect_url);
            copy("loading-screen", crate::translations::t("ui-redirecting"))
        }
        UpstreamLinkState::SuggestLink {
            provider_name,
            upstream_subject,
        } => {
            let state = Action::new(scope);
            let id = id.clone();
            auth_card(
                &crate::translations::t("ui-link-account"),
                vec![
                    copy(
                        "text-secondary",
                        crate::translations::t_with(
                            "ui-link-provider-question",
                            &[
                                (
                                    "provider",
                                    &provider_name.unwrap_or_else(|| {
                                        crate::translations::t("ui-external-provider")
                                    }),
                                ),
                                (
                                    "subject",
                                    &upstream_subject
                                        .map(|subject| format!(" ({subject})"))
                                        .unwrap_or_default(),
                                ),
                            ],
                        ),
                    ),
                    state.messages(),
                    ui::action(
                        scope,
                        &crate::translations::t("ui-link-account"),
                        "btn btn-primary btn-block",
                        state,
                        move || {
                            let id = id.clone();
                            async move {
                                upstream_action(&id, serde_json::json!({"action":"link"})).await
                            }
                        },
                    ),
                ],
            )
        }
        UpstreamLinkState::LinkMismatch { existing_handle } => auth_card(
            &crate::translations::t("ui-account-mismatch"),
            vec![
                copy(
                    "text-secondary",
                    crate::translations::t_with(
                        "ui-provider-account-conflict",
                        &[("handle", &existing_handle)],
                    ),
                ),
                copy(
                    "text-secondary",
                    crate::translations::t(
                        "ui-please-log-out-and-sign-in-with-the-correct-acco-ee2c5341",
                    ),
                ),
                link(
                    crate::translations::t("ui-go-to-home"),
                    "/",
                    "btn btn-primary btn-block",
                ),
            ],
        ),
        UpstreamLinkState::AccountLocked { handle } => auth_card(
            &crate::translations::t("ui-account-locked"),
            vec![
                copy(
                    "text-secondary",
                    crate::translations::t_with("ui-account-locked-handle", &[("handle", &handle)]),
                ),
                plain(crate::translations::t(
                    "ui-please-contact-your-administrator-for-assistance",
                )),
            ],
        ),
        UpstreamLinkState::AccountDeactivated { handle } => auth_card(
            &crate::translations::t("ui-account-deactivated"),
            vec![
                copy(
                    "text-secondary",
                    crate::translations::t_with(
                        "ui-account-deactivated-handle",
                        &[("handle", &handle)],
                    ),
                ),
                plain(crate::translations::t(
                    "ui-please-contact-your-administrator-for-assistance",
                )),
            ],
        ),
        UpstreamLinkState::Error { code, description } => auth_card(
            crate::translations::t_with("ui-error-code", &[("code", &code)]),
            vec![alert(description, false)],
        ),
        UpstreamLinkState::Register {
            suggested_handle,
            handle_forced,
            suggested_display_name,
            display_name_forced,
            suggested_email,
            email_forced,
            provider_name,
            has_tos,
        } => {
            let import_name = scope.cage(suggested_display_name.is_some());
            let import_email = scope.cage(suggested_email.is_some());
            let terms = scope.cage(false);
            let state = Action::new(scope);
            let initial = suggested_handle.unwrap_or_default();
            let fixed_handle = initial.clone();
            let mut children = vec![copy(
                "text-secondary",
                crate::translations::t_with(
                    "ui-complete-provider-registration",
                    &[(
                        "provider",
                        &provider_name
                            .unwrap_or_else(|| crate::translations::t("ui-external-provider")),
                    )],
                ),
            )];
            if suggested_display_name.is_some() && !display_name_forced {
                children.push(ui::checkbox(
                    scope,
                    "import-name",
                    &crate::translations::t("ui-import-display-name"),
                    import_name,
                    true,
                ));
            }
            if suggested_email.is_some() && !email_forced {
                children.push(ui::checkbox(
                    scope,
                    "import-email",
                    &crate::translations::t("ui-import-email-address"),
                    import_email,
                    true,
                ));
            }
            if has_tos {
                children.push(ui::checkbox(
                    scope,
                    "accept-terms",
                    &crate::translations::t("ui-i-accept-the-terms-of-service"),
                    terms,
                    true,
                ));
            }
            let id = id.clone();
            children.push(ui::form(scope,"upstream-register",vec![Field::new(scope,crate::translations::t("ui-username"),initial).required().readonly(handle_forced)],crate::translations::t("ui-register"),"btn btn-primary btn-block",state,move |values|{let id=id.clone();let fixed=fixed_handle.clone();async move{
                if has_tos&&!terms.get_untracked(){return Err(crate::translations::t("ui-you-must-accept-the-terms-of-service").into())}upstream_action(&id,serde_json::json!({"action":"register","handle":if handle_forced{fixed}else{values[0].clone()},"import_email":email_forced||import_email.get_untracked(),"import_display_name":display_name_forced||import_name.get_untracked(),"accept_terms":terms.get_untracked()})).await
            }}));
            auth_card(&crate::translations::t("ui-create-account"), children)
        }
    })
}
async fn upstream_action(id: &str, body: serde_json::Value) -> Outcome {
    let response = api::api_post::<UpstreamLinkActionOutcome>(
        &format!("/self/upstream-oauth/link/{}", encode(id)),
        body,
    )
    .await?;
    match response {
        UpstreamLinkActionOutcome::Success { redirect_url } => {
            go_to_url(&redirect_url)?;
            Ok(None)
        }
        UpstreamLinkActionOutcome::Error {
            error,
            field_errors,
        } => {
            let mut messages = vec![error];
            if let Some(fields) = field_errors {
                messages.extend(
                    [fields.handle, fields.accept_terms, fields.form]
                        .into_iter()
                        .flatten(),
                );
            }
            Err(messages.join(" · "))
        }
    }
}
fn scope_description(scope: &str) -> String {
    match scope {
        "openid" => crate::translations::t("ui-verify-your-identity-with-coauth"),
        "profile" => crate::translations::t("ui-view-your-basic-account-profile"),
        "email" => crate::translations::t("ui-view-your-verified-email-address"),
        "phone" => crate::translations::t("ui-view-your-phone-number"),
        "address" => crate::translations::t("ui-view-your-address"),
        "urn:arkret:station:session.bind" => crate::translations::t(
            "ui-receive-a-short-lived-session-grant-bound-to-this-login-session",
        ),
        other if other.starts_with("urn:arkret:station:") => {
            crate::translations::t("ui-act-as-a-trusted-station-integration")
        }
        other if other.starts_with("urn:arkret:client:") => {
            crate::translations::t("ui-use-arkret-client-capabilities-on-your-behalf")
        }
        other if other == "urn:coauth:admin" || other.starts_with("urn:arkret:admin:") => {
            crate::translations::t("ui-administrative-access-to-coauth-management-apis")
        }
        other => other.to_owned(),
    }
    .into()
}
