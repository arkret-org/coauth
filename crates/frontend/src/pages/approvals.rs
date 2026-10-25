use std::collections::BTreeMap;

use coauth_account_types::{UpstreamLinkActionOutcome, UpstreamLinkState};
use serde::{Deserialize, Serialize};

use super::auth_card;
use crate::api::types::*;
use crate::api::{self};
use crate::ui::{self, *};

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
            return plain("Redirecting to login…");
        }
        if response.policy_violation {
            return auth_card(
                "Access Denied",
                vec![alert(
                    "This authorization request was denied by policy.",
                    false,
                )],
            );
        }
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
                    copy("form-label", "This will allow the application to:"),
                    Box::new(sapid::text_list().unstyled().items(items)),
                ],
            ));
        }
        body.push(state.messages());
        let request = grant.clone();
        body.push(ui::action(
            scope,
            if device { "Approve" } else { "Allow" },
            "btn btn-primary btn-block",
            state,
            move || {
                let id = request.clone();
                async move {
                    let path = format!("{prefix}/{}/decision", encode(&id));
                    if device {
                        let response = api::api_post::<DeviceApprovalOutcome>(
                            &path,
                            serde_json::json!({"action":"approve"}),
                        )
                        .await?;
                        if response.status != "fulfilled" {
                            return Err(format!("Unexpected status: {}", response.status));
                        }
                        done.revise(|value| {
                            *value = Some(
                                "Device authorized successfully. You can now use the device."
                                    .into(),
                            );
                        });
                        Ok(None)
                    } else {
                        let response = api::api_post::<OAuthApprovalSubmitOutcome>(
                            &path,
                            serde_json::json!({"action":"approve"}),
                        )
                        .await?;
                        if response.error.as_deref() == Some("not_authenticated") {
                            go(&format!(
                                "/login?kind=continue_authorization_grant&id={}",
                                encode(&id)
                            ))?;
                            return Ok(None);
                        }
                        if response.status != "success" {
                            return Err(response
                                .error
                                .unwrap_or_else(|| "Authorization failed.".into()));
                        }
                        go(&response
                            .redirect_url
                            .ok_or("No redirect URL in response.")?)?;
                        Ok(None)
                    }
                }
            },
        ));
        if device {
            let request = grant.clone();
            body.push(ui::action(
                scope,
                "Deny",
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
                            return Err(format!("Unexpected status: {}", response.status));
                        }
                        done.revise(|value| {
                            *value = Some("Device authorization was rejected.".into());
                        });
                        Ok(None)
                    }
                },
            ));
        }
        if let Some(uri) = response.client.client_uri {
            body.push(link(format!("About {name}"), uri, "link"));
        }
        let title = if device {
            "Authorize device".into()
        } else {
            format!("Authorize {name}")
        };
        let pending = std::cell::RefCell::new(Some(auth_card(title, body)));
        ui::reactive(done, move |_, message| match message {
            Some(message) => auth_card(
                "Device authorization",
                vec![
                    copy("alert alert-info", message),
                    link("Go to account", "/settings", "btn btn-primary btn-block"),
                ],
            ),
            None => pending
                .borrow_mut()
                .take()
                .unwrap_or_else(|| plain("Waiting for authorization…")),
        })
    })
}
pub fn device_link(scope: &Scope) -> View {
    let state = Action::new(scope);
    auth_card(
        "Link a device",
        vec![
            copy(
                "text-secondary",
                "Enter the code displayed on the device you want to link.",
            ),
            ui::form(
                scope,
                "device-link",
                vec![
                    Field::new(scope, "Device code", "")
                        .required()
                        .placeholder("ABCD-EFGH"),
                ],
                "Continue",
                "btn btn-primary btn-block",
                state,
                |values| async move {
                    let response = api::api_get::<DeviceLinkOutcome>(&format!(
                        "/device-link?code={}",
                        encode(&values[0])
                    ))
                    .await?;
                    if response.status != "valid" {
                        return Err("Invalid or expired code. Please try again.".into());
                    }
                    let id = response
                        .grant_id
                        .ok_or("Device response did not provide a grant ID")?;
                    go(&format!("/device/{}", encode(&id)))?;
                    Ok(None)
                },
            ),
            link("Back to account", "/", "link"),
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
            .unwrap_or_else(|| "Unknown client".into());
        let mut head = vec![];
        if let Some(uri) = client.logo_uri {
            head.push(Box::new(image().class("client-logo").source(uri).alt(name.clone())) as View);
        }
        head.push(heading(1, "heading-xs", name));
        let mut rows = vec![block(
            "metadata-row",
            vec![copy("key", "Client ID"), copy("value", client.client_id)],
        )];
        for (label, uri) in [
            ("Client URI", client.client_uri),
            ("Terms of Service", client.tos_uri),
            ("Privacy Policy", client.policy_uri),
        ] {
            if let Some(uri) = uri {
                rows.push(block(
                    "metadata-row",
                    vec![copy("key", label), link(uri.clone(), uri, "value link")],
                ));
            }
        }
        stack(vec![
            link("← Back to sessions", "/sessions", "text-sm"),
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
            Field::new(scope, "Locale", "en").choices([
                ("en", "English"),
                ("zh-CN", "Chinese, Simplified (zh-CN)"),
                ("zh-Hant", "Chinese, Traditional (zh-Hant)"),
                ("ja", "Japanese (ja)"),
                ("ko", "Korean (ko)"),
                ("es", "Español (es)"),
                ("fr", "Français (fr)"),
                ("de", "Deutsch (de)"),
            ]),
            Field::new(scope, "Display name", "").placeholder("Empty value clears this locale"),
            Field::new(scope, "Description (optional)", ""),
        ],
        "Save",
        "btn btn-primary",
        state,
        move |values| {
            let path = format!("/local/admin/oauth/clients/{}/i18n", encode(&id));
            let reload = reload.clone();
            async move {
                api::api_post::<I18nOutcome>(&path,serde_json::json!({"locale":values[0],"display_name":values[1],"description":(!values[2].trim().is_empty()).then(||values[2].clone())})).await?;
                reload.reload();
                Ok(Some(format!("Saved locale {}", values[0])))
            }
        },
    );
    stack(vec![
        heading(1, "heading-xs", "OAuth Client i18n editor"),
        heading(2, "heading-2xs", "Existing locales"),
        entries,
        heading(2, "heading-2xs", "Add / update entry"),
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
            let _ = go(&redirect_url);
            copy("loading-screen", "Redirecting…")
        }
        UpstreamLinkState::SuggestLink {
            provider_name,
            upstream_subject,
        } => {
            let state = Action::new(scope);
            let id = id.clone();
            auth_card(
                "Link Account",
                vec![
                    copy(
                        "text-secondary",
                        format!(
                            "Would you like to link your account with {}{}?",
                            provider_name.unwrap_or_else(|| "the external provider".into()),
                            upstream_subject
                                .map(|subject| format!(" ({subject})"))
                                .unwrap_or_default()
                        ),
                    ),
                    state.messages(),
                    ui::action(
                        scope,
                        "Link Account",
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
            "Account Mismatch",
            vec![
                copy(
                    "text-secondary",
                    format!(
                        "This external account is already linked to another user: {existing_handle}."
                    ),
                ),
                copy(
                    "text-secondary",
                    "Please log out and sign in with the correct account, or contact your administrator.",
                ),
                link("Go to Home", "/", "btn btn-primary btn-block"),
            ],
        ),
        UpstreamLinkState::AccountLocked { handle } => auth_card(
            "Account Locked",
            vec![
                copy(
                    "text-secondary",
                    format!("The account {handle} has been locked."),
                ),
                plain("Please contact your administrator for assistance."),
            ],
        ),
        UpstreamLinkState::AccountDeactivated { handle } => auth_card(
            "Account Deactivated",
            vec![
                copy(
                    "text-secondary",
                    format!("The account {handle} has been deactivated."),
                ),
                plain("Please contact your administrator for assistance."),
            ],
        ),
        UpstreamLinkState::Error { code, description } => {
            auth_card(format!("Error: {code}"), vec![alert(description, false)])
        }
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
                format!(
                    "Complete your registration with {}.",
                    provider_name.unwrap_or_else(|| "external provider".into())
                ),
            )];
            if suggested_display_name.is_some() && !display_name_forced {
                children.push(ui::checkbox(
                    scope,
                    "import-name",
                    "Import display name",
                    import_name,
                    true,
                ));
            }
            if suggested_email.is_some() && !email_forced {
                children.push(ui::checkbox(
                    scope,
                    "import-email",
                    "Import email address",
                    import_email,
                    true,
                ));
            }
            if has_tos {
                children.push(ui::checkbox(
                    scope,
                    "accept-terms",
                    "I accept the Terms of Service",
                    terms,
                    true,
                ));
            }
            let id = id.clone();
            children.push(ui::form(scope,"upstream-register",vec![Field::new(scope,"Username",initial).required().readonly(handle_forced)],"Register","btn btn-primary btn-block",state,move |values|{let id=id.clone();let fixed=fixed_handle.clone();async move{
                if has_tos&&!terms.get_untracked(){return Err("You must accept the Terms of Service.".into())}upstream_action(&id,serde_json::json!({"action":"register","handle":if handle_forced{fixed}else{values[0].clone()},"import_email":email_forced||import_email.get_untracked(),"import_display_name":display_name_forced||import_name.get_untracked(),"accept_terms":terms.get_untracked()})).await
            }}));
            auth_card("Create Account", children)
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
            go(&redirect_url)?;
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
        "openid" => "Verify your identity with coauth",
        "profile" => "View your basic account profile",
        "email" => "View your verified email address",
        "phone" => "View your phone number",
        "address" => "View your address",
        "urn:arkret:station:session.bind" => {
            "Receive a short-lived session grant bound to this login session"
        }
        other if other.starts_with("urn:arkret:station:") => "Act as a trusted Station integration",
        other if other.starts_with("urn:arkret:client:") => {
            "Use Arkret client capabilities on your behalf"
        }
        other if other == "urn:coauth:admin" || other.starts_with("urn:arkret:admin:") => {
            "Administrative access to coauth management APIs"
        }
        other => other,
    }
    .into()
}
