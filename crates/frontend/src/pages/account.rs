use crate::api::types::*;
use crate::api::{self};
use crate::ui::{self, *};

pub fn shell(scope: &Scope, path: String) -> View {
    let viewer = ui::resource(scope, || api::api_get::<ViewerOutcome>("/self/viewer"));
    let refresh = viewer.clone();
    ui::resource_body(viewer, move |scope, response| {
        let Some(user) = response.viewer.as_user().cloned() else {
            let _ = go("/login");
            return plain(crate::translations::t("ui-redirecting-to-login"));
        };
        let Some(principal) = user.principal.clone() else {
            return alert(crate::translations::t("ui-user-data-unavailable"), false);
        };
        let stored = user
            .profile
            .preferred_locale
            .as_deref()
            .and_then(crate::translations::UiLocale::from_tag);
        crate::translations::set_account_locale(stored);
        crate::translations::adopt_requested_locale_into_account(stored);
        let name = user
            .profile
            .display_name
            .clone()
            .or_else(|| principal.display_name.clone())
            .unwrap_or_else(|| principal.principal_address.clone());
        let avatar = if let Some(url) = user.profile.avatar_url.clone() {
            Box::new(
                image()
                    .class("user-avatar")
                    .source(url)
                    .alt(crate::translations::t("ui-avatar")),
            ) as View
        } else {
            copy(
                "user-avatar",
                name.chars()
                    .next()
                    .map_or("?".into(), |c| c.to_uppercase().to_string()),
            )
        };
        let mut profile = vec![
            avatar,
            block(
                "user-meta",
                vec![
                    copy("text-lg font-semibold", name),
                    copy(
                        "user-principal-address",
                        principal.principal_address.clone(),
                    ),
                ],
            ),
        ];
        if response.site_config.display_name_change_allowed {
            profile.push(profile_editor(scope, &user, refresh.clone()));
        }
        let mut nav = vec![block(
            "sidebar-profile",
            vec![block("user-greeting", profile)],
        )];
        for (title, items) in [
            (
                crate::translations::t("ui-account"),
                vec![
                    (crate::translations::t("ui-overview"), "/"),
                    (crate::translations::t("ui-settings"), "/settings"),
                    (crate::translations::t("ui-identities"), "/identities"),
                ],
            ),
            (
                crate::translations::t("ui-security"),
                vec![
                    (crate::translations::t("ui-security"), "/security"),
                    (crate::translations::t("ui-devices"), "/sessions"),
                ],
            ),
        ] {
            let mut group = vec![copy("sidebar-group-label", title)];
            for (label, target) in items {
                group.push(link(
                    label,
                    target,
                    if path == target {
                        "sidebar-item active"
                    } else {
                        "sidebar-item"
                    },
                ));
            }
            nav.push(block("sidebar-nav-group", group));
        }
        if user.can_request_admin
            && let Some(url) = response.site_config.admin_portal_url.clone()
        {
            nav.push(block(
                "sidebar-nav-group",
                vec![
                    copy(
                        "sidebar-group-label",
                        crate::translations::t("ui-administration"),
                    ),
                    link(
                        crate::translations::t("ui-admin-portal-external"),
                        url,
                        "sidebar-item",
                    ),
                ],
            ));
        }
        let mut preferences = vec![
            copy(
                "sidebar-group-label",
                crate::translations::t("ui-preferences"),
            ),
            link(
                crate::translations::t("ui-notifications"),
                "/notifications",
                if path == "/notifications" {
                    "sidebar-item active"
                } else {
                    "sidebar-item"
                },
            ),
        ];
        if response.site_config.plan_management_iframe_uri.is_some() {
            preferences.push(link(
                crate::translations::t("ui-plan"),
                "/plan",
                if path == "/plan" {
                    "sidebar-item active"
                } else {
                    "sidebar-item"
                },
            ));
        }
        nav.push(block("sidebar-nav-group", preferences));
        let body = block(
            "account-layout",
            vec![
                Box::new(
                    view()
                        .role(Role::Navigation)
                        .class("account-sidebar")
                        .fill(nav),
                ),
                block(
                    "account-content",
                    vec![if path == "/" {
                        overview_for_user(scope, user.clone())
                    } else {
                        super::route(scope, &path)
                    }],
                ),
            ],
        );
        block(
            "account-with-preferences",
            vec![super::preferences(scope), super::layout(scope, body, true)],
        )
    })
}
fn profile_editor(
    scope: &Scope,
    user: &coauth_account_types::ViewerUser,
    refresh: Resource<ViewerOutcome>,
) -> View {
    let open = scope.cage(false);
    let state = Action::new(scope);
    let avatar = scope.cage(user.profile.avatar_url.clone());
    let initial = user.profile.display_name.clone().unwrap_or_default();
    let avatar_initial = initial
        .chars()
        .next()
        .map_or("?".to_owned(), |value| value.to_uppercase().to_string());
    let locale = user.profile.preferred_locale.clone().unwrap_or_default();
    let form = ui::form(
        scope,
        "profile-edit",
        vec![
            Field::new(scope, crate::translations::t("ui-display-name"), initial).description(
                crate::translations::t("ui-your-display-name-is-shown-to-other-users"),
            ),
            Field::new(scope, crate::translations::t("ui-language"), locale)
                .description(crate::translations::t(
                    "ui-applies-everywhere-you-sign-in-and-to-the-notifi-53557f56",
                ))
                .choices([
                    ("", crate::translations::t("ui-use-device-language")),
                    ("en", "English".to_owned()),
                    ("zh", "中文".to_owned()),
                ]),
            Field::new(
                scope,
                crate::translations::t("ui-principal-id"),
                user.principal
                    .as_ref()
                    .map(|p| p.principal_address.clone())
                    .unwrap_or_default(),
            )
            .readonly(true),
        ],
        crate::translations::t("ui-save"),
        "btn btn-primary",
        state,
        move |values| {
            let refresh = refresh.clone();
            async move {
                let locale = values[1].trim();
                if !locale.is_empty() && crate::translations::UiLocale::from_tag(locale).is_none() {
                    return Err(crate::translations::t(
                        "ui-choose-a-supported-account-language-en-or-zh-cn",
                    )
                    .into());
                }
                let response=api::api_patch::<PatchViewerProfileOutcome>("/self/viewer/profile",serde_json::json!({"display_name":(!values[0].is_empty()).then(||values[0].clone()),"avatar_url":avatar.get_untracked(),"preferred_locale":(!locale.is_empty()).then_some(locale)})).await?;
                crate::translations::set_account_locale(
                    response
                        .profile
                        .preferred_locale
                        .as_deref()
                        .and_then(crate::translations::UiLocale::from_tag),
                );
                open.revise(|v| *v = false);
                refresh.reload();
                Ok(None)
            }
        },
    );
    let body = stack(vec![
        block(
            "profile-avatar-controls",
            vec![
                ui::reactive(avatar, move |_, url| match url {
                    Some(url) => Box::new(
                        image()
                            .class("user-avatar user-avatar-lg self-center")
                            .source(url)
                            .alt(crate::translations::t("ui-avatar")),
                    ),
                    None => copy(
                        "user-avatar user-avatar-lg self-center",
                        avatar_initial.clone(),
                    ),
                }),
                avatar_upload(scope, avatar, state),
            ],
        ),
        form,
    ]);
    ui::dialog(
        scope,
        "edit-profile",
        &crate::translations::t("ui-edit-profile"),
        "btn btn-tertiary btn-sm",
        body,
        open,
    )
}
fn avatar_upload(scope: &Scope, avatar: Cage<Option<String>>, state: Action) -> View {
    let controller = scope.cage(None::<sapid::FileController>);
    let weak = scope.downgrade();
    let task_scope = weak.clone();
    Box::new(
        sapid::file_button()
            .unstyled()
            .class(scope.bond(move || {
                if state.busy.get() {
                    "btn btn-secondary btn-sm avatar-uploading"
                } else {
                    "btn btn-secondary btn-sm"
                }
                .to_owned()
            }))
            .label(scope.bond(move || {
                if state.busy.get() {
                    crate::translations::t("ui-uploading-avatar")
                } else {
                    crate::translations::t("ui-upload-avatar")
                }
                .to_owned()
            }))
            .controller_ref(controller)
            .configuration(glory::render::FileConfig {
                multiple: false,
                max_files: 1,
                max_file_bytes: 5 * 1024 * 1024,
                max_total_bytes: 5 * 1024 * 1024,
                filters: ["image/png", "image/jpeg", "image/gif", "image/webp"]
                    .into_iter()
                    .map(|value| glory::render::FileFilter::Mime(value.into()))
                    .collect(),
                ..Default::default()
            })
            .on_result(move |result| {
                if let glory::render::FileOutcome::Rejected(reason) = result {
                    state.feedback.revise(|value| {
                        *value = Some(Err(crate::translations::t_with(
                            "ui-avatar-selection-rejected",
                            &[("reason", &format!("{reason:?}"))],
                        )))
                    });
                }
            })
            .on_files(move |files| {
                let Some(file) = files.first().cloned() else {
                    return;
                };
                let Some(control) = controller.get_untracked() else {
                    return;
                };
                let owner = task_scope.clone();
                state.run(&weak, async move {
                    let url = upload_avatar(owner, control.clone(), file).await?;
                    avatar.revise(|value| *value = Some(url));
                    let _ = control.clear();
                    Ok(Some(
                        crate::translations::t("ui-avatar-uploaded-save-your-profile-to-apply-it")
                            .into(),
                    ))
                });
            }),
    )
}
#[cfg(target_arch = "wasm32")]
async fn upload_avatar(
    owner: glory::ui::WeakScope,
    control: sapid::FileController,
    file: glory::render::FileInfo,
) -> std::result::Result<String, String> {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::task::{Poll, Waker};

    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    let mut bytes = Vec::with_capacity(file.size as usize);
    let mut offset = 0u64;
    while offset < file.size {
        let scope = owner
            .upgrade()
            .ok_or(crate::translations::t("ui-avatar-selection-was-closed"))?;
        let result = Rc::new(RefCell::new((None, None::<Waker>)));
        let reply = result.clone();
        control
            .read_in(
                &scope,
                glory::render::FileRead {
                    file: file.token,
                    offset,
                    length: (file.size - offset).min(65536) as u32,
                },
                move |value| {
                    let mut reply = reply.borrow_mut();
                    reply.0 = Some(value);
                    if let Some(waker) = reply.1.take() {
                        waker.wake();
                    }
                },
            )
            .map_err(|error| error.to_string())?;
        let chunk = std::future::poll_fn(move |cx| {
            let mut result = result.borrow_mut();
            match result.0.take() {
                Some(value) => Poll::Ready(value),
                None => {
                    result.1 = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
        .map_err(|error| error.to_string())?;
        if chunk.is_empty() {
            return Err(crate::translations::t("ui-unable-to-read-the-complete-avatar").into());
        }
        offset += chunk.len() as u64;
        bytes.extend(chunk);
    }
    let array = js_sys::Uint8Array::from(bytes.as_slice());
    let parts = js_sys::Array::new();
    parts.push(&array.buffer());
    let properties = web_sys::BlobPropertyBag::new();
    properties.set_type(&file.media_type);
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &properties)
        .map_err(|_| crate::translations::t("ui-unable-to-prepare-avatar"))?;
    let form = web_sys::FormData::new()
        .map_err(|_| crate::translations::t("ui-unable-to-prepare-avatar-upload"))?;
    form.append_with_blob_and_filename("avatar", &blob, &file.name)
        .map_err(|_| crate::translations::t("ui-unable-to-attach-avatar"))?;
    let options = web_sys::RequestInit::new();
    options.set_method("POST");
    options.set_credentials(web_sys::RequestCredentials::SameOrigin);
    options.set_body(&form);
    let request = web_sys::Request::new_with_str_and_init(
        &format!("{}/self/viewer/avatar", crate::config::api_base_url()),
        &options,
    )
    .map_err(|_| crate::translations::t("ui-unable-to-create-avatar-request"))?;
    let window =
        web_sys::window().ok_or(crate::translations::t("ui-browser-window-unavailable"))?;
    let response: web_sys::Response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|error| {
            crate::translations::t_with(
                "ui-avatar-upload-failed",
                &[("error", &format!("{error:?}"))],
            )
        })?
        .dyn_into()
        .map_err(|_| crate::translations::t("ui-invalid-upload-response"))?;
    if !response.ok() {
        return Err(crate::translations::t_with(
            "ui-avatar-http-failed",
            &[("status", &response.status().to_string())],
        ));
    }
    let json = JsFuture::from(
        response
            .json()
            .map_err(|_| crate::translations::t("ui-invalid-avatar-response"))?,
    )
    .await
    .map_err(|_| crate::translations::t("ui-invalid-avatar-response"))?;
    js_sys::Reflect::get(&json, &JsValue::from_str("avatar_url"))
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| crate::translations::t("ui-avatar-response-did-not-provide-a-url").into())
}
#[cfg(not(target_arch = "wasm32"))]
async fn upload_avatar(
    _: glory::ui::WeakScope,
    _: sapid::FileController,
    _: glory::render::FileInfo,
) -> std::result::Result<String, String> {
    Err(crate::translations::t("ui-avatar-upload-requires-a-browser").into())
}

pub fn overview(scope: &Scope) -> View {
    let source = ui::resource(scope, || api::api_get::<ViewerOutcome>("/self/viewer"));
    ui::resource_body(source, |scope, response| {
        match response.viewer.as_user().cloned() {
            Some(user) => overview_for_user(scope, user),
            None => plain(crate::translations::t("ui-sign-in-to-view-your-account")),
        }
    })
}
fn overview_for_user(scope: &Scope, user: coauth_account_types::ViewerUser) -> View {
    let security = ui::resource(scope, || {
        api::api_get::<SecuritySummaryOutcome>("/self/viewer/security")
    });
    ui::resource_body(security, move |_, summary| {
        let pending_emails = user
            .emails
            .as_ref()
            .map(|emails| {
                emails
                    .edges
                    .iter()
                    .filter(|edge| edge.node.confirmed_at.is_none())
                    .map(|edge| edge.node.email.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut sessions = user
            .browser_sessions
            .as_ref()
            .map(|connection| {
                connection
                    .edges
                    .iter()
                    .map(|edge| edge.node.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        sessions.sort_by_key(|session| {
            std::cmp::Reverse(
                session
                    .last_active_at
                    .as_deref()
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok()),
            )
        });
        let mut recent = vec![];
        for session in sessions.into_iter().take(3) {
            recent.push(block(
                "overview-session-row",
                vec![
                    copy(
                        "font-semibold",
                        session
                            .display_name
                            .unwrap_or_else(|| crate::translations::t("ui-browser-session").into()),
                    ),
                    copy(
                        "text-sm text-secondary",
                        session
                            .last_active_at
                            .map(|value| crate::utils::format_date(&value))
                            .unwrap_or_else(|| {
                                crate::translations::t("ui-activity-time-unavailable")
                            }),
                    ),
                    link(
                        crate::translations::t("ui-view-session"),
                        format!("/sessions/{}", encode(&session.id)),
                        "btn btn-secondary btn-sm",
                    ),
                ],
            ));
        }
        if recent.is_empty() {
            recent.push(copy(
                "text-secondary",
                crate::translations::t("ui-no-browser-sessions-are-listed"),
            ));
        }
        let mut children = vec![
            heading(
                1,
                "heading-xs",
                crate::translations::t("ui-account-overview"),
            ),
            copy(
                "text-secondary",
                crate::translations::t(
                    "ui-manage-the-sign-in-methods-and-sessions-for-this-account",
                ),
            ),
            overview_section(
                crate::translations::t("ui-account-summary"),
                vec![
                    details(vec![
                        (
                            crate::translations::t("ui-password-sign-in").into(),
                            if summary.has_password {
                                crate::translations::t("ui-available")
                            } else {
                                crate::translations::t("ui-not-configured")
                            }
                            .into(),
                        ),
                        (
                            crate::translations::t("ui-active-sessions").into(),
                            summary.active_sessions_count.to_string(),
                        ),
                        (
                            crate::translations::t("ui-linked-identity-providers").into(),
                            summary.linked_providers_count.to_string(),
                        ),
                        (
                            crate::translations::t("ui-verified-email-addresses").into(),
                            summary.verified_emails_count.to_string(),
                        ),
                        (
                            crate::translations::t("ui-verified-phone-numbers").into(),
                            summary.verified_phones_count.to_string(),
                        ),
                    ]),
                    copy(
                        "text-sm text-secondary",
                        crate::translations::t(
                            "ui-passkeys-and-linked-providers-can-be-valid-sign-9df79123",
                        ),
                    ),
                    link(
                        crate::translations::t("ui-manage-sign-in-methods"),
                        "/security",
                        "btn btn-secondary",
                    ),
                ],
            ),
        ];
        if !pending_emails.is_empty() {
            children.push(overview_section(
                crate::translations::t("ui-email-verification-pending"),
                vec![
                    copy(
                        "text-secondary",
                        crate::translations::t(
                            "ui-an-email-address-on-this-account-is-waiting-for-verification",
                        ),
                    ),
                    copy("overview-pending-emails", pending_emails.join(" · ")),
                    link(
                        crate::translations::t("ui-review-email-addresses"),
                        "/settings",
                        "btn btn-secondary",
                    ),
                ],
            ));
        }
        children.push(overview_section(
            crate::translations::t("ui-recent-browser-sessions"),
            recent,
        ));
        children.push(link(
            crate::translations::t("ui-view-all-devices-and-sessions"),
            "/sessions",
            "btn btn-secondary",
        ));
        block("overview-shell overview-focused", children)
    })
}

fn overview_section(title: impl Into<String>, mut children: Vec<View>) -> View {
    children.insert(0, heading(2, "heading-sm", title));
    block("overview-section", children)
}

pub fn settings(scope: &Scope) -> View {
    let source = ui::resource(scope, || api::api_get::<ViewerOutcome>("/self/viewer"));
    let reload = source.clone();
    let actions = Action::new(scope);
    ui::resource_body(source, move |scope, response| {
        let Some(user) = response.viewer.as_user() else {
            return alert(crate::translations::t("ui-not-authenticated"), false);
        };
        let Some(session) = response.viewer_session.as_browser_session() else {
            return alert(crate::translations::t("ui-not-authenticated"), false);
        };
        let mut body = vec![];
        let emails = user
            .emails
            .as_ref()
            .map(|v| v.edges.iter().map(|v| v.node.clone()).collect::<Vec<_>>())
            .unwrap_or_default();
        if response.site_config.email_change_allowed || !emails.is_empty() {
            let mut contacts = vec![];
            for email in emails {
                let identity = block(
                    "flex items-center gap-2 flex-1 email-identity",
                    vec![
                        copy("email-address", email.email.clone()),
                        copy(
                            if email.is_primary {
                                "email-badge primary"
                            } else {
                                "email-badge"
                            },
                            if email.is_primary {
                                crate::translations::t("ui-primary")
                            } else {
                                crate::translations::t("ui-secondary")
                            },
                        ),
                        copy(
                            if email.confirmed_at.is_some() {
                                "email-badge primary"
                            } else {
                                "email-badge"
                            },
                            if email.confirmed_at.is_some() {
                                crate::translations::t("ui-verified")
                            } else {
                                crate::translations::t("ui-unverified")
                            },
                        ),
                    ],
                );
                let mut row = vec![identity];
                if email.confirmed_at.is_none() {
                    row.push(link(
                        crate::translations::t("ui-verify"),
                        format!("/emails/{}/verify", encode(&email.id)),
                        "link",
                    ));
                }
                if response.site_config.email_change_allowed {
                    let id = email.id.clone();
                    let reload = reload.clone();
                    row.push(ui::action(
                        scope,
                        &crate::translations::t("ui-remove"),
                        "btn btn-destructive btn-sm",
                        actions,
                        move || {
                            let path = format!("/user-emails/{}", encode(&id));
                            let reload = reload.clone();
                            async move {
                                let result = api::api_delete::<RemoveEmailPayload>(&path).await?;
                                match result.status {
                                    RemoveEmailStatus::Removed => {
                                        reload.reload();
                                        Ok(None)
                                    }
                                    RemoveEmailStatus::NotFound => {
                                        Err(crate::translations::t("ui-email-address-not-found")
                                            .into())
                                    }
                                }
                            }
                        },
                    ));
                }
                contacts.push(block("user-email", row));
            }
            if response.site_config.email_change_allowed {
                contacts.push(ui::form(
                    scope,
                    "add-email",
                    vec![
                        Field::new(scope, crate::translations::t("ui-email-address"), "")
                            .email()
                            .required()
                            .placeholder(crate::translations::t("ui-enter-your-email")),
                    ],
                    crate::translations::t("ui-add"),
                    "btn btn-primary",
                    actions,
                    |values| async move {
                        let result = api::api_post::<AddEmailPayload>(
                            "/account/email-auth/start",
                            serde_json::json!({"email":values[0],"password":null,"language":"en"}),
                        )
                        .await?;
                        match result.status {
                            AddEmailStatus::Added => {
                                let email = result.email.ok_or(crate::translations::t(
                                    "ui-email-response-did-not-provide-a-verification-id",
                                ))?;
                                go(&format!("/emails/{}/verify", encode(&email.id)))?;
                                Ok(None)
                            }
                            AddEmailStatus::Exists => Err(crate::translations::t(
                                "ui-this-email-address-is-already-in-use",
                            )
                            .into()),
                            AddEmailStatus::Invalid => {
                                Err(crate::translations::t("ui-invalid-email-address").into())
                            }
                            AddEmailStatus::Denied => Err(format!(
                                "{} {}",
                                crate::translations::t("ui-email-denied"),
                                result.violations.unwrap_or_default().join(", ")
                            )),
                        }
                    },
                ));
            }
            body.push(ui::disclosure(
                scope,
                "contact-info",
                &crate::translations::t("ui-contact-info"),
                stack(contacts),
                true,
            ));
            body.push(separator());
        }
        if response.site_config.password_login_enabled && user.has_password {
            body.push(ui::disclosure(
                scope,
                "account-password",
                &crate::translations::t("ui-account-password"),
                block(
                    "password-preview",
                    vec![
                        copy("password-dots", "••••••••"),
                        link(
                            crate::translations::t("ui-change-password"),
                            "/password/change",
                            "btn btn-secondary btn-sm",
                        ),
                    ],
                ),
                true,
            ));
            body.push(separator());
        }
        body.push(identity_section(
            scope,
            user.linked_accounts.clone().unwrap_or_default(),
            false,
            actions,
            reload.clone(),
        ));
        body.push(separator());
        body.push(actions.messages());
        let session_id = session.id.clone();
        let signout_open = scope.cage(false);
        let signout = ui::action(
            scope,
            &crate::translations::t("ui-sign-out"),
            "btn btn-destructive-solid",
            actions,
            move || {
                let path = format!("/browser-sessions/{}", encode(&session_id));
                async move {
                    let response = api::api_delete::<EndSessionPayload>(&path).await?;
                    if response.status != EndSessionStatus::Ended {
                        return Err(crate::translations::t("ui-session-could-not-be-ended").into());
                    }
                    go("/login")?;
                    Ok(None)
                }
            },
        );
        body.push(ui::dialog(
            scope,
            "sign-out",
            &crate::translations::t("ui-sign-out"),
            "btn btn-destructive btn-lg",
            stack(vec![
                plain(crate::translations::t(
                    "ui-are-you-sure-you-want-to-sign-out",
                )),
                actions.messages(),
                signout,
            ]),
            signout_open,
        ));
        if response.site_config.account_deactivation_allowed {
            body.push(separator());
            body.push(deactivation(
                scope,
                user,
                response.site_config.password_login_enabled,
            ));
        }
        body.push(separator());
        block("flex flex-col gap-6 account-settings", body)
    })
}
fn deactivation(
    scope: &Scope,
    user: &coauth_account_types::ViewerUser,
    password_login: bool,
) -> View {
    let open = scope.cage(false);
    let erase = scope.cage(false);
    let ready = scope.cage(false);
    let state = Action::new(scope);
    let password_mode = user.has_password && password_login;
    let address = user
        .principal
        .as_ref()
        .map(|value| value.principal_address.clone())
        .unwrap_or_default();
    let field = Field::new(
        scope,
        if password_mode {
            crate::translations::t("ui-enter-your-password-to-confirm")
        } else {
            crate::translations::t("ui-type-your-account-address-to-confirm")
        },
        "",
    )
    .required();
    let field = if password_mode {
        field.password()
    } else {
        field
    };
    let confirmation = field.value;
    let expected = address.clone();
    let gate_address = address.clone();
    scope.effect(move || {
        let valid = if password_mode {
            !confirmation.get().is_empty()
        } else {
            !gate_address.is_empty() && confirmation.get() == gate_address
        };
        state.allowed.revise(|value| *value = ready.get() && valid);
    });
    let weak = scope.downgrade();
    let countdown = std::rc::Rc::new(std::cell::Cell::new(0u64));
    scope.effect(move || {
        let value = open.get();
        let serial = countdown.get().wrapping_add(1);
        countdown.set(serial);
        ready.revise(|v| *v = false);
        if value && let Some(scope) = weak.upgrade() {
            let countdown = countdown.clone();
            let _ = scope.owner().spawn(async move {
                gloo_timers::future::TimeoutFuture::new(3000).await;
                if open.get_untracked() && countdown.get() == serial {
                    ready.revise(|v| *v = true);
                }
            });
        }
    });
    let confirm = ui::form(
        scope,
        "deactivate-account",
        vec![field],
        crate::translations::t("ui-deactivate"),
        "btn btn-destructive-solid",
        state,
        move |values| {
            let expected = expected.clone();
            async move {
                if !ready.get_untracked() {
                    return Err(crate::translations::t(
                        "ui-please-wait-before-confirming-this-action",
                    )
                    .into());
                }
                if !password_mode && (expected.is_empty() || values[0] != expected) {
                    return Err(crate::translations::t(
                        "ui-enter-the-account-address-exactly-to-confirm",
                    )
                    .into());
                }
                let mut body = serde_json::json!({"principal_erase":erase.get_untracked()});
                if password_mode {
                    body["password"] = values[0].clone().into();
                }
                let response =
                    api::api_post::<DeactivateUserPayload>("/viewer/deactivate", body).await?;
                match response.status {
                    DeactivateUserStatus::Deactivated => {
                        go("/login")?;
                        Ok(None)
                    }
                    DeactivateUserStatus::IncorrectPassword => {
                        Err(crate::translations::t("ui-incorrect-password").into())
                    }
                    DeactivateUserStatus::NotFound => {
                        Err(crate::translations::t("ui-account-not-found").into())
                    }
                }
            }
        },
    );
    let content = stack(vec![
        copy(
            "text-md",
            crate::translations::t_with("ui-account-address", &[("address", &address)]),
        ),
        copy(
            "text-md text-secondary",
            crate::translations::t("ui-are-you-sure-you-want-to-deactivate-your-account-30dcc162"),
        ),
        ui::checkbox(
            scope,
            "erase-data",
            &crate::translations::t("ui-erase-all-my-data"),
            erase,
            true,
        ),
        ui::reactive(erase, |_, yes| {
            if yes {
                alert(
                    crate::translations::t(
                        "ui-all-your-messages-and-media-will-be-permanently-ca795700",
                    ),
                    false,
                )
            } else {
                block("", vec![])
            }
        }),
        confirm,
    ]);
    let _ = confirmation;
    ui::dialog(
        scope,
        "deactivate-account",
        &crate::translations::t("ui-deactivate-account"),
        "btn btn-tertiary text-destructive",
        content,
        open,
    )
}
fn identity_section(
    scope: &Scope,
    accounts: Vec<LinkedAccount>,
    protect_last: bool,
    state: Action,
    viewer: Resource<ViewerOutcome>,
) -> View {
    let total = accounts.len();
    let linked_ids = accounts
        .iter()
        .map(|account| account.provider_id.clone())
        .collect::<Vec<_>>();
    let providers = ui::resource(scope, || {
        api::api_get::<ProvidersOutcome>("/account/auth/providers")
    });
    let mut body = vec![copy(
        "text-md text-secondary",
        crate::translations::t("ui-connect-external-accounts-to-enable-additional-sign-in-methods"),
    )];
    if accounts.is_empty() {
        body.push(copy(
            "text-md text-secondary",
            crate::translations::t("ui-no-external-accounts-linked"),
        ));
    }
    for account in accounts {
        let name = account
            .provider_name
            .or(account.provider_brand)
            .unwrap_or_else(|| crate::translations::t("ui-external-provider").into());
        let subject = account.human_account_name.unwrap_or(account.subject);
        let id = account.id;
        let reload = viewer.clone();
        let remove = if protect_last && total <= 1 {
            Box::new(
                sapid::button()
                    .unstyled()
                    .class("btn btn-destructive btn-sm")
                    .label(crate::translations::t("ui-unlink"))
                    .enabled(false),
            ) as View
        } else {
            ui::action(
                scope,
                &crate::translations::t("ui-unlink"),
                "btn btn-destructive btn-sm",
                state,
                move || {
                    let path = format!("/linked-accounts/{}", encode(&id));
                    let reload = reload.clone();
                    async move {
                        api::api_delete::<UnlinkOutcome>(&path).await?;
                        reload.reload();
                        Ok(Some(crate::translations::t("ui-identity-unlinked").into()))
                    }
                },
            )
        };
        body.push(block(
            "flex items-center justify-between p-3 rounded-lg border",
            vec![
                block(
                    "flex flex-col gap-1",
                    vec![
                        copy("text-md font-semibold", name),
                        copy("text-sm text-secondary", subject),
                    ],
                ),
                remove,
            ],
        ));
    }
    body.push(ui::resource_body(providers, move |_, response| {
        block(
            "flex flex-col gap-2",
            response
                .providers
                .into_iter()
                .filter(|provider| !linked_ids.contains(&provider.id))
                .map(|provider| {
                    link(
                        crate::translations::t_with(
                            "ui-link-provider",
                            &[("provider", &provider.human_name.unwrap_or(provider.id))],
                        ),
                        provider.authorize_url,
                        "btn btn-secondary",
                    )
                })
                .collect(),
        )
    }));
    ui::disclosure(
        scope,
        "linked-accounts",
        &crate::translations::t("ui-linked-accounts"),
        stack(body),
        true,
    )
}
pub fn identities(scope: &Scope) -> View {
    let source = ui::resource(scope, || {
        api::api_get::<LinkedAccountsOutcome>("/self/linked-accounts")
    });
    let providers = ui::resource(scope, || {
        api::api_get::<ProvidersOutcome>("/account/auth/providers")
    });
    let reload = source.clone();
    let state = Action::new(scope);
    ui::resource_body(source, move |scope, response| {
        let count = response.accounts.len();
        let linked_ids = response
            .accounts
            .iter()
            .map(|a| a.provider_id.clone())
            .collect::<Vec<_>>();
        let mut rows = vec![
            heading(
                1,
                "heading-xs",
                crate::translations::t("ui-identity-bindings"),
            ),
            state.messages(),
            heading(
                2,
                "text-md font-semibold",
                crate::translations::t("ui-linked-accounts"),
            ),
            copy(
                "text-md text-secondary",
                crate::translations::t(
                    "ui-external-identity-providers-currently-linked-to-bcc52e6c",
                ),
            ),
        ];
        if count == 0 {
            rows.push(copy(
                "text-md text-secondary",
                crate::translations::t("ui-no-external-accounts-linked"),
            ));
        }
        for account in response.accounts {
            let label = account
                .provider_name
                .or(account.provider_brand)
                .unwrap_or_else(|| crate::translations::t("ui-external-provider").into());
            let id = account.id.clone();
            let reload = reload.clone();
            let remove = if count <= 1 {
                Box::new(
                    sapid::button()
                        .unstyled()
                        .class("btn btn-destructive btn-sm")
                        .label(crate::translations::t("ui-unlink"))
                        .enabled(false),
                ) as View
            } else {
                ui::action(
                    scope,
                    &crate::translations::t("ui-unlink"),
                    "btn btn-destructive btn-sm",
                    state,
                    move || {
                        let path = format!("/linked-accounts/{}", encode(&id));
                        let reload = reload.clone();
                        async move {
                            api::api_delete::<UnlinkOutcome>(&path).await?;
                            reload.reload();
                            Ok(Some(crate::translations::t("ui-identity-unlinked").into()))
                        }
                    },
                )
            };
            rows.push(block(
                "flex items-center justify-between p-3 rounded-lg border",
                vec![
                    block(
                        "flex flex-col gap-1",
                        vec![
                            copy("text-md font-semibold", label),
                            copy(
                                "text-sm text-secondary",
                                account.human_account_name.unwrap_or(account.subject),
                            ),
                        ],
                    ),
                    remove,
                ],
            ));
        }
        rows.push(ui::resource_body(providers.clone(), move |_, providers| {
            let links = providers
                .providers
                .iter()
                .filter(|provider| !linked_ids.contains(&provider.id))
                .map(|provider| {
                    link(
                        crate::translations::t_with(
                            "ui-link-provider",
                            &[(
                                "provider",
                                provider.human_name.as_deref().unwrap_or(&provider.id),
                            )],
                        ),
                        &provider.authorize_url,
                        "btn btn-secondary",
                    )
                })
                .collect();
            stack(vec![separator(), block("flex flex-col gap-3", links)])
        }));
        stack(rows)
    })
}
pub fn notifications(scope: &Scope) -> View {
    let source = ui::resource(scope, || {
        api::api_get::<NotificationPreferencesOutcome>("/self/viewer/preferences")
    });
    ui::resource_body(source, |scope, response| {
        let prefs = scope.cage(response.preferences);
        let baseline = scope.cage(
            prefs
                .get_untracked()
                .iter()
                .map(|p| (p.channel.clone(), p.enabled))
                .collect::<Vec<_>>(),
        );
        crate::drafts::track(scope, move || {
            if prefs
                .get_untracked()
                .iter()
                .map(|p| (p.channel.clone(), p.enabled))
                .collect::<Vec<_>>()
                != baseline.get_untracked()
            {
                crate::drafts::State::Unsaved
            } else {
                crate::drafts::State::Clean
            }
        });
        let state = Action::new(scope);
        let mut children = vec![heading(
            1,
            "heading-xs",
            crate::translations::t("ui-notification-preferences"),
        )];
        for (channel, title, label, description) in [
            (
                "email",
                crate::translations::t("ui-email-notifications"),
                crate::translations::t("ui-receive-email-notifications"),
                crate::translations::t(
                    "ui-enable-or-disable-email-notifications-for-accoun-3ebf0191",
                ),
            ),
            (
                "sms",
                crate::translations::t("ui-sms-notifications"),
                crate::translations::t("ui-receive-sms-notifications"),
                crate::translations::t(
                    "ui-enable-or-disable-sms-notifications-for-account-2229c8b7",
                ),
            ),
        ] {
            let available = response
                .available_channels
                .iter()
                .any(|v| v.channel == channel && v.enabled);
            let checked = scope.cage(
                prefs
                    .get_untracked()
                    .iter()
                    .find(|v| v.channel == channel)
                    .is_some_and(|v| v.enabled),
            );
            let key = channel.to_owned();
            scope.effect(move || {
                let enabled = checked.get();
                prefs.revise(|prefs| {
                    if let Some(preference) = prefs.iter_mut().find(|value| value.channel == key) {
                        preference.enabled = enabled;
                    } else {
                        prefs.push(ChannelPreference {
                            channel: key.clone(),
                            enabled,
                        });
                    }
                });
            });
            children.push(stack(vec![
                heading(2, "text-md font-semibold", title),
                badge(
                    crate::translations::t(if available {
                        "ui-delivery-configured"
                    } else {
                        "ui-delivery-unavailable"
                    }),
                    available,
                ),
                copy("text-md text-secondary", description),
                ui::preference_checkbox(
                    scope,
                    channel,
                    label,
                    checked,
                    scope.bond(move || available && !state.busy.get()),
                ),
            ]));
            children.push(separator());
        }
        children.push(stack(vec![
            heading(
                2,
                "text-md font-semibold",
                crate::translations::t("ui-language-preference"),
            ),
            copy(
                "text-md text-secondary",
                crate::translations::t(
                    "ui-choose-the-language-for-notification-messages-se-6cc65fb0",
                ),
            ),
        ]));
        children.push(separator());
        children.push(state.messages());
        children.push(ui::action(
            scope,
            &crate::translations::t("ui-save-preferences"),
            "btn btn-primary",
            state,
            move || async move {
                let response = api::api_patch::<UpdateNotificationPreferencesOutcome>(
                    "/self/viewer/preferences",
                    serde_json::json!({"preferences":prefs.get_untracked()}),
                )
                .await?;
                baseline.revise(|value| {
                    *value = response
                        .preferences
                        .iter()
                        .map(|p| (p.channel.clone(), p.enabled))
                        .collect()
                });
                prefs.revise(|value| *value = response.preferences);
                Ok(Some(crate::translations::t("ui-preferences-saved").into()))
            },
        ));
        stack(children)
    })
}
pub fn plan(scope: &Scope) -> View {
    let source = ui::resource(scope, || api::api_get::<SiteConfig>("/self/site-config"));
    ui::resource_body(source, |scope, site| {
        match site
            .plan_management_iframe_uri
            .filter(|uri| safe_iframe(uri))
        {
            Some(uri) => plan_frame(scope, uri),
            None => {
                let _ = go("/");
                plain(crate::translations::t("ui-redirecting"))
            }
        }
    })
}
fn safe_iframe(uri: &str) -> bool {
    uri.len() > 8
        && uri
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}
fn plan_frame(scope: &Scope, url: String) -> View {
    let id = format!("coauth-plan-{}", scope.id().slot());
    let dom_id = id.clone();
    Box::new(
        view()
            .class("plan-frame-host")
            .semantics(Some(Box::new(glory::render::Semantics {
                id: Some(glory::render::SemanticId::new(id).expect("valid frame ID")),
                ..Default::default()
            })))
            .fill(widget(move |scope| {
                #[cfg(target_arch = "wasm32")]
                {
                    let id = dom_id.clone();
                    let url = url.clone();
                    let _ = scope.owner().spawn(async move {
                        gloo_timers::future::TimeoutFuture::new(0).await;
                        if let Some(document) =
                            web_sys::window().and_then(|window| window.document())
                            && let Some(parent) = document.get_element_by_id(&id)
                            && let Ok(frame) = document.create_element("iframe")
                        {
                            let _ = frame.set_attribute("src", &url);
                            let _ = frame.set_attribute(
                                "title",
                                &crate::translations::t("ui-plan-management"),
                            );
                            let _ = frame.set_attribute("class", "plan-iframe");
                            let _ = parent.append_child(&frame);
                        }
                    });
                }
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let _ = (&dom_id, &url, scope);
                }
                Ok(())
            })),
    )
}
