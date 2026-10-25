use crate::api::types::*;
use crate::api::{self};
use crate::ui::{self, *};

pub fn shell(scope: &Scope, path: String) -> View {
    let viewer = ui::resource(scope, || api::api_get::<ViewerOutcome>("/self/viewer"));
    let refresh = viewer.clone();
    ui::resource_body(viewer, move |scope, response| {
        let Some(user) = response.viewer.as_user().cloned() else {
            let _ = go("/login");
            return plain("Redirecting to login…");
        };
        let Some(principal) = user.principal.clone() else {
            return alert("User data unavailable.", false);
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
            Box::new(image().class("user-avatar").source(url).alt("Avatar")) as View
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
                "Account",
                vec![
                    ("Overview", "/"),
                    ("Settings", "/settings"),
                    ("Identities", "/identities"),
                ],
            ),
            (
                "Security",
                vec![("Security", "/security"), ("Devices", "/sessions")],
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
                    copy("sidebar-group-label", "Administration"),
                    link("Admin Portal (external)", url, "sidebar-item"),
                ],
            ));
        }
        let mut preferences = vec![
            copy("sidebar-group-label", "Preferences"),
            link(
                "Notifications",
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
                "Plan",
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
                block("account-content", vec![super::route(scope, &path)]),
            ],
        );
        super::layout(scope, body, true)
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
            Field::new(scope, "Display name", initial),
            Field::new(scope, "Preferred language", locale).choices([
                ("", "Use device language"),
                ("en", "English"),
                ("zh", "中文"),
            ]),
        ],
        "Save",
        "btn btn-primary",
        state,
        move |values| {
            let refresh = refresh.clone();
            async move {
                let locale = values[1].trim();
                if !locale.is_empty() && crate::translations::UiLocale::from_tag(locale).is_none() {
                    return Err("Choose a supported account language (en or zh-CN).".into());
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
                            .alt("Avatar"),
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
        copy(
            "text-sm text-secondary",
            user.principal
                .as_ref()
                .map(|p| p.principal_address.clone())
                .unwrap_or_default(),
        ),
    ]);
    ui::dialog(
        scope,
        "edit-profile",
        "Edit profile",
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
            .class(scope.bond(move || if state.busy.get() { "btn btn-secondary btn-sm avatar-uploading" } else { "btn btn-secondary btn-sm" }.to_owned()))
            .label(scope.bond(move || if state.busy.get() { "Uploading avatar…" } else { "Upload avatar" }.to_owned()))
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
                    state.feedback.revise(|value| *value = Some(Err(format!("Avatar selection was rejected: {reason:?}. Choose a PNG, JPEG, GIF or WebP image up to 5 MB."))));
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
                        "Avatar uploaded. Save your profile to apply it.".into(),
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
        let scope = owner.upgrade().ok_or("Avatar selection was closed")?;
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
            return Err("Unable to read the complete avatar.".into());
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
        .map_err(|_| "Unable to prepare avatar")?;
    let form = web_sys::FormData::new().map_err(|_| "Unable to prepare avatar upload")?;
    form.append_with_blob_and_filename("avatar", &blob, &file.name)
        .map_err(|_| "Unable to attach avatar")?;
    let options = web_sys::RequestInit::new();
    options.set_method("POST");
    options.set_credentials(web_sys::RequestCredentials::SameOrigin);
    options.set_body(&form);
    let request = web_sys::Request::new_with_str_and_init(
        &format!("{}/self/viewer/avatar", crate::config::api_base_url()),
        &options,
    )
    .map_err(|_| "Unable to create avatar request")?;
    let window = web_sys::window().ok_or("Browser window unavailable")?;
    let response: web_sys::Response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|error| format!("Avatar upload failed: {error:?}"))?
        .dyn_into()
        .map_err(|_| "Invalid upload response")?;
    if !response.ok() {
        return Err(format!("Avatar upload failed (HTTP {})", response.status()));
    }
    let json = JsFuture::from(response.json().map_err(|_| "Invalid avatar response")?)
        .await
        .map_err(|_| "Invalid avatar response")?;
    js_sys::Reflect::get(&json, &JsValue::from_str("avatar_url"))
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| "Avatar response did not provide a URL".into())
}
#[cfg(not(target_arch = "wasm32"))]
async fn upload_avatar(
    _: glory::ui::WeakScope,
    _: sapid::FileController,
    _: glory::render::FileInfo,
) -> std::result::Result<String, String> {
    Err("Avatar upload requires a browser.".into())
}

pub fn overview(scope: &Scope) -> View {
    let security = ui::resource(scope, || {
        api::api_get::<SecuritySummaryOutcome>("/self/viewer/security")
    });
    ui::resource_body(security, |_, summary| {
        let password = if summary.has_password {
            "Password is set"
        } else {
            "No password set"
        };
        let hero = block(
            "overview-hero",
            vec![
                block(
                    "overview-hero-copy",
                    vec![
                        copy("overview-eyebrow", "Control center"),
                        heading(1, "heading-xs", "Account overview"),
                        copy(
                            "text-md text-secondary",
                            "Scan account posture, pending work, and the fastest routes to your common account tasks.",
                        ),
                        badge(password, summary.has_password),
                    ],
                ),
                block(
                    "overview-hero-actions",
                    vec![
                        link("Review security", "/security", "btn btn-primary btn-sm"),
                        link("Open devices", "/sessions", "btn btn-secondary btn-sm"),
                    ],
                ),
            ],
        );
        let cards = vec![
            stat(
                "Password",
                password,
                if summary.has_password {
                    "Password login is available for this account."
                } else {
                    "Add a password to reduce recovery friction and speed up sign-in."
                },
                "Open security",
                "/security",
                if summary.has_password {
                    "tone-success"
                } else {
                    "tone-warning"
                },
            ),
            stat(
                "Active sessions",
                &summary.active_sessions_count.to_string(),
                "Browser and app sessions currently recognized as active.",
                "Manage sessions",
                "/sessions",
                "tone-neutral",
            ),
            stat(
                "Linked identities",
                &summary.linked_providers_count.to_string(),
                "Connected upstream identity providers available for sign-in.",
                "Review identities",
                "/identities",
                "tone-neutral",
            ),
        ];
        let actions = [
            (
                "Security",
                "Password health, session posture, and verified signals.",
                "/security",
            ),
            (
                "Identities",
                "Inspect or detach linked upstream sign-in providers.",
                "/identities",
            ),
            (
                "Notifications",
                "Review delivery channels and update messaging preferences.",
                "/notifications",
            ),
            (
                "Devices",
                "Rename or revoke browser and OAuth sessions.",
                "/sessions",
            ),
        ]
        .into_iter()
        .map(|(title, description, url)| {
            block(
                "overview-action-card",
                vec![
                    block(
                        "flex flex-col gap-2",
                        vec![
                            heading(2, "overview-action-title", title),
                            copy("text-sm text-secondary", description),
                        ],
                    ),
                    link("Open", url, "overview-action-arrow"),
                ],
            )
        })
        .collect();
        block(
            "overview-shell",
            vec![
                hero,
                block("overview-stat-grid", cards),
                block(
                    "flex flex-col gap-2",
                    vec![
                        copy("overview-section-title", "Quick actions"),
                        copy(
                            "text-sm text-secondary",
                            "Jump directly into the areas users typically revisit after sign-in.",
                        ),
                    ],
                ),
                block("overview-action-grid", actions),
            ],
        )
    })
}
fn stat(title: &str, value: &str, note: &str, label: &str, target: &str, tone: &str) -> View {
    block(
        &format!("overview-stat-card {tone}"),
        vec![
            block(
                "flex flex-col gap-2",
                vec![
                    copy("overview-stat-label", title),
                    copy("overview-stat-value", value),
                    copy("overview-stat-note", note),
                ],
            ),
            link(label, target, "btn btn-secondary btn-sm"),
        ],
    )
}

pub fn settings(scope: &Scope) -> View {
    let source = ui::resource(scope, || api::api_get::<ViewerOutcome>("/self/viewer"));
    let reload = source.clone();
    let actions = Action::new(scope);
    ui::resource_body(source, move |scope, response| {
        let Some(user) = response.viewer.as_user() else {
            return alert("Not authenticated.", false);
        };
        let Some(session) = response.viewer_session.as_browser_session() else {
            return alert("Not authenticated.", false);
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
                                "Primary"
                            } else {
                                "Secondary"
                            },
                        ),
                        copy(
                            if email.confirmed_at.is_some() {
                                "email-badge primary"
                            } else {
                                "email-badge"
                            },
                            if email.confirmed_at.is_some() {
                                "Verified"
                            } else {
                                "Unverified"
                            },
                        ),
                    ],
                );
                let mut row = vec![identity];
                if email.confirmed_at.is_none() {
                    row.push(link(
                        "Verify",
                        format!("/emails/{}/verify", encode(&email.id)),
                        "link",
                    ));
                }
                if response.site_config.email_change_allowed {
                    let id = email.id.clone();
                    let reload = reload.clone();
                    row.push(ui::action(
                        scope,
                        "Remove",
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
                                        Err("Email address not found.".into())
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
                        Field::new(scope, "Email address", "")
                            .email()
                            .required()
                            .placeholder("Enter your email"),
                    ],
                    "Add",
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
                                let email = result
                                    .email
                                    .ok_or("Email response did not provide a verification ID")?;
                                go(&format!("/emails/{}/verify", encode(&email.id)))?;
                                Ok(None)
                            }
                            AddEmailStatus::Exists => {
                                Err("This email address is already in use.".into())
                            }
                            AddEmailStatus::Invalid => Err("Invalid email address.".into()),
                            AddEmailStatus::Denied => Err(format!(
                                "Email denied: {}",
                                result.violations.unwrap_or_default().join(", ")
                            )),
                        }
                    },
                ));
            }
            body.push(ui::disclosure(
                scope,
                "contact-info",
                "Contact info",
                stack(contacts),
                true,
            ));
            body.push(separator());
        }
        if response.site_config.password_login_enabled && user.has_password {
            body.push(ui::disclosure(
                scope,
                "account-password",
                "Account password",
                block(
                    "password-preview",
                    vec![
                        copy("password-dots", "••••••••"),
                        link(
                            "Change password",
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
            "Sign out",
            "btn btn-destructive-solid",
            actions,
            move || {
                let path = format!("/browser-sessions/{}", encode(&session_id));
                async move {
                    let response = api::api_delete::<EndSessionPayload>(&path).await?;
                    if response.status != EndSessionStatus::Ended {
                        return Err("Session could not be ended.".into());
                    }
                    go("/login")?;
                    Ok(None)
                }
            },
        );
        body.push(ui::dialog(
            scope,
            "sign-out",
            "Sign out",
            "btn btn-destructive btn-lg",
            stack(vec![
                plain("Are you sure you want to sign out?"),
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
            "Enter your password to confirm"
        } else {
            "Type your account address to confirm"
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
        "Deactivate",
        "btn btn-destructive-solid",
        state,
        move |values| {
            let expected = expected.clone();
            async move {
                if !ready.get_untracked() {
                    return Err("Please wait before confirming this action.".into());
                }
                if !password_mode && (expected.is_empty() || values[0] != expected) {
                    return Err("Enter the account address exactly to confirm.".into());
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
                    DeactivateUserStatus::IncorrectPassword => Err("Incorrect password.".into()),
                    DeactivateUserStatus::NotFound => Err("Account not found.".into()),
                }
            }
        },
    );
    let content = stack(vec![
        copy("text-md", format!("Account: {address}")),
        copy(
            "text-md text-secondary",
            "Are you sure you want to deactivate your account? This action cannot be undone.",
        ),
        ui::checkbox(scope, "erase-data", "Erase all my data", erase, true),
        ui::reactive(erase, |_, yes| {
            if yes {
                alert(
                    "All your messages and media will be permanently deleted from the server. This cannot be reversed.",
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
        "Deactivate account",
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
        "Connect external accounts to enable additional sign-in methods.",
    )];
    if accounts.is_empty() {
        body.push(copy(
            "text-md text-secondary",
            "No external accounts linked.",
        ));
    }
    for account in accounts {
        let name = account
            .provider_name
            .or(account.provider_brand)
            .unwrap_or_else(|| "External provider".into());
        let subject = account.human_account_name.unwrap_or(account.subject);
        let id = account.id;
        let reload = viewer.clone();
        let remove = if protect_last && total <= 1 {
            Box::new(
                sapid::button()
                    .unstyled()
                    .class("btn btn-destructive btn-sm")
                    .label("Unlink")
                    .enabled(false),
            ) as View
        } else {
            ui::action(
                scope,
                "Unlink",
                "btn btn-destructive btn-sm",
                state,
                move || {
                    let path = format!("/linked-accounts/{}", encode(&id));
                    let reload = reload.clone();
                    async move {
                        api::api_delete::<UnlinkOutcome>(&path).await?;
                        reload.reload();
                        Ok(Some("Identity unlinked.".into()))
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
                        format!("Link {}", provider.human_name.unwrap_or(provider.id)),
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
        "Linked accounts",
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
            heading(1, "heading-xs", "Identity Bindings"),
            state.messages(),
            heading(2, "text-md font-semibold", "Linked accounts"),
            copy(
                "text-md text-secondary",
                "External identity providers currently linked to your account. You can sign in with any of these.",
            ),
        ];
        if count == 0 {
            rows.push(copy(
                "text-md text-secondary",
                "No external accounts linked.",
            ));
        }
        for account in response.accounts {
            let label = account
                .provider_name
                .or(account.provider_brand)
                .unwrap_or_else(|| "External provider".into());
            let id = account.id.clone();
            let reload = reload.clone();
            let remove = if count <= 1 {
                Box::new(
                    sapid::button()
                        .unstyled()
                        .class("btn btn-destructive btn-sm")
                        .label("Unlink")
                        .enabled(false),
                ) as View
            } else {
                ui::action(
                    scope,
                    "Unlink",
                    "btn btn-destructive btn-sm",
                    state,
                    move || {
                        let path = format!("/linked-accounts/{}", encode(&id));
                        let reload = reload.clone();
                        async move {
                            api::api_delete::<UnlinkOutcome>(&path).await?;
                            reload.reload();
                            Ok(Some("Identity unlinked.".into()))
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
                        format!(
                            "Link {}",
                            provider.human_name.as_deref().unwrap_or(&provider.id)
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
        let state = Action::new(scope);
        let mut children = vec![heading(1, "heading-xs", "Notification Preferences")];
        for (channel, title, label, description) in [
            (
                "email",
                "Email notifications",
                "Receive email notifications",
                "Enable or disable email notifications for account activity and security alerts.",
            ),
            (
                "sms",
                "SMS notifications",
                "Receive SMS notifications",
                "Enable or disable SMS notifications for account verification and alerts.",
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
                    format!(
                        "{} delivery {}",
                        if channel == "email" { "Email" } else { "SMS" },
                        if available {
                            "configured"
                        } else {
                            "not configured"
                        }
                    ),
                    available,
                ),
                copy("text-md text-secondary", description),
                ui::checkbox(scope, channel, label, checked, available),
            ]));
            children.push(separator());
        }
        children.push(stack(vec![heading(2,"text-md font-semibold","Language preference"),copy("text-md text-secondary","Choose the language for notification messages sent to you. This setting is not yet available.")]));
        children.push(separator());
        children.push(state.messages());
        children.push(ui::action(
            scope,
            "Save preferences",
            "btn btn-primary",
            state,
            move || async move {
                let response = api::api_patch::<UpdateNotificationPreferencesOutcome>(
                    "/self/viewer/preferences",
                    serde_json::json!({"preferences":prefs.get_untracked()}),
                )
                .await?;
                prefs.revise(|value| *value = response.preferences);
                Ok(Some("Preferences saved.".into()))
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
                plain("Redirecting…")
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
                            let _ = frame.set_attribute("title", "Plan management");
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
