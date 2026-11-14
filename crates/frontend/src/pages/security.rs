use crate::api::types::*;
use crate::api::{self};
use crate::ui::{self, *};

pub fn page(scope: &Scope) -> View {
    let summary = ui::resource(scope, || {
        api::api_get::<SecuritySummaryOutcome>("/self/viewer/security")
    });
    let passkeys = ui::resource(scope, || {
        api::api_get::<PasskeyListOutcome>("/self/passkeys")
    });
    let refresh = passkeys.clone();
    let state = Action::new(scope);
    ui::resource_body(summary, move |scope, summary| {
        let password_label = if summary.has_password {
            crate::translations::t("ui-password-is-set")
        } else {
            crate::translations::t("ui-no-password-set")
        };
        let mut children = vec![
            heading(
                1,
                "heading-xs",
                crate::translations::t("ui-security-center"),
            ),
            block(
                "flex flex-col gap-2",
                vec![
                    heading(
                        2,
                        "text-md font-semibold",
                        crate::translations::t("ui-password-status"),
                    ),
                    copy("badge", password_label),
                    copy(
                        "text-md text-secondary",
                        crate::translations::t(
                            "ui-view-and-manage-your-account-password-check-when-ca728765",
                        ),
                    ),
                ],
            ),
            separator(),
        ];
        let mut key_children = vec![
            heading(
                2,
                "text-md font-semibold",
                crate::translations::t("ui-passkeys"),
            ),
            copy(
                "text-md text-secondary",
                crate::translations::t(
                    "ui-passkeys-protect-this-coauth-account-from-phishi-8a8d7486",
                ),
            ),
            state.messages(),
        ];
        let reload = refresh.clone();
        key_children.push(ui::resource_body(
            passkeys.clone(),
            move |scope, response| {
                if response.passkeys.is_empty() {
                    return copy(
                        "text-md text-secondary",
                        crate::translations::t("ui-no-passkeys-are-registered-yet"),
                    );
                }
                stack(
                    response
                        .passkeys
                        .into_iter()
                        .map(|key| passkey(scope, key, state, reload.clone()))
                        .collect(),
                )
            },
        ));
        let reload = refresh.clone();
        key_children.push(ui::form(
            scope,
            "new-passkey",
            vec![
                Field::new(scope, crate::translations::t("ui-new-passkey-name"), "")
                    .placeholder(crate::translations::t("ui-for-example-windows-hello")),
            ],
            crate::translations::t("ui-add-passkey"),
            "btn btn-primary btn-sm",
            state,
            move |values| {
                let reload = reload.clone();
                async move {
                    let label = (!values[0].trim().is_empty()).then(|| values[0].trim().into());
                    crate::passkey::register(None, label).await?;
                    reload.reload();
                    Ok(Some(crate::translations::t("ui-passkey-added").into()))
                }
            },
        ));
        key_children.push(copy(
            "text-sm text-secondary",
            crate::translations::t("ui-adding-renaming-or-removing-a-passkey-requires-a-f3dc3b5a"),
        ));
        children.push(block("flex flex-col gap-3", key_children));
        children.push(separator());
        children.push(block(
            "flex flex-col gap-2",
            vec![
                heading(
                    2,
                    "text-md font-semibold",
                    crate::translations::t("ui-active-sessions"),
                ),
                plain(crate::translations::t_count(
                    "ui-session-count",
                    summary.active_sessions_count as u64,
                )),
                copy(
                    "text-md text-secondary",
                    crate::translations::t(
                        "ui-a-summary-of-your-currently-active-browser-and-app-sessions",
                    ),
                ),
                link(
                    crate::translations::t("ui-manage-sessions"),
                    "/sessions",
                    "btn btn-secondary btn-sm",
                ),
            ],
        ));
        children.push(separator());
        children.push(block(
            "flex flex-col gap-2",
            vec![
                heading(
                    2,
                    "text-md font-semibold",
                    crate::translations::t("ui-verified-emails"),
                ),
                plain(crate::translations::t_count(
                    "ui-verified-email-count",
                    summary.verified_emails_count as u64,
                )),
            ],
        ));
        children.push(separator());
        children.push(block(
            "flex flex-col gap-2",
            vec![
                heading(
                    2,
                    "text-md font-semibold",
                    crate::translations::t("ui-linked-providers"),
                ),
                plain(crate::translations::t_count(
                    "ui-linked-provider-count",
                    summary.linked_providers_count as u64,
                )),
            ],
        ));
        children.push(separator());
        stack(children)
    })
}
fn passkey(
    scope: &Scope,
    key: PasskeySummary,
    state: Action,
    source: Resource<PasskeyListOutcome>,
) -> View {
    let remove = revoke_passkey_confirmation(scope, &key, state, source.clone());
    let id = key.id.clone();
    let reload = source.clone();
    let backup = if key.backup_eligible {
        if key.backup_state {
            crate::translations::t("ui-synced-passkey")
        } else {
            crate::translations::t("ui-sync-capable-passkey")
        }
    } else {
        crate::translations::t("ui-device-bound-credential")
    };
    let mut badges = vec![
        copy(
            "font-semibold",
            key.label
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or(&crate::translations::t("ui-unnamed-passkey")),
        ),
        copy("badge", backup),
    ];
    if key.user_verified {
        badges.push(badge(crate::translations::t("ui-user-verified"), true));
    }
    let description = if let Some(last_used) = key.last_used_at.as_deref() {
        crate::translations::t_with(
            "ui-passkey-dates",
            &[
                ("created", &crate::utils::format_date(&key.created_at)),
                ("used", &crate::utils::format_date(last_used)),
            ],
        )
    } else {
        crate::translations::t_with(
            "ui-passkey-created",
            &[("created", &crate::utils::format_date(&key.created_at))],
        )
    };
    let name = Field::new(
        scope,
        crate::translations::t("ui-passkey-name"),
        key.label.unwrap_or_default(),
    );
    let name_value = name.value;
    let field = ui::field(
        scope,
        &format!("passkey-{}", key.id),
        name,
        scope.bond(move || !state.busy.get()),
        state,
    );
    let rename = ui::action(
        scope,
        &crate::translations::t("ui-save-name"),
        "btn btn-secondary btn-sm",
        state,
        move || {
            let value = name_value.get_untracked();
            let path = format!("/self/passkeys/{}", encode(&id));
            let source = reload.clone();
            async move {
                api::api_patch::<PasskeyMutationOutcome>(&path,serde_json::json!({"label":(!value.trim().is_empty()).then(||value.trim().to_owned())})).await?;
                source.reload();
                Ok(Some(crate::translations::t("ui-passkey-name-saved").into()))
            }
        },
    );
    block(
        "flex flex-col gap-2",
        vec![
            block("flex items-center gap-2", badges),
            copy("text-sm text-secondary", description),
            field,
            block("flex gap-2", vec![rename, remove]),
        ],
    )
}

fn revoke_passkey_confirmation(
    scope: &Scope,
    key: &PasskeySummary,
    state: Action,
    source: Resource<PasskeyListOutcome>,
) -> View {
    use crate::translations::t;
    let open = scope.cage(false);
    let owner = scope.downgrade();
    let id = key.id.clone();
    let rows = vec![
        (
            t("security-passkey-name"),
            key.label
                .clone()
                .filter(|label| !label.trim().is_empty())
                .unwrap_or_else(|| t("security-passkey-unnamed")),
        ),
        (t("security-passkey-id"), key.id.clone()),
        (t("security-passkey-created"), key.created_at.clone()),
        (
            t("security-passkey-last-used"),
            key.last_used_at
                .clone()
                .unwrap_or_else(|| t("security-passkey-never-used")),
        ),
    ];
    let mut content = Some(block(
        "passkey-revoke-details",
        vec![
            ui::details(rows),
            copy(
                "text-sm text-secondary",
                t("security-passkey-alternative-help"),
            ),
        ],
    ));
    Box::new(
        sapid::alert_dialog(format!("passkey-revoke-{}-{}", scope.id().slot(), key.id))
            .unstyled()
            .class("account-confirm-dialog passkey-revoke-dialog")
            .label(t("security-passkey-remove"))
            .title(t("security-passkey-remove-title"))
            .description(t("security-passkey-remove-impact"))
            .cancel_label(t("action-cancel"))
            .confirm_label(t("security-passkey-remove-confirm"))
            .confirm_variant(sapid::ButtonVariant::Danger)
            .confirm_enabled(scope.bond(move || !state.busy.get() && state.allowed.get()))
            .open(open)
            .on_open_change(move |next| {
                if next {
                    state.feedback.revise(|value| *value = None);
                }
                open.revise(|value| *value = next);
            })
            .on_confirm(move || {
                let path = format!("/self/passkeys/{}/revoke", encode(&id));
                let source = source.clone();
                state.run(&owner, async move {
                    api::api_post::<PasskeyMutationOutcome>(&path, serde_json::json!({})).await?;
                    source.reload();
                    Ok(Some(t("security-passkey-removed")))
                });
            })
            .trigger_content(move || {
                Box::new(
                    text()
                        .kind(TextKind::Inline)
                        .class("btn btn-destructive btn-sm")
                        .content(t("security-passkey-remove")),
                ) as View
            })
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || content.take().unwrap_or_else(|| block("", vec![]))),
    )
}
