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
            "Password is set"
        } else {
            "No password set"
        };
        let mut children = vec![
            heading(1, "heading-xs", "Security Center"),
            block(
                "flex flex-col gap-2",
                vec![
                    heading(2, "text-md font-semibold", "Password status"),
                    badge(password_label, summary.has_password),
                    copy(
                        "text-md text-secondary",
                        "View and manage your account password. Check when it was last changed and update it if needed.",
                    ),
                ],
            ),
            separator(),
        ];
        let mut key_children = vec![
            heading(2, "text-md font-semibold", "Passkeys"),
            copy(
                "text-md text-secondary",
                "Passkeys protect this Coauth account from phishing. They do not replace your Arkret DID principal recovery secret or authorize a new long-lived device.",
            ),
            state.messages(),
        ];
        let reload = refresh.clone();
        key_children.push(ui::resource_body(
            passkeys.clone(),
            move |scope, response| {
                if response.passkeys.is_empty() {
                    return copy("text-md text-secondary", "No passkeys are registered yet.");
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
                Field::new(scope, "New passkey name", "").placeholder("For example, Windows Hello"),
            ],
            "Add passkey",
            "btn btn-primary btn-sm",
            state,
            move |values| {
                let reload = reload.clone();
                async move {
                    let label = (!values[0].trim().is_empty()).then(|| values[0].trim().into());
                    crate::passkey::register(None, label).await?;
                    reload.reload();
                    Ok(Some("Passkey added.".into()))
                }
            },
        ));
        key_children.push(copy("text-sm text-secondary","Adding, renaming, or removing a passkey requires a recent sign-in. If this session is too old, sign out and authenticate again first."));
        children.push(block("flex flex-col gap-3", key_children));
        children.push(separator());
        children.push(block(
            "flex flex-col gap-2",
            vec![
                heading(2, "text-md font-semibold", "Active sessions"),
                plain(format!(
                    "{} active session(s)",
                    summary.active_sessions_count
                )),
                copy(
                    "text-md text-secondary",
                    "A summary of your currently active browser and app sessions.",
                ),
                link("Manage sessions", "/sessions", "btn btn-secondary btn-sm"),
            ],
        ));
        children.push(separator());
        children.push(block(
            "flex flex-col gap-2",
            vec![
                heading(2, "text-md font-semibold", "Verified emails"),
                plain(format!(
                    "{} verified email(s)",
                    summary.verified_emails_count
                )),
            ],
        ));
        children.push(separator());
        children.push(block(
            "flex flex-col gap-2",
            vec![
                heading(2, "text-md font-semibold", "Linked providers"),
                plain(format!(
                    "{} linked provider(s)",
                    summary.linked_providers_count
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
            "Synced passkey"
        } else {
            "Sync-capable passkey"
        }
    } else {
        "Device-bound credential"
    };
    let mut badges = vec![
        copy(
            "font-semibold",
            key.label
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("Unnamed passkey"),
        ),
        copy("badge", backup),
    ];
    if key.user_verified {
        badges.push(badge("User verified", true));
    }
    let description = format!(
        "Created {}{}",
        key.created_at,
        key.last_used_at
            .map(|value| format!(" · Last used {value}"))
            .unwrap_or_default()
    );
    let name = Field::new(scope, "Passkey name", key.label.unwrap_or_default());
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
        "Save name",
        "btn btn-secondary btn-sm",
        state,
        move || {
            let value = name_value.get_untracked();
            let path = format!("/self/passkeys/{}", encode(&id));
            let source = reload.clone();
            async move {
                api::api_patch::<PasskeyMutationOutcome>(&path,serde_json::json!({"label":(!value.trim().is_empty()).then(||value.trim().to_owned())})).await?;
                source.reload();
                Ok(Some("Passkey name saved.".into()))
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
