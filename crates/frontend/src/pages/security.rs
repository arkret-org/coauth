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
    let id = key.id;
    let remove = ui::action(scope, "Remove", "btn btn-danger btn-sm", state, move || {
        let path = format!("/self/passkeys/{}/revoke", encode(&id));
        let source = source.clone();
        async move {
            api::api_post::<PasskeyMutationOutcome>(&path, serde_json::json!({})).await?;
            source.reload();
            Ok(Some("Passkey removed.".into()))
        }
    });
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
