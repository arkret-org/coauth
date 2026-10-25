use coauth_account_types::DeviceType;

use crate::api::types::*;
use crate::api::{self};
use crate::ui::{self, *};
use crate::utils::{format_date, format_last_active};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pagination {
    pub direction: Option<(bool, String)>,
    pub include_ended: bool,
    pub limit: i32,
}
impl Default for Pagination {
    fn default() -> Self {
        Self {
            direction: None,
            include_ended: false,
            limit: 6,
        }
    }
}
pub fn query(prefix: &str, page: &Pagination) -> String {
    let mut value = format!("?session_limit={}", page.limit);
    if let Some((after, cursor)) = &page.direction {
        value.push_str(&format!(
            "&{prefix}_{}={}",
            if *after { "after" } else { "before" },
            encode(cursor)
        ));
    }
    if page.include_ended {
        value.push_str("&include_ended=true");
    }
    value
}
pub fn list(scope: &Scope, browser: bool) -> View {
    let pagination = scope.cage(Pagination::default());
    let source = ui::resource(scope, move || {
        let page = pagination.get();
        let path = format!(
            "/self/viewer{}",
            query(if browser { "browser" } else { "app" }, &page)
        );
        async move { api::api_get::<ViewerOutcome>(&path).await }
    });
    let filter = button("Show inactive (90+ days)", "filter-toggle", move || {
        pagination.revise(|page| {
            page.include_ended = !page.include_ended;
            page.direction = None;
        });
    });
    let body = ui::resource_body(source, move |scope, response| {
        let Some(user) = response.viewer.as_user() else {
            return alert("Not authenticated.", false);
        };
        let current = response
            .viewer_session
            .as_browser_session()
            .map(|s| s.id.as_str());
        let mut body = vec![];
        let info = if browser {
            if let Some(connection) = &user.browser_sessions {
                for edge in connection.edges.iter().rev() {
                    body.push(browser_card(
                        edge.node.clone(),
                        current == Some(&edge.node.id),
                    ));
                }
                Some(connection.page_info.clone())
            } else {
                None
            }
        } else {
            body.push(block(
                "session-card compact browser-sessions-overview",
                vec![
                    link("Browser sessions", "/sessions/browsers", "session-name"),
                    copy(
                        "text-sm text-secondary",
                        format!(
                            "{} active",
                            user.browser_sessions.as_ref().map_or(0, |s| s.total_count)
                        ),
                    ),
                ],
            ));
            body.push(separator());
            if let Some(connection) = &user.app_sessions {
                for edge in connection.edges.iter().rev() {
                    match &edge.node {
                        AppSession::OAuthSession(session) => body.push(oauth_card(session.clone())),
                    }
                }
                Some(connection.page_info.clone())
            } else {
                None
            }
        };
        if body.is_empty() {
            body.push(empty(
                "No sessions",
                "There are no matching sessions to display.",
            ));
        }
        if let Some(info) = info
            && (info.has_previous_page || info.has_next_page)
        {
            let previous = info.start_cursor.clone();
            let next = info.end_cursor.clone();
            body.push(block(
                "pagination-controls",
                vec![
                    Box::new(
                        sapid::button()
                            .unstyled()
                            .class("btn btn-secondary btn-sm")
                            .label("Previous")
                            .enabled(info.has_previous_page)
                            .on_press(move || {
                                if let Some(cursor) = &previous {
                                    pagination.revise(|page| {
                                        page.direction = Some((false, cursor.clone()));
                                    });
                                }
                            }),
                    ),
                    Box::new(
                        sapid::button()
                            .unstyled()
                            .class("btn btn-secondary btn-sm")
                            .label("Next")
                            .enabled(info.has_next_page)
                            .on_press(move || {
                                if let Some(cursor) = &next {
                                    pagination.revise(|page| {
                                        page.direction = Some((true, cursor.clone()));
                                    });
                                }
                            }),
                    ),
                ],
            ));
        }
        let _ = scope;
        stack(body)
    });
    stack(vec![
        heading(
            1,
            "heading-xs",
            if browser {
                "Browser sessions"
            } else {
                "Sessions"
            },
        ),
        filter,
        body,
    ])
}
fn browser_name(session: &BrowserSession) -> String {
    session.display_name.clone().unwrap_or_else(|| {
        session
            .user_agent
            .as_ref()
            .map(|ua| {
                [ua.name.clone(), ua.model.clone()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" - ")
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Unknown session".into())
    })
}
fn browser_card(session: BrowserSession, current: bool) -> View {
    let name = browser_name(&session);
    let icon = session
        .user_agent
        .as_ref()
        .map_or("❓", |agent| match agent.device_type {
            DeviceType::Pc => "🖥",
            DeviceType::Mobile => "📱",
            DeviceType::Unknown => "❓",
        });
    let mut fields = vec![];
    if current {
        fields.push(("Status".into(), "Current session".into()));
    }
    if let Some(active) = session.last_active_at {
        fields.push(("Last active".into(), format_last_active(&active)));
    }
    if let Some(ip) = session.last_active_ip {
        fields.push(("IP address".into(), ip));
    }
    block(
        "session-card",
        vec![
            block(
                "card-header",
                vec![
                    copy("device-icon", icon),
                    block(
                        "content",
                        vec![link(
                            name,
                            format!("/sessions/{}", encode(&session.id)),
                            "session-name",
                        )],
                    ),
                    copy(
                        "text-sm text-secondary",
                        session
                            .user_agent
                            .as_ref()
                            .and_then(|ua| ua.os.clone())
                            .unwrap_or_default(),
                    ),
                ],
            ),
            ui::details(fields),
        ],
    )
}
fn oauth_card(session: OAuthSession) -> View {
    let client = session.client.clone();
    let icon = session
        .user_agent
        .as_ref()
        .map_or("❓", |agent| match agent.device_type {
            DeviceType::Pc => "🖥",
            DeviceType::Mobile => "📱",
            DeviceType::Unknown => "❓",
        });
    let name = session
        .display_name
        .clone()
        .or_else(|| {
            session
                .client
                .as_ref()
                .and_then(|client| client.client_name.clone())
        })
        .unwrap_or_else(|| "Unknown application".into());
    let mut fields = vec![];
    if let Some(active) = session.last_active_at {
        fields.push(("Last active".into(), format_last_active(&active)));
    }
    if let Some(ip) = session.last_active_ip {
        fields.push(("IP address".into(), ip));
    }
    let mut title = vec![link(
        name,
        format!("/sessions/{}", encode(&session.id)),
        "session-name",
    )];
    if let Some(client) = client {
        let name = client.client_name.unwrap_or(client.client_id);
        let avatar = match client.logo_uri {
            Some(uri) => Box::new(image().source(uri).alt(name.clone())) as View,
            None => plain(
                name.chars()
                    .next()
                    .map_or("?".into(), |value| value.to_uppercase().to_string()),
            ),
        };
        title.push(block(
            "session-client",
            vec![block("client-avatar", vec![avatar]), plain(name)],
        ));
    }
    block(
        "session-card",
        vec![
            block(
                "card-header",
                vec![copy("device-icon", icon), block("content", title)],
            ),
            ui::details(fields),
        ],
    )
}
pub fn detail(scope: &Scope, id: String) -> View {
    let request = id.clone();
    let source = ui::resource(scope, move || {
        let path = format!("/self/sessions/{}", encode(&request));
        async move { api::api_get::<Session>(&path).await }
    });
    ui::resource_body(source, move |scope, session| {
        let state = Action::new(scope);
        let mut fields = vec![];
        let (title, prefix, id) = match session {
            Session::BrowserSession(session) => {
                let name = browser_name(&session);
                if let Some(created) = session.created_at {
                    fields.push(("Created".into(), format_date(&created)));
                }
                if let Some(active) = session.last_active_at {
                    fields.push(("Last active".into(), format_last_active(&active)));
                }
                if let Some(ip) = session.last_active_ip {
                    fields.push(("IP address".into(), ip));
                }
                if let Some(agent) = session.user_agent {
                    if let Some(os) = agent.os {
                        fields.push(("OS".into(), os));
                    }
                    if let Some(browser) = agent.name {
                        fields.push(("Browser".into(), browser));
                    }
                }
                if let Some(auth) = session.last_authentication {
                    fields.push(("Last authenticated".into(), format_date(&auth.created_at)));
                }
                (name, "browser-sessions", session.id)
            }
            Session::OAuthSession(session) => {
                let name = session
                    .display_name
                    .clone()
                    .or_else(|| session.client.as_ref().and_then(|v| v.client_name.clone()))
                    .unwrap_or_else(|| "Unknown application".into());
                if let Some(created) = session.created_at {
                    fields.push(("Created".into(), format_date(&created)));
                }
                if let Some(active) = session.last_active_at {
                    fields.push(("Last active".into(), format_last_active(&active)));
                }
                if let Some(ip) = session.last_active_ip {
                    fields.push(("IP address".into(), ip));
                }
                if let Some(scope) = session.scope {
                    fields.push(("Scope".into(), scope));
                }
                if let Some(client) = session.client {
                    fields.push((
                        "Client".into(),
                        client.client_name.unwrap_or(client.client_id),
                    ));
                }
                (name, "oauth-sessions", session.id)
            }
        };
        let mut body = vec![
            link("← Back to sessions", "/sessions", "link"),
            heading(1, "heading-xs", title.clone()),
            ui::details(fields),
            state.messages(),
        ];
        if prefix == "oauth-sessions" {
            let request = id.clone();
            let open = scope.cage(false);
            let form = ui::form(
                scope,
                "rename-session",
                vec![Field::new(scope, "Display name", title)],
                "Save",
                "btn btn-primary",
                state,
                move |values| {
                    let path = format!("/oauth-sessions/{}/name", encode(&request));
                    async move {
                        api::api_put::<serde_json::Value>(&path,serde_json::json!({"human_name":(!values[0].trim().is_empty()).then(||values[0].trim().to_owned())})).await?;
                        go("/sessions")?;
                        Ok(None)
                    }
                },
            );
            body.push(ui::dialog(
                scope,
                "rename-session",
                "Edit display name",
                "btn btn-secondary",
                form,
                open,
            ));
        }
        body.push(ui::action(
            scope,
            "End session",
            "btn btn-destructive",
            state,
            move || {
                let path = format!("/{prefix}/{}", encode(&id));
                async move {
                    let result = api::api_delete::<EndSessionPayload>(&path).await?;
                    if result.status != EndSessionStatus::Ended {
                        return Err("Session could not be ended.".into());
                    }
                    go("/sessions")?;
                    Ok(None)
                }
            },
        ));
        stack(body)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursor_query_keeps_connection_and_ended_filter() {
        let page = Pagination {
            direction: Some((true, "app:cursor 1".into())),
            include_ended: true,
            limit: 6,
        };
        assert_eq!(
            query("app", &page),
            "?session_limit=6&app_after=app%3Acursor%201&include_ended=true"
        );
    }
}
