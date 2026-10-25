//! Application-owned state and semantic controls for the account interface.
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::rc::Rc;

pub use glory::prelude::*;
pub type View = Box<dyn Widget>;
pub type Outcome = std::result::Result<Option<String>, String>;

pub fn plain(value: impl Into<String>) -> View {
    Box::new(text().kind(TextKind::Paragraph).content(value.into()))
}
pub fn copy(class: &str, value: impl Into<String>) -> View {
    Box::new(
        text()
            .kind(TextKind::Paragraph)
            .class(class.to_owned())
            .content(value.into()),
    )
}
pub fn heading(level: u8, class: &str, value: impl Into<String>) -> View {
    Box::new(
        text()
            .kind(TextKind::Heading(level))
            .class(class.to_owned())
            .content(value.into()),
    )
}
pub fn block(class: &str, children: Vec<View>) -> View {
    Box::new(view().class(class.to_owned()).fill(children))
}
pub fn stack(children: Vec<View>) -> View {
    block("flex flex-col gap-6", children)
}
pub fn link(label: impl Into<String>, target: impl Into<String>, class: &str) -> View {
    Box::new(
        sapid::anchor()
            .unstyled()
            .class(class.to_owned())
            .label(label.into())
            .href(target.into()),
    )
}
pub fn button(label: impl Into<String>, class: &str, action: impl FnMut() + 'static) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(class.to_owned())
            .label(label.into())
            .on_press(action),
    )
}
pub fn badge(label: impl Into<String>, ok: bool) -> View {
    copy(
        if ok {
            "badge badge-success"
        } else {
            "badge badge-warning"
        },
        label,
    )
}
pub fn separator() -> View {
    block("separator section", vec![])
}
pub fn disclosure(scope: &Scope, key: &str, label: &str, content: View, open: bool) -> View {
    let mut content = Some(content);
    Box::new(
        sapid::collapsible(format!("{}-{key}", scope.id().slot()))
            .unstyled()
            .class("collapsible-section")
            .label(label.to_owned())
            .default_open(open)
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || content.take().unwrap_or_else(|| block("", vec![]))),
    )
}
pub fn dialog(
    scope: &Scope,
    key: &str,
    label: &str,
    class: &str,
    content: View,
    open: Cage<bool>,
) -> View {
    let mut content = Some(content);
    Box::new(
        sapid::dialog(format!("{}-{key}", scope.id().slot()))
            .unstyled()
            .class("account-dialog")
            .label(label.to_owned())
            .title(label.to_owned())
            .close_label(if key == "edit-profile" {
                "Cancel"
            } else {
                "Close"
            })
            .open(open)
            .on_open_change(move |next| open.revise(|value| *value = next))
            .trigger_content({
                let label = label.to_owned();
                let class = class.to_owned();
                move || {
                    Box::new(
                        text()
                            .kind(TextKind::Inline)
                            .class(class.clone())
                            .content(label.clone()),
                    ) as View
                }
            })
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || content.take().unwrap_or_else(|| block("", vec![]))),
    )
}
pub fn note(title: impl Into<String>, description: impl Into<String>) -> View {
    let title = title.into();
    block(
        "page-heading",
        vec![
            copy(
                "page-heading-icon",
                if title == "Device not found" {
                    "?"
                } else {
                    "🔒"
                },
            ),
            heading(1, "heading-sm", title),
            copy("page-heading-subtitle", description),
        ],
    )
}
pub fn empty(title: &str, description: &str) -> View {
    block(
        "empty-state",
        vec![
            heading(2, "heading-xs", title),
            copy("text-md text-secondary", description),
        ],
    )
}
pub fn alert(message: impl Into<String>, success: bool) -> View {
    Box::new(
        view()
            .role(if success { Role::Status } else { Role::Alert })
            .class(if success {
                "alert alert-success"
            } else {
                "alert alert-critical"
            })
            .fill(plain(message)),
    )
}
pub fn reactive<T: Clone + 'static>(
    source: Cage<T>,
    render: impl Fn(&Scope, T) -> View + 'static,
) -> View {
    let render = Rc::new(render);
    Box::new(view().class("account-region").fill(widget(move |scope| {
        let mounted = Rc::new(RefCell::new(None::<glory::ui::Mounted>));
        scope.retain(mounted.clone())?;
        let weak = scope.downgrade();
        let render = render.clone();
        scope.effect(move || {
            let value = source.get();
            let Some(parent) = weak.upgrade() else { return };
            mounted.borrow_mut().take();
            let render = render.clone();
            match parent
                .mount_with(|| widget(move |child| render(child, value.clone()).build(child)))
            {
                Ok(next) => *mounted.borrow_mut() = Some(next),
                Err(error) => report(&format!("Coauth region render failed: {error}")),
            }
        });
        Ok(())
    })))
}
#[cfg(target_arch = "wasm32")]
fn report(message: &str) {
    web_sys::console::error_1(&message.into());
}
#[cfg(not(target_arch = "wasm32"))]
fn report(message: &str) {
    eprintln!("{message}");
}

pub struct Resource<T: Clone + 'static> {
    pub data: Cage<Option<std::result::Result<T, String>>>,
    revision: Cage<u64>,
}
impl<T: Clone + 'static> Clone for Resource<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data,
            revision: self.revision,
        }
    }
}
impl<T: Clone + 'static> Resource<T> {
    pub fn reload(&self) {
        self.revision.revise(|v| *v = v.wrapping_add(1));
    }
}
pub fn resource<T, F, Fut>(scope: &Scope, loader: F) -> Resource<T>
where
    T: Clone + 'static,
    F: Fn() -> Fut + 'static,
    Fut: Future<Output = std::result::Result<T, String>> + 'static,
{
    let data = scope.cage(None);
    let revision = scope.cage(0u64);
    let generation = Rc::new(Cell::new(0u64));
    let active = Rc::new(RefCell::new(None::<glory::core::TaskToken>));
    let weak = scope.downgrade();
    scope.effect(move || {
        let _ = revision.get();
        if let Some(task) = active.borrow_mut().take() {
            task.cancel();
        }
        let Some(scope) = weak.upgrade() else { return };
        let serial = generation.get().wrapping_add(1);
        generation.set(serial);
        data.revise(|value| *value = None);
        let future = loader();
        let generation = generation.clone();
        let weak = scope.downgrade();
        match scope.owner().spawn(async move {
            let result = future.await;
            if weak.upgrade().is_some() && generation.get() == serial {
                data.revise(|value| *value = Some(result));
            }
        }) {
            Ok(token) => *active.borrow_mut() = Some(token),
            Err(error) => data.revise(|value| *value = Some(Err(error.to_string()))),
        }
    });
    Resource { data, revision }
}
pub fn resource_body<T: Clone + 'static>(
    source: Resource<T>,
    render: impl Fn(&Scope, T) -> View + 'static,
) -> View {
    reactive(source.data, move |scope, result| match result {
        None => copy("loading-screen", "Loading…"),
        Some(Ok(value)) => render(scope, value),
        Some(Err(message)) => {
            let reload = source.clone();
            stack(vec![
                alert(message, false),
                button("Try again", "btn btn-secondary", move || reload.reload()),
            ])
        }
    })
}
#[derive(Clone, Copy)]
pub struct Action {
    pub busy: Cage<bool>,
    pub allowed: Cage<bool>,
    pub feedback: Cage<Option<std::result::Result<String, String>>>,
    owner: Cage<glory::ui::WeakScope>,
}
impl Action {
    pub fn new(scope: &Scope) -> Self {
        Self {
            busy: scope.cage(false),
            allowed: scope.cage(true),
            feedback: scope.cage(None),
            owner: scope.cage(scope.downgrade()),
        }
    }
    pub fn messages(self) -> View {
        reactive(self.feedback, |_, value| match value {
            Some(Ok(message)) => alert(message, true),
            Some(Err(message)) => alert(message, false),
            None => Box::new(widget(|_| Ok(()))),
        })
    }
    pub fn run<Fut>(self, _scope: &glory::ui::WeakScope, future: Fut)
    where
        Fut: Future<Output = Outcome> + 'static,
    {
        if self.busy.get_untracked() || !self.allowed.get_untracked() {
            return;
        }
        let Some(scope) = self.owner.get_untracked().upgrade() else {
            return;
        };
        self.busy.revise(|v| *v = true);
        self.feedback.revise(|v| *v = None);
        let state = self;
        let _ = scope.owner().spawn(async move {
            let response = future.await;
            state.busy.revise(|v| *v = false);
            state.feedback.revise(|v| {
                *v = match response {
                    Ok(message) => message.map(Ok),
                    Err(error) => Some(Err(error)),
                }
            });
        });
    }
}
#[derive(Clone)]
pub struct Field {
    pub label: String,
    pub value: Cage<String>,
    pub purpose: Purpose,
    pub required: bool,
    pub readonly: bool,
    pub placeholder: String,
    pub description: String,
    pub options: Vec<(String, String)>,
}
impl Field {
    pub fn new(scope: &Scope, label: impl Into<String>, initial: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: scope.cage(initial.into()),
            purpose: Purpose::Text,
            required: false,
            readonly: false,
            placeholder: String::new(),
            description: String::new(),
            options: vec![],
        }
    }
    pub fn password(mut self) -> Self {
        self.purpose = Purpose::Password;
        self
    }
    pub fn email(mut self) -> Self {
        self.purpose = Purpose::Email;
        self
    }
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub fn readonly(mut self, value: bool) -> Self {
        self.readonly = value;
        self
    }
    pub fn choices(
        mut self,
        options: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options = options
            .into_iter()
            .map(|(value, label)| (value.into(), label.into()))
            .collect();
        self
    }
    pub fn description(mut self, value: impl Into<String>) -> Self {
        self.description = value.into();
        self
    }
    pub fn placeholder(mut self, value: impl Into<String>) -> Self {
        self.placeholder = value.into();
        self
    }
}
pub fn field(
    scope: &Scope,
    key: &str,
    item: Field,
    enabled: impl Into<Lotus<bool>>,
    state: Action,
) -> View {
    let value = item.value;
    let enabled = enabled.into();
    let reference = scope.cage(None::<glory::render::NodeId>);
    if matches!(
        key,
        "login-identifier-0" | "login-password-0" | "register-0" | "registration-verify-0"
    ) {
        let weak = scope.downgrade();
        scope.effect(move || {
            if let Some(node) = reference.get()
                && let Some(scope) = weak.upgrade()
            {
                let weak = weak.clone();
                let _ = scope.owner().spawn(async move {
                    gloo_timers::future::TimeoutFuture::new(0).await;
                    if let Some(scope) = weak.upgrade() {
                        let _ = scope.action(glory::render::Action::Focus(node));
                    }
                });
            }
        });
    }
    let select_key = format!("select-{}-{key}", scope.id().slot());
    let hint_empty = item.placeholder.is_empty();
    let hint_class = scope.bond(move || {
        if hint_empty || !value.get().is_empty() {
            "form-input-hint is-hidden"
        } else {
            "form-input-hint"
        }
        .to_owned()
    });
    Box::new(
        sapid::field(format!("{}-{key}", scope.id().slot()))
            .unstyled()
            .class("form-field")
            .label(item.label.clone())
            .description(item.description.clone())
            .required(item.required)
            .readonly(item.readonly)
            .invalid(scope.bond(move || matches!(state.feedback.get(), Some(Err(_)))))
            .error(scope.bond(move || match state.feedback.get() {
                Some(Err(error)) => error,
                _ => String::new(),
            }))
            .control(move |control| -> View {
                if !item.options.is_empty() {
                    let options = item.options.clone();
                    let label = item.label.clone();
                    let key = select_key.clone();
                    let enabled = enabled.clone();
                    return Box::new(widget(move |scope| {
                        let controlled_options = options.clone();
                        let proposal_options = options.clone();
                        sapid::native_select(key.clone())
                            .unstyled()
                            .class("form-input")
                            .name(label.clone())
                            .field(control.clone())
                            .options(options.iter().enumerate().map(|(index, (value, label))| {
                                sapid::select_option(format!("option-{index}"), label).value(value)
                            }))
                            .value(scope.bond(move || {
                                controlled_options
                                    .iter()
                                    .position(|(candidate, _)| *candidate == value.get())
                                    .map(|index| format!("option-{index}"))
                            }))
                            .enabled(enabled.clone())
                            .on_value_change(move |new| {
                                let next = new
                                    .and_then(|key| {
                                        key.strip_prefix("option-")
                                            .and_then(|index| index.parse::<usize>().ok())
                                    })
                                    .and_then(|index| proposal_options.get(index))
                                    .map(|(value, _)| value.clone())
                                    .unwrap_or_default();
                                value.revise(|old| *old = next);
                            })
                            .show_in(scope)
                    }));
                }
                let input: View = if item.purpose == Purpose::Password {
                    Box::new(
                        sapid::password_input()
                            .unstyled()
                            .class("form-input")
                            .name(item.label.clone())
                            .node_ref(reference)
                            .field(control)
                            .value(value)
                            .enabled(enabled.clone())
                            .on_value_change(move |new| value.revise(|old| *old = new)),
                    )
                } else {
                    Box::new(
                        sapid::text_field()
                            .unstyled()
                            .class("form-input")
                            .name(item.label.clone())
                            .node_ref(reference)
                            .purpose(item.purpose)
                            .field(control)
                            .value(value)
                            .enabled(enabled.clone())
                            .on_value_change(move |new| value.revise(|old| *old = new)),
                    )
                };
                Box::new(
                    view().class("form-input-hint-wrap").fill((
                        input,
                        text()
                            .kind(TextKind::Inline)
                            .class(hint_class)
                            .content(item.placeholder.clone()),
                    )),
                )
            }),
    )
}
pub fn form<F, Fut>(
    scope: &Scope,
    key: &str,
    fields: Vec<Field>,
    label: impl Into<String>,
    class: &str,
    state: Action,
    submit: F,
) -> View
where
    F: Fn(Vec<String>) -> Fut + 'static,
    Fut: Future<Output = Outcome> + 'static,
{
    let enabled = scope.bond(move || !state.busy.get());
    let can_submit = scope.bond(move || !state.busy.get() && state.allowed.get());
    let values = fields.iter().map(|field| field.value).collect::<Vec<_>>();
    let mut children = if key == "new-passkey" {
        vec![]
    } else {
        vec![state.messages()]
    };
    let new_password = fields
        .iter()
        .find(|field| field.label == "New password")
        .map(|field| field.value);
    for (index, item) in fields.into_iter().enumerate() {
        let is_new = item.label == "New password";
        children.push(field(
            scope,
            &format!("{key}-{index}"),
            item,
            enabled,
            state,
        ));
        if is_new && let Some(value) = new_password {
            children.push(password_strength(scope, value));
        }
    }
    children.push(Box::new(
        sapid::submit_button()
            .unstyled()
            .class(class.to_owned())
            .label(label.into())
            .enabled(can_submit),
    ));
    let weak = scope.downgrade();
    Box::new(
        sapid::form(format!("{}-{key}", scope.id().slot()))
            .unstyled()
            .class(if key == "add-email" {
                "form-root account-inline-form"
            } else if key == "new-passkey" {
                "form-root account-new-passkey"
            } else {
                "form-root"
            })
            .fill(children)
            .on_submit(move |_| {
                if state.busy.get_untracked() {
                    return;
                }
                let snapshot = values.iter().map(|value| value.get_untracked()).collect();
                state.run(&weak, submit(snapshot));
            }),
    )
}
fn password_strength(scope: &Scope, value: Cage<String>) -> View {
    let policy = resource(scope, || {
        crate::api::api_get::<crate::api::types::SiteConfig>("/self/site-config")
    });
    let snapshot = scope.cage((String::new(), None::<u8>));
    scope.effect(move || {
        let minimum = policy
            .data
            .get()
            .and_then(std::result::Result::ok)
            .map(|site| site.minimum_password_complexity);
        snapshot.revise(|old| *old = (value.get(), minimum));
    });
    reactive(snapshot, |_, (value, minimum)| {
        if value.is_empty() {
            return Box::new(widget(|_| Ok(())));
        }
        let score = u8::from(zxcvbn::zxcvbn(&value, &[]).score());
        let key = ["very-weak", "weak", "fair", "good", "strong"][usize::from(score.min(4))];
        let mut label = crate::translations::t(&format!("coauth-password-strength-{key}"));
        if let Some(minimum) = minimum {
            label.push_str(" — ");
            label.push_str(&crate::translations::t(if score >= minimum {
                "coauth-password-strength-meets-requirement"
            } else {
                "coauth-password-strength-too-weak"
            }));
        }
        block(
            &format!("password-strength password-score-{score}"),
            vec![
                Box::new(
                    sapid::progress(f64::from(score))
                        .unstyled()
                        .class("password-strength-progress")
                        .range(0.0, 4.0)
                        .name("Password strength")
                        .value_text(label.clone()),
                ),
                copy("password-strength-label", label),
            ],
        )
    })
}
pub fn checkbox(_scope: &Scope, _key: &str, label: &str, value: Cage<bool>, enabled: bool) -> View {
    Box::new(
        sapid::checkbox()
            .unstyled()
            .class("checkbox-label")
            .name(label.to_owned())
            .label(label.to_owned())
            .checked(value)
            .enabled(enabled)
            .on_checked_change(move |next| value.revise(|old| *old = next)),
    )
}
pub fn action<F, Fut>(scope: &Scope, label: &str, class: &str, state: Action, submit: F) -> View
where
    F: Fn() -> Fut + 'static,
    Fut: Future<Output = Outcome> + 'static,
{
    let enabled = scope.bond(move || !state.busy.get() && state.allowed.get());
    let weak = scope.downgrade();
    Box::new(
        sapid::button()
            .unstyled()
            .class(class.to_owned())
            .label(label.to_owned())
            .enabled(enabled)
            .on_press(move || {
                if !state.busy.get_untracked() {
                    state.run(&weak, submit());
                }
            }),
    )
}
pub fn details(rows: Vec<(String, String)>) -> View {
    block(
        "session-metadata",
        rows.into_iter()
            .map(|(label, value)| {
                block(
                    "metadata-row",
                    vec![copy("key", label), copy("value", value)],
                )
            })
            .collect(),
    )
}
pub fn get_query(name: &str) -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        let query = web_sys::window()?.location().search().ok()?;
        web_sys::UrlSearchParams::new_with_str(&query)
            .ok()?
            .get(name)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = name;
        None
    }
}
pub fn go(url: &str) -> std::result::Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .ok_or("Browser window unavailable")?
            .location()
            .set_href(url)
            .map_err(|_| "Unable to navigate".into())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = url;
        Ok(())
    }
}
pub fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub fn auth_success() -> Outcome {
    let action =
        crate::post_auth_continuation::current().or_else(crate::post_auth_continuation::load);
    let url = match action {
        Some(coauth_account_types::PostAuthAction::ContinueAuthorizationGrant { id }) => {
            format!("/oauth/approval/{id}")
        }
        Some(coauth_account_types::PostAuthAction::ContinueDeviceCodeGrant { id }) => {
            format!("/device/{id}")
        }
        Some(coauth_account_types::PostAuthAction::ChangePassword) => "/password/change".into(),
        Some(coauth_account_types::PostAuthAction::LinkUpstream { id }) => {
            format!("/upstream/link/{id}")
        }
        Some(coauth_account_types::PostAuthAction::ManageAccount { action }) => match action {
            Some(coauth_account_types::AccountAction::Profile) => "/settings".into(),
            Some(coauth_account_types::AccountAction::SessionsList) => "/sessions".into(),
            Some(
                coauth_account_types::AccountAction::SessionView { device_id }
                | coauth_account_types::AccountAction::SessionEnd { device_id },
            ) => format!("/sessions/{}", encode(&device_id)),
            None => "/".into(),
        },
        None => "/".into(),
    };
    crate::post_auth_continuation::clear();
    go(&url)?;
    Ok(None)
}
