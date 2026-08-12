use coauth_account_types::PostAuthAction;

#[cfg(target_arch = "wasm32")]
const SESSION_KEY: &str = "coauth.session.post_auth_action.v1";

fn from_parts(kind: &str, id: &str) -> Option<PostAuthAction> {
    let id = id.parse::<ulid::Ulid>().ok()?;
    match kind {
        "continue_authorization_grant" => Some(PostAuthAction::ContinueAuthorizationGrant { id }),
        "continue_device_code_grant" => Some(PostAuthAction::ContinueDeviceCodeGrant { id }),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
fn session_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.session_storage().ok().flatten()
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn current() -> Option<PostAuthAction> {
    let window = web_sys::window()?;
    let query = window.location().search().ok()?;
    let params = web_sys::UrlSearchParams::new_with_str(&query).ok()?;
    from_parts(&params.get("kind")?, &params.get("id")?)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn current() -> Option<PostAuthAction> {
    None
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn save(action: &PostAuthAction) {
    let Some(storage) = session_storage() else {
        return;
    };
    if let Ok(encoded) = serde_json::to_string(action) {
        let _ = storage.set_item(SESSION_KEY, &encoded);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn save(_action: &PostAuthAction) {}

#[cfg(target_arch = "wasm32")]
pub(crate) fn load() -> Option<PostAuthAction> {
    let encoded = session_storage()?.get_item(SESSION_KEY).ok().flatten()?;
    serde_json::from_str(&encoded).ok()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn load() -> Option<PostAuthAction> {
    None
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn clear() {
    if let Some(storage) = session_storage() {
        let _ = storage.remove_item(SESSION_KEY);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn clear() {}

/// Capture the server-authored continuation before the SPA router can rewrite
/// the entry URL. A bare `/register` is a new standalone registration and must
/// not inherit a previous tab-local OAuth transaction.
pub(crate) fn capture_entry_request() {
    #[cfg(target_arch = "wasm32")]
    {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Ok(pathname) = window.location().pathname() else {
            return;
        };
        if pathname != "/login" && pathname != "/register" {
            return;
        }
        if let Some(action) = current() {
            save(&action);
        } else if pathname == "/register" {
            clear();
        }
    }
}

pub(crate) fn save_parts(kind: &str, id: &str) {
    if let Some(action) = from_parts(kind, id) {
        save(&action);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_are_parsed_into_the_shared_strong_type() {
        let action = from_parts("continue_authorization_grant", "01KZSR7E53EEMVXE4ZN88CK3PT")
            .expect("valid action");
        assert!(matches!(
            action,
            PostAuthAction::ContinueAuthorizationGrant { .. }
        ));
        assert!(from_parts("unknown", "01KZSR7E53EEMVXE4ZN88CK3PT").is_none());
    }
}
