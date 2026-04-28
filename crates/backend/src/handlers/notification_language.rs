use salvo::prelude::*;

use crate::handlers::preferred_language;

/// Resolve the locale used for outbound notifications.
///
/// An explicit language from the client takes precedence when it is present
/// and non-empty. Otherwise the request's preferred language is used.
#[must_use]
pub fn notification_language(req: &Request, depot: &Depot, requested: Option<&str>) -> String {
    requested
        .map(str::trim)
        .filter(|language| !language.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| preferred_language(req, depot).to_string())
}
