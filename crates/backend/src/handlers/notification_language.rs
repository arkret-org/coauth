use salvo::prelude::*;

use crate::handlers::preferred_ui_locale;

/// Resolve the locale used for outbound notifications.
///
/// This used to be a third, separate precedence rule: any non-empty client
/// string won outright and was stored verbatim, so a caller could pin a
/// notification to a language the product does not ship. It now feeds the same
/// resolver as every other surface, which means the returned code is always one
/// the template catalogues actually carry.
///
/// * `account` — the recipient's stored `preferred_locale`. A notification is read later, on
///   whatever device the person happens to open, so their account preference outranks anything
///   about the request that triggered it.
/// * `requested` — an explicit per-message language override.
#[must_use]
pub fn notification_language(
    req: &Request,
    _depot: &Depot,
    account: Option<&str>,
    requested: Option<&str>,
) -> String {
    preferred_ui_locale(req, account, requested)
        .code()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_request_is_normalised_not_trusted_verbatim() {
        // `zh-Hant` is not a catalogue name; the old implementation stored it
        // as-is and the template lookup then missed.
        assert_eq!(
            notification_language(&Request::default(), &Depot::new(), None, Some("zh-Hant")),
            "zh"
        );
    }

    #[test]
    fn an_unsupported_request_falls_through_to_the_account() {
        assert_eq!(
            notification_language(&Request::default(), &Depot::new(), Some("zh"), Some("de")),
            "zh"
        );
    }

    #[test]
    fn blank_and_absent_requests_are_equivalent() {
        for requested in [Some("   "), Some(""), None] {
            assert_eq!(
                notification_language(&Request::default(), &Depot::new(), Some("zh"), requested),
                "zh"
            );
        }
    }

    #[test]
    fn nothing_known_yields_the_reference_locale() {
        assert_eq!(
            notification_language(&Request::default(), &Depot::new(), None, None),
            "en"
        );
    }
}
