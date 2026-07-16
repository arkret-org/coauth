// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use coauth_i18n::{Locale, Translator, locale};
use headers::HeaderMapExt as _;
use salvo::prelude::*;

use crate::salvo_utils::language_detection::AcceptLanguage;

pub fn preferred_language(req: &Request, depot: &Depot) -> Locale {
    preferred_language_with_requested(req, depot, std::iter::empty())
}

/// Choose a UI locale using explicit OIDC `ui_locales` candidates first,
/// followed by the browser's `Accept-Language` preferences.
pub fn preferred_language_with_requested(
    req: &Request,
    depot: &Depot,
    requested: impl IntoIterator<Item = Locale>,
) -> Locale {
    let translator = depot
        .get::<Arc<Translator>>("translator")
        .cloned()
        .unwrap_or_else(|_| Arc::new(Translator::default()));

    let accept_language = req.headers().typed_get::<AcceptLanguage>();
    let requested = requested.into_iter().flat_map(expand_locale);
    let accepted = accept_language
        .iter()
        .flat_map(AcceptLanguage::iter)
        .cloned()
        .flat_map(expand_locale);

    translator.choose_locale(requested.chain(accepted))
}

fn expand_locale(lang: Locale) -> Vec<Locale> {
    // `zh-CN` does not fall back to `zh-Hans` through ICU's automatic chain.
    if lang == locale!("zh-CN") {
        vec![lang, locale!("zh-Hans")]
    } else {
        vec![lang]
    }
}
