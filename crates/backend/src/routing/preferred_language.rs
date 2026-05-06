// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use coauth_i18n::{DataLocale, Translator, locale};
use headers::HeaderMapExt as _;
use salvo::prelude::*;

use crate::salvo_utils::language_detection::AcceptLanguage;

pub fn preferred_language(req: &Request, depot: &Depot) -> DataLocale {
    let translator = depot
        .get::<Arc<Translator>>("translator")
        .cloned()
        .unwrap_or_else(|_| Arc::new(Translator::default()));

    let accept_language = req.headers().typed_get::<AcceptLanguage>();

    let iter = accept_language
        .iter()
        .flat_map(AcceptLanguage::iter)
        .flat_map(|lang| {
            let lang = lang.clone();
            // NOTE: `zh-CN` does not fall back to `zh-Hans` via ICU's
            // automatic locale chain (but `zh-TW` → `zh-Hant` does), so we
            // expand it manually here. A full alias table would be a nicer
            // solution but has not been needed beyond this one case.
            if lang == locale!("zh-CN").into() {
                vec![lang, locale!("zh-Hans").into()]
            } else {
                vec![lang]
            }
        });

    translator.choose_locale(iter)
}
