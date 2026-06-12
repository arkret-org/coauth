use serde::Serialize;

const EN_FTL: &str = include_str!("../../../translations/en.ftl");
const ZH_FTL: &str = include_str!("../../../translations/zh.ftl");

#[derive(Serialize)]
struct BundledFluentLocale {
    locale: &'static str,
    source: &'static str,
}

#[must_use]
pub fn bundled_fluent_json() -> String {
    serde_json::to_string(&[
        BundledFluentLocale {
            locale: "en",
            source: EN_FTL,
        },
        BundledFluentLocale {
            locale: "zh",
            source: ZH_FTL,
        },
    ])
    .expect("static Fluent catalogs should serialize")
}
