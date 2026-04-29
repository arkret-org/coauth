// This is needed to make the Environment::add* functions work
#![allow(clippy::needless_pass_by_value)]

//! Template environment setup: registers filters, functions, tests,
//! and global objects used by the Jinja templates.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    str::FromStr,
    sync::{Arc, atomic::AtomicUsize},
};

use chrono::Timelike as _;
use coauth_data::UrlBuilder;
use coauth_i18n::{DataLocale, Translator};
use minijinja::{
    Error, ErrorKind, State, Value,
    value::{Kwargs, Object, ViaDeserialize, from_args},
};
use url::Url;

/// Populate the given minijinja [`Environment`](minijinja::Environment) with
/// all custom filters, functions, tests, and globals needed by the templates.
pub fn register(
    env: &mut minijinja::Environment,
    url_builder: UrlBuilder,
    translator: Arc<Translator>,
) {
    // Third-party compatibility helpers
    env.set_unknown_method_callback(minijinja_contrib::pycompat::unknown_method_callback);
    minijinja_contrib::add_to_environment(env);

    // Tests
    env.add_test("empty", test_is_empty);

    // Filters
    env.add_filter("to_params", filter_to_params);
    env.add_filter("simplify_url", filter_simplify_url);
    env.add_filter("add_slashes", filter_add_slashes);
    env.add_filter("parse_user_agent", filter_parse_user_agent);
    env.add_filter("id_color_hash", filter_id_color_hash);

    // URL prefix filter -- needs a captured UrlBuilder
    env.add_filter("prefix_url", move |raw_url: &str| -> String {
        apply_url_prefix(raw_url, &url_builder)
    });

    // Functions
    env.add_function("add_params_to_url", fn_add_params_to_url);
    env.add_function("counter", || Ok(Value::from_object(Counter::new())));

    // Globals
    env.add_global("include_asset", Value::from_object(IncludeAssetStub));
    env.add_global(
        "translator",
        Value::from_object(TranslatorFactory { translator }),
    );
}

// ---------------------------------------------------------------------------
// URL prefix helper
// ---------------------------------------------------------------------------

fn apply_url_prefix(raw_url: &str, url_builder: &UrlBuilder) -> String {
    // Non-internal URLs (not starting with /) are returned as-is
    if !raw_url.starts_with('/') {
        return raw_url.to_owned();
    }

    match url_builder.prefix() {
        Some(prefix) => format!("{prefix}{raw_url}"),
        None => raw_url.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Test: empty
// ---------------------------------------------------------------------------

fn test_is_empty(seq: Value) -> bool {
    seq.len() == Some(0)
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// Escapes backslashes, double-quotes, and single-quotes in a string.
fn filter_add_slashes(input: &str) -> String {
    let mut result = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\'' => result.push_str("\\'"),
            other => result.push(other),
        }
    }
    result
}

/// Serializes a value to URL-encoded query parameters.
fn filter_to_params(params: &Value, kwargs: Kwargs) -> Result<String, Error> {
    let encoded = serde_urlencoded::to_string(params).map_err(|e| {
        Error::new(
            ErrorKind::InvalidOperation,
            "Could not serialize parameters",
        )
        .with_source(e)
    })?;

    let prefix: &str = kwargs.get("prefix").unwrap_or("");
    kwargs.assert_all_used()?;

    if encoded.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("{prefix}{encoded}"))
    }
}

/// Filter which simplifies a URL to its domain name for HTTP(S) URLs
fn filter_simplify_url(raw_url: &str, kwargs: Kwargs) -> Result<String, minijinja::Error> {
    let Ok(mut parsed) = Url::from_str(raw_url) else {
        return Ok(raw_url.to_owned());
    };

    // Strip query and fragment unconditionally
    parsed.set_query(None);
    parsed.set_fragment(None);

    // Only simplify HTTPS URLs further
    if parsed.scheme() != "https" {
        return Ok(parsed.to_string());
    }

    let keep_path: bool = kwargs.get::<Option<bool>>("keep_path")?.unwrap_or_default();
    kwargs.assert_all_used()?;

    let Some(host) = parsed.domain() else {
        return Ok(parsed.to_string());
    };

    if keep_path {
        Ok(format!("{host}{path}", path = parsed.path()))
    } else {
        Ok(host.to_owned())
    }
}

/// Compute a 1-6 hash of a string, matching compound-web's `useIdColorHash`.
fn filter_id_color_hash(input: &str) -> u32 {
    let char_sum: u32 = input.chars().map(|c| c as u32).sum();
    char_sum % 6 + 1
}

/// Parse a raw user-agent string into a structured representation.
fn filter_parse_user_agent(raw_ua: String) -> Value {
    Value::from_serialize(coauth_data::UserAgent::parse(raw_ua))
}

// ---------------------------------------------------------------------------
// Function: add_params_to_url
// ---------------------------------------------------------------------------

/// Where to place the parameters in the URL
enum ParamTarget {
    Fragment,
    Query,
}

fn fn_add_params_to_url(
    uri: ViaDeserialize<Url>,
    mode: &str,
    params: ViaDeserialize<HashMap<String, Value>>,
) -> Result<String, Error> {
    let target = match mode {
        "fragment" => ParamTarget::Fragment,
        "query" => ParamTarget::Query,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "Invalid `mode` parameter",
            ));
        }
    };

    // Parse existing params from the URL
    let existing_str = match target {
        ParamTarget::Fragment => uri.fragment(),
        ParamTarget::Query => uri.query(),
    };

    let existing_params: HashMap<String, Value> = existing_str
        .map(serde_urlencoded::from_str)
        .transpose()
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidOperation,
                "Could not parse existing `uri` parameters",
            )
            .with_source(e)
        })?
        .unwrap_or_default();

    // Merge: new params take precedence, but we use a BTreeMap for
    // deterministic key ordering in the output
    let merged: BTreeMap<&String, &Value> = params.iter().chain(existing_params.iter()).collect();

    let encoded = serde_urlencoded::to_string(merged).map_err(|e| {
        Error::new(
            ErrorKind::InvalidOperation,
            "Could not serialize back parameters",
        )
        .with_source(e)
    })?;

    let mut uri = uri;
    match target {
        ParamTarget::Fragment => uri.set_fragment(Some(&encoded)),
        ParamTarget::Query => uri.set_query(Some(&encoded)),
    }

    Ok(uri.to_string())
}

// ---------------------------------------------------------------------------
// Global object: translator / translate
// ---------------------------------------------------------------------------

/// Factory object: calling `translator("en")` produces a [`TranslateHandle`].
struct TranslatorFactory {
    translator: Arc<Translator>,
}

impl fmt::Debug for TranslatorFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranslatorFactory")
            .field("translator", &"..")
            .finish()
    }
}

impl fmt::Display for TranslatorFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("translator")
    }
}

impl Object for TranslatorFactory {
    fn call(self: &Arc<Self>, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (locale_str,): (&str,) = from_args(args)?;

        let locale: DataLocale = locale_str.parse().map_err(|e| {
            Error::new(ErrorKind::InvalidOperation, "Invalid language").with_source(e)
        })?;

        Ok(Value::from_object(TranslateHandle {
            locale,
            translator: Arc::clone(&self.translator),
        }))
    }
}

/// A locale-bound translation handle. Calling it with a message key returns
/// the formatted translation. Also exposes `relative_date` and `short_time`
/// methods.
struct TranslateHandle {
    translator: Arc<Translator>,
    locale: DataLocale,
}

impl fmt::Debug for TranslateHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranslateHandle")
            .field("locale", &self.locale)
            .finish()
    }
}

impl fmt::Display for TranslateHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("translate")
    }
}

impl Object for TranslateHandle {
    fn call(self: &Arc<Self>, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (msg_key, kwargs): (&str, Kwargs) = from_args(args)?;

        // Collect keyword arguments into FluentArgs
        let mut fluent_args = fluent_bundle::FluentArgs::new();
        for name in kwargs.args() {
            let val: Value = kwargs.get(name)?;
            // Convert minijinja Value to FluentValue
            if let Some(n) = val.as_i64() {
                fluent_args.set(name.to_owned(), fluent_bundle::FluentValue::from(n));
            } else if let Some(s) = val.as_str() {
                fluent_args.set(
                    name.to_owned(),
                    fluent_bundle::FluentValue::from(s.to_owned()),
                );
            } else {
                fluent_args.set(
                    name.to_owned(),
                    fluent_bundle::FluentValue::from(val.to_string()),
                );
            }
        }
        kwargs.assert_all_used()?;

        let args_ref = if fluent_args.iter().count() > 0 {
            Some(&fluent_args)
        } else {
            None
        };

        let formatted = self
            .translator
            .format(&self.locale, msg_key, args_ref)
            .ok_or_else(|| Error::new(ErrorKind::InvalidOperation, "Missing translation"))?;

        Ok(Value::from_safe_string(formatted))
    }

    fn call_method(
        self: &Arc<Self>,
        _state: &State,
        method: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        match method {
            "relative_date" => {
                let (raw_date,): (String,) = from_args(args)?;
                let parsed_date: chrono::DateTime<chrono::Utc> = raw_date.parse().map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidOperation,
                        "Invalid date while calling function `relative_date`",
                    )
                    .with_source(e)
                })?;

                // NOTE: template functions are called synchronously from
                // minijinja during render and don't have access to the
                // async-scope `Clock`. We fall back to the system clock,
                // which is acceptable because `relative_date` output is
                // day-granularity and test snapshots render their own
                // fixtures outside the template layer.
                #[allow(clippy::disallowed_methods)]
                let now = chrono::Utc::now();

                let day_diff = (parsed_date - now).num_days();

                let formatted = self
                    .translator
                    .relative_date(&self.locale, day_diff)
                    .map_err(|_| {
                        Error::new(
                            ErrorKind::InvalidOperation,
                            "Failed to format relative date",
                        )
                    })?;

                Ok(Value::from(formatted))
            }

            "short_time" => {
                let (raw_date,): (String,) = from_args(args)?;
                let parsed_date: chrono::DateTime<chrono::Utc> = raw_date.parse().map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidOperation,
                        "Invalid date while calling function `time`",
                    )
                    .with_source(e)
                })?;

                // NOTE: we format `parsed_date` in UTC rather than the
                // viewer's timezone. The callers use `short_time` for
                // email-metadata rendering ("sent at 14:02"), where
                // displaying UTC is unambiguous; localising by timezone
                // would require storing the user's preferred TZ and is not
                // yet modelled.
                let time_of_day = coauth_i18n::icu_datetime::input::Time::try_new(
                    parsed_date.hour() as u8,
                    parsed_date.minute() as u8,
                    parsed_date.second() as u8,
                    parsed_date.nanosecond(),
                )
                .map_err(|_| Error::new(ErrorKind::InvalidOperation, "Failed to convert time"))?;

                let formatted = self
                    .translator
                    .short_time(&self.locale, &time_of_day)
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidOperation, "Failed to format time")
                    })?;

                Ok(Value::from(formatted))
            }

            _ => Err(Error::new(
                ErrorKind::InvalidOperation,
                "Invalid method on include_asset",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Global object: include_asset (stub)
// ---------------------------------------------------------------------------

/// Stub implementation for the `include_asset` global. In production this
/// would inline the referenced asset; here it emits an HTML comment.
#[derive(Debug)]
struct IncludeAssetStub;

impl fmt::Display for IncludeAssetStub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fake_include_asset")
    }
}

impl Object for IncludeAssetStub {
    fn call(self: &Arc<Self>, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (asset_path,): (&str,) = from_args(args)?;
        Ok(Value::from_safe_string(format!(
            "<!--- include_asset {asset_path} -->"
        )))
    }
}

// ---------------------------------------------------------------------------
// Function: counter
// ---------------------------------------------------------------------------

/// A thread-safe, atomically-incrementing counter exposed to templates.
#[derive(Debug)]
struct Counter {
    value: AtomicUsize,
}

impl Counter {
    fn new() -> Self {
        Self {
            value: AtomicUsize::new(0),
        }
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.value.load(std::sync::atomic::Ordering::Relaxed)
        )
    }
}

impl Object for Counter {
    fn call_method(
        self: &Arc<Self>,
        _state: &State,
        method: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        from_args::<()>(args)?;

        match method {
            "reset" => {
                self.value.store(0, std::sync::atomic::Ordering::Relaxed);
                Ok(Value::UNDEFINED)
            }
            "next" => {
                let prev = self
                    .value
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Value::from(prev))
            }
            "peek" => {
                let current = self.value.load(std::sync::atomic::Ordering::Relaxed);
                Ok(Value::from(current))
            }
            _ => Err(Error::new(
                ErrorKind::InvalidOperation,
                "Invalid method on counter",
            )),
        }
    }
}
