// Copyright 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

// Without the custom_syntax feature, the `SyntaxConfig` is a unit struct
// which is annoying with this clippy lint
#![allow(clippy::default_constructed_unit_structs)]

use ::minijinja::{machinery::WhitespaceConfig, syntax::SyntaxConfig};
use camino::Utf8PathBuf;
use clap::Parser;
use key::Context;

mod key;
mod minijinja;

/// Scan a directory of templates for usage of the translation function and
/// output the list of translation keys (as FTL message identifiers).
#[derive(Parser)]
struct Options {
    /// The directory containing the templates
    templates: Utf8PathBuf,

    /// The extensions of the templates
    #[clap(long, default_value = "html,txt,subject")]
    extensions: String,

    /// The name of the translation function
    #[clap(long, default_value = "_")]
    function: String,
}

fn main() {
    tracing_subscriber::fmt::init();

    let options = Options::parse();

    let mut context = Context::new(options.function);

    for entry in walkdir::WalkDir::new(&options.templates) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }

        let path: Utf8PathBuf = entry.into_path().try_into().expect("Non-UTF8 path");
        let relative = path.strip_prefix(&options.templates).expect("Invalid path");

        let Some(extension) = path.extension() else {
            continue;
        };

        if options.extensions.split(',').any(|e| e == extension) {
            tracing::debug!("Parsing {relative}");
            let template = std::fs::read_to_string(&path).expect("Failed to read template");
            match minijinja::parse(
                &template,
                relative.as_str(),
                SyntaxConfig::default(),
                WhitespaceConfig::default(),
            ) {
                Ok(ast) => {
                    context.set_current_file(relative.as_str());
                    minijinja::find_in_stmt(&mut context, &ast).unwrap();
                }
                Err(err) => {
                    tracing::error!("Failed to parse {relative}: {}", err);
                }
            }
        }
    }

    let keys = context.ftl_keys();

    match keys.len() {
        0 => tracing::debug!("No translation keys found"),
        1 => tracing::info!("Found 1 translation key"),
        n => tracing::info!("Found {} translation keys", n),
    }

    serde_json::to_writer_pretty(std::io::stdout(), &keys).expect("Failed to write key list");

    // Just to make sure we don't end up without a trailing newline
    println!();
}
