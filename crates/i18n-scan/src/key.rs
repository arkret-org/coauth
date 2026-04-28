// Copyright 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use minijinja::machinery::Span;

pub struct Context {
    keys: Vec<Key>,
    func: String,
    current_file: Option<String>,
}

impl Context {
    pub fn new(func: String) -> Self {
        Self {
            keys: Vec::new(),
            func,
            current_file: None,
        }
    }

    pub fn set_current_file(&mut self, file: &str) {
        self.current_file = Some(file.to_owned());
    }

    pub fn record(&mut self, key: Key) {
        self.keys.push(key);
    }

    pub fn func(&self) -> &str {
        &self.func
    }

    /// Return the collected keys as a deduplicated, sorted list of FTL message
    /// identifiers (dot-separated template keys are converted to
    /// hyphen-separated FTL IDs).
    pub fn ftl_keys(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.keys.iter().map(|k| k.name.replace('.', "-")).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn set_key_location(&self, mut key: Key, span: Span) -> Key {
        if let Some(file) = &self.current_file {
            key.location = Some(Location {
                file: file.clone(),
                span,
            });
        }

        key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Message,
    Plural,
}

#[derive(Debug, Clone)]
pub struct Location {
    #[allow(dead_code)]
    file: String,
    #[allow(dead_code)]
    span: Span,
}

#[derive(Debug, Clone)]
pub struct Key {
    #[allow(dead_code)]
    kind: Kind,
    name: String,
    location: Option<Location>,
}

impl Key {
    pub fn new(kind: Kind, name: String) -> Self {
        Self {
            kind,
            name,
            location: None,
        }
    }
}
