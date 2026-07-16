// Copyright 2025 Taidge Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

pub struct Context {
    keys: Vec<Key>,
    func: String,
}

impl Context {
    pub fn new(func: String) -> Self {
        Self {
            keys: Vec::new(),
            func,
        }
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
}

#[derive(Debug, Clone)]
pub struct Key {
    name: String,
}

impl Key {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}
