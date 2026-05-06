// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Admin API endpoints for user management.
//!
//! Originally a single 1333-line `users.rs`. Split into focused
//! submodules — see `_tasks.md` T22:
//!
//! - [`create`] — `add_user`, `batch_invite`
//! - [`read`]   — `get_user`, `get_by_username`, `list_users`, plus the filter
//!   / status types they share
//! - [`update`] — `update_user` and its `AdminUserPatch` mapping
//! - [`security`] — `set_password`, `risk_action`
//! - [`tests`]  — the integration tests (was the larger half of the file)
//!
//! Public surface (`add_user`, `batch_invite`, `get_user`,
//! `get_by_username`, `list_users`, `update_user`, `risk_action`,
//! `set_password`) is re-exported here so the router wiring in
//! `server.rs` does not need to know about the layout.

mod create;
mod read;
mod security;
mod update;

#[cfg(test)]
mod tests;

pub use self::{
    create::{add_user, batch_invite},
    read::{get_by_username, get_user, list_users},
    security::{risk_action, set_password},
    update::update_user,
};
