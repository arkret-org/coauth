// Copyright 2025, 2026 Taidge Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only

use chrono::Duration;
use coauth_data::Clock as _;
use hyper::{Request, StatusCode};
use insta::assert_json_snapshot;
use serde_json::json;
use ulid::Ulid;

use crate::handlers::test_utils::{
    RequestBuilderExt, ResponseExt, TestState, assert_stamped_since, setup, stable_json,
};

mod crud;
mod filters;
mod list;
mod mutate;
mod pagination;

/// Provision a set of tokens covering all relevant combinations of
/// used / revoked / expired status so that filter tests can work
/// against a known data set.
async fn seed_tokens(ts: &mut TestState) {
    let mut repo = ts.repository().await.unwrap();

    // 1 -- never used, not revoked, not expired
    repo.user_registration_token()
        .add(
            &mut ts.rng(),
            &ts.clock,
            "token_unused".to_owned(),
            Some(10),
            None,
        )
        .await
        .unwrap();

    // 2 -- used once, not revoked
    let tok = repo
        .user_registration_token()
        .add(
            &mut ts.rng(),
            &ts.clock,
            "token_used".to_owned(),
            Some(10),
            None,
        )
        .await
        .unwrap();
    repo.user_registration_token()
        .use_token(&ts.clock, tok)
        .await
        .unwrap();

    // 3 -- never used, revoked
    let tok = repo
        .user_registration_token()
        .add(
            &mut ts.rng(),
            &ts.clock,
            "token_revoked".to_owned(),
            Some(10),
            None,
        )
        .await
        .unwrap();
    repo.user_registration_token()
        .revoke(&ts.clock, tok)
        .await
        .unwrap();

    // 4 -- used once, then revoked
    let tok = repo
        .user_registration_token()
        .add(
            &mut ts.rng(),
            &ts.clock,
            "token_used_revoked".to_owned(),
            Some(10),
            None,
        )
        .await
        .unwrap();
    let tok = repo
        .user_registration_token()
        .use_token(&ts.clock, tok)
        .await
        .unwrap();
    repo.user_registration_token()
        .revoke(&ts.clock, tok)
        .await
        .unwrap();

    // 5 -- already expired
    let past = ts.clock.now() - Duration::try_days(1).unwrap();
    repo.user_registration_token()
        .add(
            &mut ts.rng(),
            &ts.clock,
            "token_expired".to_owned(),
            Some(5),
            Some(past),
        )
        .await
        .unwrap();

    repo.save().await.unwrap();
}
