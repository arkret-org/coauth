use chrono::Duration;
use coauth_data::upstream_oauth::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository};
use coauth_data::user::UserRepository;
use coauth_data::{RepositoryAccess, UpstreamOAuthAuthorizationSessionState};
use hyper::{Request, StatusCode};
use insta::assert_json_snapshot;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use ulid::Ulid;

use super::test_utils;
use crate::handlers::test_utils::{
    RequestBuilderExt, ResponseExt, TestState, setup, stable_json, unique_test_nonce,
};

mod create;
mod delete;
mod get;
mod list;
mod patch;
