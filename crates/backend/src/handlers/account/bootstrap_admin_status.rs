use coauth_data::{BoxRepository, RepositoryAccess, RepositoryError, SiteConfig, user::UserFilter};
use salvo::{oapi::ToSchema, prelude::*};
use serde::Serialize;

use super::{DepotExt, RouteError};

#[derive(Debug, Serialize, ToSchema)]
pub struct BootstrapAdminStatusResponse {
    pub has_admin: bool,
    pub token_configured: bool,
    pub setup_required: bool,
}

fn bootstrap_token_configured(config: &SiteConfig) -> bool {
    config
        .bootstrap_admin_token
        .as_deref()
        .map(str::trim)
        .is_some_and(|token| !token.is_empty())
}

async fn load_bootstrap_admin_status_from(
    config: &SiteConfig,
    repo: &mut BoxRepository,
) -> Result<BootstrapAdminStatusResponse, RepositoryError> {
    let has_admin = repo
        .user()
        .count(UserFilter::new().can_request_admin_only())
        .await?
        > 0;
    let token_configured = bootstrap_token_configured(config);

    Ok(BootstrapAdminStatusResponse {
        has_admin,
        token_configured,
        setup_required: token_configured && !has_admin,
    })
}

#[endpoint]
pub async fn get(depot: &Depot) -> Result<Json<BootstrapAdminStatusResponse>, RouteError> {
    let config = depot.site_config()?;
    let mut repo = depot.repo().await?;
    Ok(Json(
        load_bootstrap_admin_status_from(&config, &mut repo).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::load_bootstrap_admin_status_from;
    use crate::handlers::test_utils::{TestState, setup, test_site_config};

    #[tokio::test]
    async fn setup_required_when_token_exists_and_no_admin_exists() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_site_config(
            pool,
            coauth_data::SiteConfig {
                bootstrap_admin_token: Some("bootstrap-secret".to_owned()),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut repo = state.repository().await.unwrap();
        let payload = load_bootstrap_admin_status_from(&state.site_config, &mut repo)
            .await
            .unwrap();
        repo.cancel().await.unwrap();

        assert!(!payload.has_admin);
        assert!(payload.token_configured);
        assert!(payload.setup_required);
    }

    // The lock is held briefly across the `repo.user().add(...).await` call
    // because the rng is a sync `std::sync::Mutex` shared with the repository
    // helper; this test is single-threaded so the await-while-locked is safe.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn setup_not_required_after_first_admin_exists() {
        setup();
        let Some(pool) = coauth_data::test_utils::setup_test_pool().await else {
            return;
        };
        let state = TestState::from_pool_with_site_config(
            pool,
            coauth_data::SiteConfig {
                bootstrap_admin_token: Some("bootstrap-secret".to_owned()),
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut repo = state.repository().await.unwrap();
        let mut rng = state.rng.lock().unwrap();
        let user = repo
            .user()
            .add(&mut *rng, state.clock.as_ref(), "admin".to_owned())
            .await
            .unwrap();
        repo.user().set_can_request_admin(user, true).await.unwrap();
        repo.cancel().await.unwrap();

        let mut repo = state.repository().await.unwrap();
        let payload = load_bootstrap_admin_status_from(&state.site_config, &mut repo)
            .await
            .unwrap();
        repo.cancel().await.unwrap();

        assert!(payload.has_admin);
        assert!(payload.token_configured);
        assert!(!payload.setup_required);
    }
}
