use coauth_data::user::{UserFilter, UserRepository};
use coauth_data::{BoxRepository, RepositoryAccess, RepositoryError};
use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum PrepareAdminBootstrapError {
    #[error("bootstrap admin token is invalid")]
    InvalidToken,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

fn normalize_optional_token(token: Option<&str>) -> Option<&str> {
    token.map(str::trim).filter(|token| !token.is_empty())
}

pub(super) async fn prepare_admin_bootstrap(
    repo: &mut BoxRepository,
    configured_bootstrap_admin_token: Option<&str>,
    requested_bootstrap_admin_token: Option<&str>,
) -> Result<bool, PrepareAdminBootstrapError> {
    repo.user().acquire_bootstrap_admin_lock().await?;

    let admin_count = repo
        .user()
        .count(UserFilter::new().can_request_admin_only())
        .await?;

    if admin_count > 0 {
        return Ok(false);
    }

    let Some(configured_bootstrap_admin_token) =
        normalize_optional_token(configured_bootstrap_admin_token)
    else {
        return Ok(false);
    };

    match normalize_optional_token(requested_bootstrap_admin_token) {
        Some(requested_bootstrap_admin_token)
            if crate::util::constant_time_token_eq(
                requested_bootstrap_admin_token,
                configured_bootstrap_admin_token,
            ) =>
        {
            Ok(true)
        }
        Some(_) => Err(PrepareAdminBootstrapError::InvalidToken),
        None => Ok(false),
    }
}
