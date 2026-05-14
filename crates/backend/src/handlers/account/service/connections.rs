use coauth_data::{
    BoxRepository, Client, Clock, Pagination, RepositoryAccess, RepositoryError, User,
    oauth::OAuthClientRepository,
    upstream_oauth::{
        UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
    },
};
use thiserror::Error;
use ulid::Ulid;

use crate::handlers::account::Requester;

pub struct LinkedAccountSummary {
    pub id: Ulid,
    pub provider_id: Ulid,
    pub provider_name: Option<String>,
    pub provider_brand: Option<String>,
    pub subject: String,
    pub human_account_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Error)]
pub enum LinkedAccountError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, Error)]
pub enum OAuthClientLookupError {
    #[error("not found")]
    NotFound,

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub async fn load_linked_accounts(
    repo: &mut BoxRepository,
    user: &User,
    limit: usize,
) -> Result<Vec<LinkedAccountSummary>, RepositoryError> {
    let filter = UpstreamOAuthLinkFilter::new().for_user(user);
    let page = repo
        .upstream_oauth_link()
        .list(filter, Pagination::first(limit))
        .await?;

    let providers = repo.upstream_oauth_provider().all_enabled().await?;
    let provider_map: std::collections::HashMap<Ulid, _> = providers
        .into_iter()
        .map(|provider| (provider.id, (provider.human_name, provider.brand_name)))
        .collect();

    Ok(page
        .edges
        .into_iter()
        .map(|edge| {
            let link = edge.node;
            let (provider_name, provider_brand) = provider_map
                .get(&link.provider_id)
                .cloned()
                .unwrap_or((None, None));

            LinkedAccountSummary {
                id: link.id,
                provider_id: link.provider_id,
                provider_name,
                provider_brand,
                subject: link.subject,
                human_account_name: link.human_account_name,
                created_at: link.created_at,
            }
        })
        .collect())
}

pub async fn list_linked_accounts(
    mut repo: BoxRepository,
    requester: &Requester,
    limit: usize,
) -> Result<Vec<LinkedAccountSummary>, LinkedAccountError> {
    let user = requester
        .browser_session()
        .map(|session| session.user.clone())
        .ok_or(LinkedAccountError::Unauthorized)?;

    let accounts = load_linked_accounts(&mut repo, &user, limit).await?;

    repo.cancel().await?;

    Ok(accounts)
}

pub async fn unlink_linked_account(
    mut repo: BoxRepository,
    requester: &Requester,
    clock: &dyn Clock,
    link_id: Ulid,
) -> Result<(), LinkedAccountError> {
    let user = requester
        .browser_session()
        .map(|session| session.user.clone())
        .ok_or(LinkedAccountError::Unauthorized)?;

    let link = repo
        .upstream_oauth_link()
        .lookup(link_id)
        .await?
        .ok_or(LinkedAccountError::NotFound)?;

    if link.user_id != Some(user.id) {
        return Err(LinkedAccountError::NotFound);
    }

    repo.upstream_oauth_link().remove(clock, link).await?;
    repo.save().await?;

    Ok(())
}

pub async fn load_oauth_client(
    mut repo: BoxRepository,
    client_id: Ulid,
) -> Result<Client, OAuthClientLookupError> {
    let client = repo
        .oauth_client()
        .lookup(client_id)
        .await?
        .ok_or(OAuthClientLookupError::NotFound)?;

    repo.cancel().await?;

    Ok(client)
}
