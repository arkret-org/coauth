use coauth_account_types::OAuthClientDetail;
use salvo::prelude::*;

use super::{DepotExt, NodeType, RouteError};
use crate::handlers::account::service::connections::{OAuthClientLookupError, load_oauth_client};

/// GET /_coauth/self/oauth-clients/:id
#[endpoint]
pub async fn get_client(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<OAuthClientDetail>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuthClient.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let repo = repo_factory.create().await?;

    let client = load_oauth_client(repo, ulid)
        .await
        .map_err(map_client_lookup_error)?;

    Ok(Json(OAuthClientDetail {
        id: NodeType::OAuthClient.serialize(client.id),
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        client_uri: client
            .client_uri
            .as_ref()
            .map(std::string::ToString::to_string),
        tos_uri: client
            .tos_uri
            .as_ref()
            .map(std::string::ToString::to_string),
        policy_uri: client
            .policy_uri
            .as_ref()
            .map(std::string::ToString::to_string),
        logo_uri: client
            .logo_uri
            .as_ref()
            .map(std::string::ToString::to_string),
    }))
}

fn map_client_lookup_error(error: OAuthClientLookupError) -> RouteError {
    match error {
        OAuthClientLookupError::NotFound => RouteError::NotFound,
        OAuthClientLookupError::Repository(error) => RouteError::from(error),
    }
}
