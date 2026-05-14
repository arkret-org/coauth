use salvo::{oapi::ToSchema, prelude::*};
use serde::Serialize;

use super::{DepotExt, NodeType, RouteError};
use crate::handlers::account::service::connections::{OAuth2ClientLookupError, load_oauth2_client};

#[derive(Serialize, ToSchema)]
pub struct Oauth2ClientResponse {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub logo_uri: Option<String>,
}

/// GET /api/v1/oauth2-clients/:id
#[endpoint]
pub async fn get_client(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<Oauth2ClientResponse>, RouteError> {
    let id = req
        .param::<String>("id")
        .ok_or(RouteError::BadRequest("missing id".into()))?;
    let ulid = NodeType::OAuth2Client.extract_ulid(&id)?;

    let repo_factory = depot.repo_factory()?;
    let repo = repo_factory.create().await?;

    let client = load_oauth2_client(repo, ulid)
        .await
        .map_err(map_client_lookup_error)?;

    Ok(Json(Oauth2ClientResponse {
        id: NodeType::OAuth2Client.serialize(client.id),
        client_id: client.client_id.to_string(),
        client_name: client.client_name.clone(),
        client_uri: client.client_uri.as_ref().map(|u| u.to_string()),
        tos_uri: client.tos_uri.as_ref().map(|u| u.to_string()),
        policy_uri: client.policy_uri.as_ref().map(|u| u.to_string()),
        logo_uri: client.logo_uri.as_ref().map(|u| u.to_string()),
    }))
}

fn map_client_lookup_error(error: OAuth2ClientLookupError) -> RouteError {
    match error {
        OAuth2ClientLookupError::NotFound => RouteError::NotFound,
        OAuth2ClientLookupError::Repository(error) => RouteError::from(error),
    }
}
