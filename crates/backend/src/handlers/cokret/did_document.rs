use chrono::{DateTime, Utc};
use coauth_config::CokretConfig;
use coauth_data::{RepositoryAccess, UrlBuilder, User};
use coauth_jose::jwk::PublicJsonWebKey;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::*;
use crate::handlers::common::DepotExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,

    #[serde(rename = "alsoKnownAs")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,

    #[serde(rename = "verificationMethod")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,

    #[serde(rename = "assertionMethod")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidService>,

    /// R3.2 (DID-COAUTH-1) — holder-preference metadata block carrying
    /// `primary_handle` (spec identity-handles.md §3.2.1
    /// `holder_primary_handle_at_as_of`). Always emitted for the current
    /// version of a coauth-controlled document (defaulting to `null`
    /// `primary_handle` until the holder records a preference); omitted
    /// when empty so external `did:web` / `did:plc` documents that lack a
    /// metadata block still round-trip unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<DidDocumentMetadata>,
}

/// R3.2 — DID Document `metadata` block.
///
/// Per identity-handles.md §3.2.1 the only field coauth populates is
/// `primary_handle`: a *holder preference pointer* indicating which of the
/// holder's verified handle claims they'd prefer surfaced as the canonical
/// display handle. It is explicitly **NOT** a handle declaration channel —
/// a verifier MUST still construct the `claim_set_snapshot` from signed
/// `ck.schema.handle_claim.v1` evidence and MUST ignore this field if the
/// pointed-at handle is not backed by such a claim. Default is `null`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DidDocumentMetadata {
    /// Canonical `<localpart>:<domain>` handle the holder prefers as their
    /// primary display handle, or `null` when no preference is recorded.
    #[serde(default)]
    pub primary_handle: Option<String>,
}

impl DidDocumentMetadata {
    /// Build the metadata block for a coauth-controlled DID Document's
    /// *current* version.
    ///
    /// The caller supplies the already-resolved preference because current
    /// DID document handlers read it from the database while pure builders
    /// used in unit tests can still pass `None`.
    #[must_use]
    pub fn current_for_holder(primary_handle: Option<String>) -> Self {
        Self { primary_handle }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: String,

    pub controller: String,

    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PublicJsonWebKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService {
    pub id: String,

    #[serde(rename = "type")]
    pub kind: String,

    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

pub(crate) fn user_did_document(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    user: &User,
) -> DidDocument {
    user_did_document_with_primary_handle(
        url_builder,
        cokret_config,
        user,
        user_primary_handle_preference(user),
    )
}

pub(crate) fn user_did_document_with_primary_handle(
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    user: &User,
    primary_handle: Option<String>,
) -> DidDocument {
    let did = user_did_for(url_builder, cokret_config, user);

    DidDocument {
        id: did.clone(),
        // Spec 7157ee8 §3.1: canonical handle form is
        // `<localpart>:<domain>`; `acct:` is interop-only and lives on
        // `handle_claim.handle_aliases[]`, not on the DID document.
        also_known_as: vec![user_handle(url_builder, user)],
        verification_method: Vec::new(),
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        service: vec![DidService {
            id: format!("{did}#auth-server"),
            kind: "CokretAuthServer".to_owned(),
            service_endpoint: url_builder
                .absolute_url("/api/v1/server/describe")
                .to_string(),
        }],
        // DID-COAUTH-1 — a user DID is a handle holder, so always emit the
        // metadata block. `primary_handle` defaults to `null` until the
        // holder records a preference (DID-COAUTH-3 / TODO(R3.2.1)).
        metadata: Some(DidDocumentMetadata::current_for_holder(primary_handle)),
    }
}

/// DID-COAUTH-1 / DID-COAUTH-2 — resolve the holder's recorded
/// `primary_handle` preference for inclusion in the DID Document
/// `metadata` block.
///
/// Pure builder fallback for callers that have not loaded the database-backed
/// preference. HTTP DID document and local identity resolution paths pass the
/// repository value through [`user_did_document_with_primary_handle`].
#[must_use]
fn user_primary_handle_preference(_user: &User) -> Option<String> {
    None
}

pub(crate) fn did_document_as_of_query(
    req: &Request,
) -> Result<Option<DateTime<Utc>>, CokretRouteError> {
    let Some(raw) = req
        .query::<String>("as_of")
        .or_else(|| req.query::<String>("asOf"))
    else {
        return Ok(None);
    };

    DateTime::parse_from_rfc3339(&raw)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|_| CokretRouteError::BadRequest("invalid as_of query parameter".to_owned()))
}

pub(crate) async fn local_user_did_document_if_owned(
    repo: &mut coauth_data::BoxRepository,
    url_builder: &UrlBuilder,
    cokret_config: &CokretConfig,
    did: &str,
    as_of: Option<DateTime<Utc>>,
) -> Result<Option<DidDocument>, CokretRouteError> {
    let Some(user_id) = parse_local_user_did_for(url_builder, cokret_config, did) else {
        return Ok(None);
    };

    let Some(user) = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    else {
        return Err(CokretRouteError::NotFound);
    };

    let primary_handle = match as_of {
        Some(as_of) => {
            repo.user_primary_handle_preference()
                .at(user.id, as_of)
                .await
        }
        None => repo.user_primary_handle_preference().current(user.id).await,
    }
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    .and_then(|preference| preference.handle);

    Ok(Some(user_did_document_with_primary_handle(
        url_builder,
        cokret_config,
        &user,
        primary_handle,
    )))
}

#[handler]
pub async fn service_did_json(depot: &Depot) -> Result<Json<DidDocument>, CokretRouteError> {
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let key_store = depot.key_store()?;
    let did_resolver = depot.did_resolver_service()?;

    did_resolver
        .service_did_document(&url_builder, &cokret_config, &key_store)
        .map(Json)
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))
}

#[handler]
pub async fn user_did_json(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DidDocument>, CokretRouteError> {
    let raw_id = req
        .param::<String>("id")
        .ok_or_else(|| CokretRouteError::BadRequest("missing user id".into()))?;
    let user_id = Ulid::from_string(&raw_id)
        .map_err(|_| CokretRouteError::BadRequest("invalid user id".into()))?;
    let url_builder = depot.url_builder()?;
    let cokret_config = depot.cokret_config()?;
    let mut repo = depot.repo().await?;
    let as_of = did_document_as_of_query(req)?;
    let Some(user) = repo
        .user()
        .lookup(user_id)
        .await
        .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    else {
        return Err(CokretRouteError::NotFound);
    };

    let primary_handle = match as_of {
        Some(as_of) => {
            repo.user_primary_handle_preference()
                .at(user.id, as_of)
                .await
        }
        None => repo.user_primary_handle_preference().current(user.id).await,
    }
    .map_err(|error| CokretRouteError::Internal(Box::new(error)))?
    .and_then(|preference| preference.handle);

    Ok(Json(user_did_document_with_primary_handle(
        &url_builder,
        &cokret_config,
        &user,
        primary_handle,
    )))
}
