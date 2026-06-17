use hyper::{Request, StatusCode, header::CONTENT_TYPE};
use oauth_types::scope::{OPENID, Scope};
use coauth_data::{
    UpstreamOAuthAuthorizationSession, UpstreamOAuthLink, UpstreamOAuthProviderClaimsImports,
    UpstreamOAuthProviderImportPreference, UpstreamOAuthProviderHandlePreference,
    UpstreamOAuthProviderTokenAuthMethod, UserEmailAuthentication, UserRegistration,
};
use coauth_iana::jose::JsonWebSignatureAlg;
use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};
use coauth_keystore::Keystore;
use coauth_data::{
    Repository, RepositoryError, upstream_oauth::UpstreamOAuthProviderParams,
};
use rand_chacha::ChaChaRng;
use serde_json::Value;
use ulid::Ulid;

use super::UpstreamSessionsCookie;
use crate::handlers::account::DepotExt;
#[cfg(test)]
use crate::handlers::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

mod register;
mod link_existing;

fn sign_token(
    rng: &mut ChaChaRng,
    keystore: &Keystore,
    payload: Value,
) -> Result<Jwt<'static, Value>, coauth_jose::jwt::JwtSignatureError> {
    let signer = keystore
        .signer_for_algorithm(&JsonWebSignatureAlg::Rs256)
        .unwrap();

    let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);

    Jwt::sign_with_rng(rng, header, payload, &*signer)
}

async fn add_linked_upstream_session(
    rng: &mut ChaChaRng,
    clock: &impl coauth_data::Clock,
    repo: &mut Box<dyn Repository<RepositoryError> + Send + Sync + 'static>,
    provider: &coauth_data::UpstreamOAuthProvider,
    subject: &str,
    id_token: &str,
    id_token_claims: Value,
) -> Result<(UpstreamOAuthLink, UpstreamOAuthAuthorizationSession), anyhow::Error> {
    let session = repo
        .upstream_oauth_session()
        .add(
            rng,
            clock,
            provider,
            "state".to_owned(),
            None,
            Some("nonce".to_owned()),
        )
        .await?;

    let link = repo
        .upstream_oauth_link()
        .add(rng, clock, provider, subject.to_owned(), None)
        .await?;

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(
            clock,
            session,
            &link,
            Some(id_token.to_owned()),
            Some(id_token_claims),
            None,
            None,
        )
        .await?;

    Ok((link, session))
}
