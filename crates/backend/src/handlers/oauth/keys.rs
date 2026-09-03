use coauth_jose::jwk::PublicJsonWebKeySet;
use coauth_keystore::Keystore;
use salvo::prelude::*;

#[handler]
#[tracing::instrument(name = "handlers.oauth.keys.get", skip_all)]
pub async fn get(depot: &Depot) -> Json<PublicJsonWebKeySet> {
    get_inner(depot)
}

fn get_inner(depot: &Depot) -> Json<PublicJsonWebKeySet> {
    let key_store = depot
        .get::<Keystore>("keystore")
        .expect("Keystore not found in depot");
    let jwks = key_store.public_jwks();
    Json(jwks)
}

#[cfg(test)]
mod tests {
    use coauth_keystore::{JsonWebKey, JsonWebKeySet, PrivateKey};
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    fn test_depot() -> Depot {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let es512 = JsonWebKey::new(PrivateKey::generate_ec_p521(&mut rng)).with_kid("test-es512");
        let ed25519 =
            JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng)).with_kid("test-ed25519");
        let keystore = Keystore::new(JsonWebKeySet::new(vec![es512, ed25519]));

        let mut depot = Depot::new();
        depot.insert("keystore", keystore);
        depot
    }

    /// The Station reads this deployment's Account Authority signing key out of
    /// the published keyset, selecting it by `kid`, and authorizes it in its own
    /// DID document as `#account-authority`. That makes three things a
    /// cross-deployment contract rather than an internal detail: the key is
    /// published at all, it carries `ACCOUNT_AUTHORITY_KEY_ID` verbatim, and it
    /// is an Ed25519 OKP key whose `x` is the raw public key. Dropping any of
    /// them leaves a Station unable to mint an identity that can ever verify
    /// this Authority.
    #[tokio::test]
    async fn jwks_publishes_the_account_authority_key_under_its_stable_kid() {
        crate::handlers::test_utils::setup();

        let mut rng = ChaChaRng::seed_from_u64(7);
        let authority = JsonWebKey::new(PrivateKey::generate_ed25519(&mut rng))
            .with_kid(coauth_keystore::ACCOUNT_AUTHORITY_KEY_ID);
        let keystore = Keystore::new(JsonWebKeySet::new(vec![authority]));
        let mut depot = Depot::new();
        depot.insert("keystore", keystore);

        let Json(jwks) = get_inner(&depot);
        let body = serde_json::to_value(jwks).unwrap();
        let key = body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["kid"].as_str() == Some(coauth_keystore::ACCOUNT_AUTHORITY_KEY_ID))
            .expect("the Account Authority key is published under its stable kid");

        assert_eq!(key["kty"].as_str(), Some("OKP"));
        assert_eq!(key["crv"].as_str(), Some("Ed25519"));
        assert!(
            key["d"].is_null(),
            "the private half must never be published"
        );

        use base64ct::{Base64UrlUnpadded, Encoding as _};
        let raw = Base64UrlUnpadded::decode_vec(key["x"].as_str().expect("x is a string"))
            .expect("x is base64url");
        assert_eq!(raw.len(), 32, "x is the raw Ed25519 public key");
    }

    #[tokio::test]
    async fn jwks_exposes_p521_and_ed25519_public_keys() {
        crate::handlers::test_utils::setup();

        let Json(jwks) = get_inner(&test_depot());
        let body = serde_json::to_value(jwks).unwrap();
        let keys = body["keys"].as_array().unwrap();

        assert!(keys.iter().any(|key| {
            key["kty"].as_str() == Some("EC") && key["crv"].as_str() == Some("P-521")
        }));
        assert!(keys.iter().any(|key| {
            key["kty"].as_str() == Some("OKP") && key["crv"].as_str() == Some("Ed25519")
        }));
    }
}
