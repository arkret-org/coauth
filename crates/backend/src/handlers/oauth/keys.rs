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
