static HS256_JWT: &str = include_str!("./jwts/hs256.jwt");
static HS384_JWT: &str = include_str!("./jwts/hs384.jwt");
static HS512_JWT: &str = include_str!("./jwts/hs512.jwt");
static RS256_JWT: &str = include_str!("./jwts/rs256.jwt");
static RS384_JWT: &str = include_str!("./jwts/rs384.jwt");
static RS512_JWT: &str = include_str!("./jwts/rs512.jwt");
static PS256_JWT: &str = include_str!("./jwts/ps256.jwt");
static PS384_JWT: &str = include_str!("./jwts/ps384.jwt");
static PS512_JWT: &str = include_str!("./jwts/ps512.jwt");
static ES256_JWT: &str = include_str!("./jwts/es256.jwt");
static ES384_JWT: &str = include_str!("./jwts/es384.jwt");
static ES512_JWT: &str = include_str!("./jwts/es512.jwt");
static ES256K_JWT: &str = include_str!("./jwts/es256k.jwt");
static EDDSA_ED25519_JWT: &str = include_str!("./jwts/eddsa-ed25519.jwt");
static EDDSA_ED448_JWT: &str = include_str!("./jwts/eddsa-ed448.jwt");
static OCT_KEY: &[u8] = include_bytes!("./keys/oct.bin");

fn public_jwks() -> coauth_jose::jwk::PublicJsonWebKeySet {
    serde_json::from_str(include_str!("./keys/jwks.pub.json")).unwrap()
}

fn private_jwks() -> coauth_jose::jwk::PrivateJsonWebKeySet {
    serde_json::from_str(include_str!("./keys/jwks.priv.json")).unwrap()
}

fn oct_key() -> Vec<u8> {
    let mut key = OCT_KEY.to_vec();
    if key.ends_with(b"\r\n") {
        key.remove(key.len() - 2);
    }
    key
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Payload {
    hello: String,
}

macro_rules! conditional {
    { true => $($tt:tt)* } => {
        $($tt)*
    };
    { false => $($tt:tt)* } => {};
}

macro_rules! asymmetric_jwt_test {
    ($test_name:ident, $alg:ident, $jwt:ident) => {
        asymmetric_jwt_test!($test_name, $alg, $jwt, supported = true);
    };
    ($test_name:ident, $alg:ident, $jwt:ident, supported = $supported:ident) => {
        mod $test_name {
            use std::ops::Deref;

            use coauth_iana::jose::JsonWebSignatureAlg;
            use coauth_jose::{constraints::ConstraintSet, jwt::Jwt};

            use super::*;

            #[test]
            fn validate_jwt() {
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
                assert_eq!(jwt.payload().hello, "world");
                assert_eq!(*jwt.header().alg(), JsonWebSignatureAlg::$alg);
            }

            #[test]
            fn find_public_key() {
                let jwks = public_jwks();
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                let constraints = ConstraintSet::from(jwt.header());
                let candidates = constraints.filter(jwks.deref());
                assert_eq!(candidates.len(), 1);
            }

            #[test]
            fn find_private_key() {
                let jwks = private_jwks();
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                let constraints = ConstraintSet::from(jwt.header());
                let candidates = constraints.filter(jwks.deref());
                assert_eq!(candidates.len(), 1);
            }

            conditional! { $supported =>
                use coauth_jose::jwt::JsonWebSignatureHeader;
                use rand_chacha::ChaCha8Rng;
                use rand_chacha::rand_core::SeedableRng;

                #[test]
                fn verify_jwt() {
                    let jwks = public_jwks();
                    let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                    let key = jwks.find_key(&jwt.header().into()).unwrap();

                    let key = coauth_jose::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(
                        key.params(),
                        &JsonWebSignatureAlg::$alg,
                    )
                    .unwrap();

                    jwt.verify(&key).unwrap();
                }

                #[test]
                fn sign_jwt() {
                    let mut rng = ChaCha8Rng::seed_from_u64(42);
                    let alg = JsonWebSignatureAlg::$alg;
                    let payload = Payload {
                        hello: "world".to_owned(),
                    };
                    let header = JsonWebSignatureHeader::new(alg.clone());
                    let template: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                    let jwks = private_jwks();
                    let key = jwks.find_key(&template.header().into()).unwrap();

                    let key = coauth_jose::jwa::AsymmetricSigningKey::from_jwk_and_alg(key.params(), &alg)
                        .unwrap();

                    let jwt: Jwt<'_, Payload> = Jwt::sign_with_rng(&mut rng, header, payload, &key).unwrap();
                    insta::assert_snapshot!(jwt.as_str());
                }

                #[test]
                fn sign_and_verify_jwt() {
                    let alg = JsonWebSignatureAlg::$alg;
                    let payload = Payload {
                        hello: "world".to_owned(),
                    };
                    let header = JsonWebSignatureHeader::new(alg.clone());
                    let template: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();

                    let jwks = private_jwks();
                    let key = jwks.find_key(&template.header().into()).unwrap();

                    let key = coauth_jose::jwa::AsymmetricSigningKey::from_jwk_and_alg(key.params(), &alg)
                        .unwrap();

                    let jwt: Jwt<'_, Payload> = Jwt::sign(header, payload, &key).unwrap();
                    let jwt: Jwt<'_, Payload> = Jwt::try_from(jwt.as_str()).unwrap();

                    let jwks = public_jwks();
                    let key = jwks.find_key(&template.header().into()).unwrap();

                    let key =
                        coauth_jose::jwa::AsymmetricVerifyingKey::from_jwk_and_alg(key.params(), &alg)
                            .unwrap();

                    jwt.verify(&key).unwrap();
                }
            }
        }
    };
}

macro_rules! symmetric_jwt_test {
    ($test_name:ident, $alg:ident, $jwt:ident) => {
        mod $test_name {
            use coauth_iana::jose::JsonWebSignatureAlg;
            use coauth_jose::jwt::{JsonWebSignatureHeader, Jwt};

            use super::*;

            #[test]
            fn validate_jwt() {
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
                assert_eq!(jwt.payload().hello, "world");
                assert_eq!(*jwt.header().alg(), JsonWebSignatureAlg::$alg);
            }

            #[test]
            fn verify_jwt() {
                let jwt: Jwt<'_, Payload> = Jwt::try_from($jwt).unwrap();
                let key = coauth_jose::jwa::SymmetricKey::new_for_alg(
                    oct_key(),
                    &JsonWebSignatureAlg::$alg,
                )
                .unwrap();
                jwt.verify(&key).unwrap();
            }

            #[test]
            fn sign_and_verify_jwt() {
                let alg = JsonWebSignatureAlg::$alg;
                let payload = Payload {
                    hello: "world".to_owned(),
                };
                let header = JsonWebSignatureHeader::new(alg.clone());

                let key = coauth_jose::jwa::SymmetricKey::new_for_alg(oct_key(), &alg).unwrap();

                let jwt: Jwt<'_, Payload> = Jwt::sign(header, payload, &key).unwrap();
                let jwt: Jwt<'_, Payload> = Jwt::try_from(jwt.as_str()).unwrap();

                jwt.verify(&key).unwrap();
            }
        }
    };
}

symmetric_jwt_test!(hs256, Hs256, HS256_JWT);
symmetric_jwt_test!(hs384, Hs384, HS384_JWT);
symmetric_jwt_test!(hs512, Hs512, HS512_JWT);

asymmetric_jwt_test!(rs256, Rs256, RS256_JWT);
asymmetric_jwt_test!(rs384, Rs384, RS384_JWT);
asymmetric_jwt_test!(rs512, Rs512, RS512_JWT);
asymmetric_jwt_test!(ps256, Ps256, PS256_JWT);
asymmetric_jwt_test!(ps384, Ps384, PS384_JWT);
asymmetric_jwt_test!(ps512, Ps512, PS512_JWT);
asymmetric_jwt_test!(es256, Es256, ES256_JWT);
asymmetric_jwt_test!(es384, Es384, ES384_JWT);
asymmetric_jwt_test!(es512, Es512, ES512_JWT);
asymmetric_jwt_test!(es256k, Es256K, ES256K_JWT);
asymmetric_jwt_test!(eddsa_ed25519, EdDsa, EDDSA_ED25519_JWT);
asymmetric_jwt_test!(eddsa_ed448, EdDsa, EDDSA_ED448_JWT, supported = false);

#[test]
fn test_private_to_public_jwks() {
    let priv_jwks = private_jwks();
    let pub_jwks = coauth_jose::jwk::PublicJsonWebKeySet::from(priv_jwks);

    assert_eq!(pub_jwks, public_jwks());
}
