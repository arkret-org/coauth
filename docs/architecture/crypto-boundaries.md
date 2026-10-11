# Coauth cryptographic consumer boundaries

Arkret wire models and verifiers belong to the SDK. Equal primitives do not imply equal token policies. This inventory records the current consumers and the smallest safe shared boundary; it does not create another protocol profile.

| Consumer | Input and algorithm | Transcript and header | Key selection | Claims, freshness and replay | Owner |
| --- | --- | --- | --- | --- | --- |
| Upstream OIDC ID token | Compact JWT; configured provider signing algorithm from the JOSE supported set | Original encoded header + `.` + original encoded payload; registered JOSE header fields, non-empty `crit` refused | Coauth public JWKS; constrained candidate search | Connector checks configured `iss`, `aud`, `exp`, `iat`, `sub`; exchange checks optional `at_hash`, `c_hash`, expected nonce and userinfo subject agreement | `services/upstream_oidc.rs`, `oidc_client/requests/jose.rs` |
| Signed userinfo | Compact JWT; explicit configured signed-response algorithm | Same JOSE compact transcript | Configured provider JWKS | Signature, expected algorithm, issuer and client audience; JSON/signed response mismatch refused | `services/upstream_oidc.rs` |
| OAuth client assertion | `private_key_jwt` or `client_secret_jwt`; JOSE asymmetric whitelist or HMAC family | Compact JWT; no unsupported critical extensions | Registered client JWKS or decrypted client secret | Client `iss`/`sub`, token endpoint `aud`, required `exp`/`iat`, maximum five-minute lifetime, non-empty JTI and namespaced replay store | `salvo_utils/client_authorization.rs` |
| Session-grant issuance | Typed SDK `SignedSessionGrantClaims`; reserved keyring signing key | JOSE compact JWT with durable signing `kid`; claims validate before signing | Exact key ID reserved by the durable issuance operation | Issuer/issuance nonce, holder/device binding, expiry and exact outcome persistence are domain obligations outside the signer | `handlers/arkret/session_grant/issuance.rs` |
| SDK Ed25519 JWT verification | Compact JWT, only `alg=Ed25519`, OKP Ed25519 key | Same compact signing input; closed header set; any `crit` member refused | Exactly one eligible JWKS key; ambiguity refused | Policy checks issuer/audience and exp/nbf/iat; no application replay persistence | SDK `signatures/src/jwt.rs` |
| Arkret DPoP | Compact proof with embedded Ed25519 public JWK | SDK owns closed protected header, proof claims, method/URL/access-token bindings and thumbprint | Embedded public key; grant-bound JKT checked by consumer | SDK proof age/future skew; Coauth owns repository-backed JTI admission. Handoff can consume JTI inside its transaction | SDK `signatures/src/dpop.rs`, `services/dpop.rs` |
| Arkret detached proofs | Canonical SDK signing input, Ed25519 | SDK protected header and detached JWS; Data Integrity proofs use their separately owned cryptosuite transcript | Verified DID method evidence/custody key, not arbitrary JWT candidates | Consumer retains DID history acceptance, purpose, freshness, authorization and operation replay | SDK `signatures`, `identity`; Coauth DID binding services |
| Stored client/provider secrets | 32-byte key, 12-byte nonce, ChaCha20-Poly1305 with empty AAD | Base64 of nonce followed by ciphertext and 16-byte tag | Coauth runtime encryption key | Authenticated decryption; no JWT claims or key selection. OAuth clients, upstream provider secrets and encoded Apple credentials are actual callers | `keyring/src/encrypter.rs`, `sync.rs`, client authorization/provider credential adapters |

## Shared and retained implementation

Coauth JOSE already delegates base64url encoding/decoding to `arkret-canonical`. Canonical Arkret request/proof inputs use SDK helpers. The two Ed25519 crate generations cross only through `backend/src/arkret_key_bridge.rs`; raw 32-byte keys and common deterministic signatures are tested there.

The JWT verifier surfaces remain separate. In particular, accepting empty `crit` or trying several candidates cannot be preserved by substituting the SDK verifier. SDK JWT verification also does not expose a general multi-algorithm JWT signer or replace OIDC nonce/token-hash checks, registered HMAC client credentials, or application replay persistence. These differences are frozen by differential tests, not normalized into a common permissive wrapper.

`coauth-jose/tests/jws.rs` retains fixed external token/key vectors and randomized sign/verify coverage for its supported algorithm families. RSA-PSS and ECDSA verification uses fixed vectors and cross-verification; freshly generated signatures need not be byte-identical across implementations. Deterministic Ed25519 common input additionally compares exact compact and detached signature bytes against an independently computed fixed vector.

## Independent AEAD dependency axis

The Encrypter uses `Aead` and `KeyInit`, not PKCS#8. Its dependency upgrade is independent of the JOSE `PrivateKey` enum's shared PKCS#8 return type. PKCS#8 PEM/DER protection and the SDK keystore's authenticated encrypted vault are distinct boundaries.

There is no Encrypter caller for stored access/refresh-token fields in the current source. Verification must cover actual client/provider encrypted-secret rows rather than invent encrypted token columns or a compatibility reader. Nonce/ciphertext/tag framing and deterministic ciphertext must stay unchanged; wrong keys/nonces, tampering and truncation must fail closed.
