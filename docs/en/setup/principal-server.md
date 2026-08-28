# Principal Server configuration

coauth now runs as the Arkret Auth Server. Downstream Principal Servers such as
Soland consume OAuth/OIDC tokens and Arkret session grants; coauth no longer
connects to the retired delegated-auth adapter.

## Configure Soland as a Principal Server

Declare each trusted Principal Server in the `arkret.principal_servers`
section:

```yaml
arkret:
  principal_servers:
    - name: soland
      endpoint: https://soland.example.com/
      service_id: ak:did_core:webvh:<soland-scid>
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}
```

- `name`: operator-facing identifier for the Principal Server.
- `endpoint`: base URL advertised through Arkret/OIDC discovery.
- `service_id`: optional explicit identity pin (`ak:did_core:webvh:<scid>`).
  When present it has the highest priority. When omitted, the pin comes from
  the persisted trust enrollment created by the one-time bootstrap (see
  below).
- `embedded_webvh_registration_bearer`: deployment credential used by Coauth
  to query or idempotently register its service identity with this Provider.

## One-time trust bootstrap

The Principal Server DID/audience is never trusted from a bare
`/_arkret/describe` response. Before coauth accepts tokens or session grants
for a Principal Server audience, that audience must be pinned by either the
configured `service_id` or a persisted trust enrollment. Create the
enrollment once per deployment:

```console
$ coauth principal-server trust bootstrap --name soland
```

Bootstrap performs a full online verification of the Principal Server
identity chain (WebVH history, service-identity binding, resolution record
and endpoint bindings) and persists the verified pin plus an audit entry.
It is idempotent: re-running it with an unchanged identity succeeds without
altering the pin.

After a legitimate identity genesis (new SCID), replace the pin explicitly:

```console
$ coauth principal-server trust replace --name soland \
    --expect-old ak:did_core:webvh:<old-scid> \
    --accept-new ak:did_core:webvh:<new-scid>
```

Replacement revokes session grants bound to the old audience in the same
transaction. `coauth principal-server trust revoke --name soland` removes the
pin entirely; the server then refuses to serve until a pin exists again.

## Coauth's own service identity

Coauth is a class-A service: it generates and holds the signing key of its own
service DID and only *hosts* the public `did:webvh` log on its Provider (the
Principal Server configured above). At runtime the identity comes from exactly
two places:

- the verified record in the local `service_identity` table;
- the stable mapping the Provider keeps for the registration key
  `{service_kind: auth_server, public_base}`.

Coauth's own `service_id` is never written into configuration.
`embedded_webvh_registration_bearer` is only the deployment-level transport
credential used to reach the Provider; it confers no identity. Control lives in
the Ed25519 private key with kid `coauth-service-identity-v1` in the key
backend.

### Verifying the Provider proof

Every `ServiceRegistrationOutcome` the Provider returns carries a registration
receipt. Coauth verifies its Provider proof in full before it writes any local
state:

1. obtain the Provider's current complete DID from its `/_arkret/describe` surface; when
   `principal_servers[].service_id` is pinned, the advertised `service_id` must equal that pin
   verbatim;
2. derive the `did.jsonl` URL from that DID and verify the Provider's method-native history
   completely (SCID derivation, entry hash chain, every entry proof and the rotation
   authorization), requiring the verified head to be the version describe advertises;
3. require `project(did)` to equal the receipt's `provider_service_id`, and the bare controller
   DID of the receipt's `verification_method` to equal that `did` verbatim;
4. require that method to be an `assertionMethod` of the Provider DID Document that was effective at
   the receipt's `issued_at`;
5. verify the receipt's Ed25519 detached JWS.

A transport credential, mTLS, a successful HTTPS exchange or a structurally
self-consistent proof can **never** stand in for this step. Any failure is
`service_registration_restore_failed`: the runtime reports `503 faulted` and
writes nothing locally, and the operator should check whether the Provider's
describe surface and its hosted `did.jsonl` belong to the same identity and
match the pin. A Provider whose describe surface or `did.jsonl` is temporarily
unreachable is not mistaken for a failure: with no local record the runtime
waits in `WaitingProvider`, with an already verified record it serves as
`DegradedStored`, and both keep retrying.

### Automatic recovery after local state loss

After a database swap, a wipe, or a restore onto an empty database, coauth
still holds that Ed25519 key but has lost the `service_identity` record.
Startup then back-fills the original DID automatically, with no operator step:

1. look the registration key up on the Provider and find the existing registration;
2. verify the returned DID Document and registration receipt against the local signing and control
   key binding;
3. fetch the method-native history from the `did.jsonl` URL derived from the DID itself and verify
   the whole chain (SCID derivation and entry proofs);
4. require the canonical digest of the first inception entry to equal the `log_head_digest` the
   Provider signed into the receipt;
5. require that entry's `updateKeys[0]` to equal the control key this process derives from its own
   key backend.

Step 5 is the control proof: only a process holding the local service-identity
key satisfies it, so a registration rooted in a *different* control root is
never adopted and instead fails closed as `service_identity_key_mismatch`.

The Provider-side registration must **not** be cleared by hand. Deleting it
makes coauth mint a new DID and orphans every credential and derived identity
issued under the old one.

While the Provider or its hosted `did.jsonl` is unreachable the runtime stays in
`WaitingProvider` and keeps retrying; discovery answers
`503 service_identity_unavailable` with `Retry-After`, and no restart is needed
once the Provider returns.

Losing the key backend *and* the database is unrecoverable by design: the
Provider is a hosting party, not a controller, and never holds coauth's private
key.

## Server-to-server trust boundary (deployment-internal)

In its Auth-Server role coauth performs two server-to-server reads/writes
against the Principal Server that have **no principal session** and therefore
cannot use the principal-authenticated `/_arkret/self/*` protocol surface.
These are deployment-internal S2S contracts on the Principal Server's own
negative-space root, per `service-http-binding.md` §2.1.4(b) — they are **not**
v1 protocol operations:

| coauth call | Principal Server endpoint | Operation id | When |
| --- | --- | --- | --- |
| Device signing-key directory lookup | `POST /_soland/gate/account/device-signing-keys/query` | `org.arkret.soland.gate.account.device_signing_keys.query` | Verifying a device holder proof during session-grant refresh / soft-logout restore |
| Collaboration capability fanout | `POST /_soland/root/authz/capability-fanout` | `org.arkret.soland.root.authz.capability_fanout.submit` | Materialising a coauth-issued `ak.capability.grant` / `ak.capability.revoke` |

Both edges are authenticated with the shared bearer configured on the matching
`principal_servers` entry:

`service_id` is the explicit configuration pin and takes priority when
present. When it is absent, the persisted trust enrollment created by
`coauth principal-server trust bootstrap` is the authorization pin. Any
operation that authenticates this Principal Server requires one of the two
and fails closed when neither exists. `/_arkret/describe` is capability and
metadata only; a remote Describe response cannot establish or replace a pin.

```yaml
arkret:
  principal_servers:
    - name: soland
      # ...
      embedded_webvh_registration_bearer: "<shared S2S secret>"
```

Operationally this means the bearer is a **trust-boundary secret**: it grants
coauth (the authentication TCB) directory-read and capability-fanout authority
against the Principal Server. Rotate it on the same cadence as other
inter-service credentials, and ensure the coauth↔Principal-Server hop is
confined to the trusted deployment network. The Principal Server treats these
endpoints as deployment-local product surface and never exposes them on its
`/_arkret/*` protocol root.

## Discovery

coauth publishes Principal Server metadata through the standard OpenID
discovery document and the Arkret server description endpoint:

- `/.well-known/openid-configuration`
- `/_arkret/describe`

Run `coauth doctor` after the server is up to verify these discovery surfaces.
