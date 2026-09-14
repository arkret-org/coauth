# Station configuration

coauth runs as the deployment-private account-authentication component behind
the owning Station's Account Authority surface. Downstream Stations such as
Soland consume OAuth/OIDC tokens and Arkret session grants; they do not discover
coauth as a separate Arkret service role.

## Configure Soland as a Station

Declare each trusted Station in the `arkret.stations`
section:

```yaml
arkret:
  stations:
    - name: soland
      endpoint: https://soland.example.com/
      trust_domain: ak:trust_domain:soland.example.com
      internal_authority_shared_secret_file: /run/secrets/soland_internal_authority_shared_secret
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}
```

- `name`: operator-facing identifier for the Station.
- `endpoint`: base URL advertised through Arkret/OIDC discovery.
- `trust_domain` and `internal_authority_shared_secret{_file}`: explicit
  deployment boundaries for the fixed internal channel. A file is read only
  once during startup.
- `embedded_webvh_registration_bearer`: deployment credential used by coauth
  for private Station-to-component calls. It is not a public service-role credential.

## Automatic verified durable binding

First startup requires neither advance knowledge of the Station service ID nor
an administrator initialization command. Coauth performs full online
verification from the configured exact endpoint (WebVH history,
service-identity binding, authenticated resolution, role and endpoint
bindings), then atomically persists the pin, anti-rollback floor and audit
entry. A bare `/_arkret/describe` response or shared secret alone cannot
establish identity; concurrent replicas converge only on an identical verified
tuple.

The Coauth HTTP server does not wait for this verification before binding. It
publishes OIDC discovery, its public JWKS and health endpoints first so a fresh
Station can obtain the Account Authority key. Business routes remain
fail-closed with `503`, and `/readyz` remains unavailable, until background
verification succeeds. Task workers still require the synchronous preflight
before processing jobs.

After a legitimate identity genesis (new SCID), replace the pin explicitly:

```console
$ coauth station trust replace --name soland \
    --expect-old ak:did_core:webvh:<old-scid> \
    --accept-new ak:did_core:webvh:<new-scid>
```

Replacement revokes session grants bound to the old audience in the same
transaction. `coauth station trust revoke --name soland` removes the
pin entirely; the server then refuses to serve until the next full automatic
verification establishes a binding again.

## Deployment-private Account Authority signer

Coauth is an internal Account Authority process of the owning Station. Its
signing credential is deployment-private: it is not an Arkret service kind, is
not entered in public service registration, and is not exposed through a
role-local Describe or peer discovery. Clients discover only the owning
Station's `auth_metadata.account_authority` URL.

The signer and any process-local identifier are implementation details. They
must not be entered into public service registration, advertised as a service
DID, or used as a peer/federation identity. Restore and rotate this key through
the Station deployment's private key-management procedure.

## Server-to-server trust boundary (deployment-internal)

As the Station's private account-authentication component, coauth performs two
server-to-server reads/writes
against the Station that have **no principal session** and therefore
cannot use the principal-authenticated `/_arkret/self/*` protocol surface.
These are deployment-internal S2S contracts on the Station's own
negative-space root, per `service-http-binding.md` §2.1.4(b) — they are **not**
v1 protocol operations:

| coauth call | Station endpoint | Operation id | When |
| --- | --- | --- | --- |
| Device signing-key directory lookup | `POST /_soland/gate/account/device-signing-keys/query` | `org.arkret.soland.gate.account.device_signing_keys.query` | Verifying a device holder proof during session-grant refresh / soft-logout restore |
| Collaboration capability fanout | `POST /_soland/root/authz/capability-fanout` | `org.arkret.soland.root.authz.capability_fanout.submit` | Materialising a coauth-issued `ak.capability.grant` / `ak.capability.revoke` |

Both edges are authenticated with the shared bearer configured on the matching
`stations` entry:

Runtime authorization uses only the fully verified durable Station binding. An
endpoint change is updated with CAS only when the same service core proves
continuous, non-rollback WebVH history; a new core/genesis requires the
explicit replace command above. The shared secret authenticates only the
configuration slot corresponding to that binding and cannot establish or
replace the pin.

```yaml
arkret:
  stations:
    - name: soland
      # ...
      embedded_webvh_registration_bearer: "<shared S2S secret>"
```

Operationally this means the bearer is a **trust-boundary secret**: it grants
coauth (the authentication TCB) directory-read and capability-fanout authority
against the Station. Rotate it on the same cadence as other
inter-service credentials, and ensure the coauth↔Station hop is
confined to the trusted deployment network. The Station treats these
endpoints as deployment-local product surface and never exposes them on its
`/_arkret/*` protocol root.

## Discovery

coauth publishes only its standard OpenID Provider discovery document at
`/.well-known/openid-configuration`. The owning Station publishes the Arkret
Describe document and its `auth_metadata.account_authority` entry; coauth does
not expose a role-local `/_arkret/describe` endpoint.
