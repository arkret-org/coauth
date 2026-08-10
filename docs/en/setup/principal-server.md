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
- `embedded_webvh_registration_bearer`: deployment credential used by Coauth
  to query or idempotently register its service identity with this Provider.
  The Principal Server DID/audience is always resolved from `/_arkret/describe`
  and cannot be configured manually.

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

`service_id` is the local authorization pin. Any operation that authenticates
this Principal Server requires it and fails closed when it is absent.
`/_arkret/describe` is capability and metadata only; a remote Describe response
cannot establish or replace the configured identity.

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
