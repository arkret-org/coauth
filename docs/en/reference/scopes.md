# OAuth 2.0 scopes

`coauth` now treats Contrix scopes as the primary product surface. Legacy
Matrix / Palpo scopes still exist for compatibility adapters, but they are no
longer the recommended integration path.

## Primary coauth / Contrix scopes

### `openid`

Requests an OpenID Connect `id_token` and allows access to the userinfo
endpoint. This remains the baseline scope for interactive OIDC clients such as
`chask`.

### `email`

Requests the user's verified email address when the deployment has that data.
The scope is typically paired with `openid`.

### `urn:coauth:admin`

Canonical coauth admin scope. This grants access to the coauth admin API and is
the preferred scope for stable admin tooling.

### `urn:contrix:admin:*`

Contrix admin capability family. `coauth` currently accepts the wildcard family
and `urn:contrix:admin:<capability>` prefixes as administrative access.

Use this family for Contrix-native admin integrations such as `sodmin` or
internal automation that wants a Contrix namespace instead of the coauth one.

### `urn:contrix:client:*`

Contrix client capability family. This is intended for first-party or trusted
Contrix clients such as `chask`.

Today it is advertised as a coarse-grained capability family; narrower suffixes
can be added by policy and client conventions over time.

### `urn:contrix:principal-server:*`

Principal Server capability family. This is the namespace intended for trusted
Principal Server integrations that need scoped access beyond a generic OIDC
login.

### `urn:contrix:principal-server:session.bind`

Requests or describes the ability to mint a short-lived Contrix session grant
for the authenticated browser session. This is the scope `coauth` uses when it
issues a session grant for a trusted Principal Server.

## Contrix claims exposed alongside scopes

When applicable, ID tokens, userinfo responses, and introspection responses can
expose these Contrix claims:

- `org.contrix.principal_did`
- `org.contrix.device_id`
- `org.contrix.session_id`

`device_id` is only present when the session is bound to a device identifier.

## Legacy compatibility scopes

### `urn:matrix:client:api:*` and `urn:matrix:org.matrix.msc2967.client:api:*`

Legacy Matrix client API access scopes. These belong to the compatibility
adapter path and should not be used as the primary scope contract for new
Contrix deployments.

### `urn:matrix:client:device:[device id]` and `urn:matrix:org.matrix.msc2967.client:device:[device id]`

Legacy Matrix device-binding scopes. They encode the device identifier in the
scope token itself and are still understood by compatibility code paths.

### `urn:palpo:admin:*`

Legacy Palpo admin scope family. This is only relevant when `coauth` is acting
as a delegated-auth bridge for an older Palpo / Matrix deployment.

### `urn:mas:admin`

Legacy admin scope kept for backward compatibility. Existing tokens that still
carry `urn:mas:admin` continue to work, but new integrations should migrate to
`urn:coauth:admin` or `urn:contrix:admin:*`.

## Policy notes

- OIDC discovery advertises the primary Contrix scope families and claims.
- `urn:coauth:admin` is the stable scope for the existing admin API.
- `urn:contrix:admin:*` is the Contrix-native admin namespace.
- `urn:contrix:principal-server:session.bind` is the scope used for trusted
  Principal Server session grants.
- Matrix / Palpo scopes should be treated as legacy compatibility affordances,
  not as the default scope registry for new work.
