# OAuth scopes

`coauth` treats coauth and Arkret scopes as the supported scope surface.

## `openid`

Requests an OpenID Connect `id_token` and allows access to the userinfo
endpoint. This is the baseline scope for interactive OIDC clients such as
`inkson`.

## `email`

Requests the user's verified email address when the deployment has that data.
The scope is typically paired with `openid`.

## `urn:coauth:admin`

Canonical coauth admin scope. This grants access to the coauth admin API and is
the preferred scope for stable admin tooling.

## `urn:arkret:admin:*`

Arkret admin capability family. `coauth` accepts the wildcard family and
`urn:arkret:admin:<capability>` prefixes as administrative access.

Use this family for Arkret-native admin integrations such as `sodmin` or
internal automation that wants a Arkret namespace instead of the coauth one.

## `urn:arkret:client:*`

Arkret client capability family for first-party or trusted Arkret clients.

## `urn:arkret:client:device:[device id]`

Arkret device-binding scope. It associates the OAuth session with the client
device identifier used by downstream Principal Servers.

## `urn:arkret:principal-server:*`

Principal Server capability family. This namespace is intended for trusted
Principal Server integrations that need scoped access beyond a generic OIDC
login.

## `urn:arkret:principal-server:session.bind`

Requests or describes the ability to mint a short-lived Arkret session grant
for the authenticated browser session. This is the scope `coauth` uses when it
issues a session grant for a trusted Principal Server.

## Arkret Claims

When applicable, ID tokens, userinfo responses, and introspection responses can
expose these Arkret claims:

- `org.arkret.principal_did`
- `org.arkret.device_id`
- `org.arkret.session_id`

`device_id` is only present when the session is bound to a device identifier.
