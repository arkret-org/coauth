# OAuth scopes

`coauth` treats coauth and Contrix scopes as the supported scope surface.

## `openid`

Requests an OpenID Connect `id_token` and allows access to the userinfo
endpoint. This is the baseline scope for interactive OIDC clients such as
`yougen`.

## `email`

Requests the user's verified email address when the deployment has that data.
The scope is typically paired with `openid`.

## `urn:coauth:admin`

Canonical coauth admin scope. This grants access to the coauth admin API and is
the preferred scope for stable admin tooling.

## `urn:contrix:admin:*`

Contrix admin capability family. `coauth` accepts the wildcard family and
`urn:contrix:admin:<capability>` prefixes as administrative access.

Use this family for Contrix-native admin integrations such as `sodmin` or
internal automation that wants a Contrix namespace instead of the coauth one.

## `urn:contrix:client:*`

Contrix client capability family for first-party or trusted Contrix clients.

## `urn:contrix:client:device:[device id]`

Contrix device-binding scope. It associates the OAuth session with the client
device identifier used by downstream Principal Servers.

## `urn:contrix:principal-server:*`

Principal Server capability family. This namespace is intended for trusted
Principal Server integrations that need scoped access beyond a generic OIDC
login.

## `urn:contrix:principal-server:session.bind`

Requests or describes the ability to mint a short-lived Contrix session grant
for the authenticated browser session. This is the scope `coauth` uses when it
issues a session grant for a trusted Principal Server.

## Contrix Claims

When applicable, ID tokens, userinfo responses, and introspection responses can
expose these Contrix claims:

- `org.contrix.principal_did`
- `org.contrix.device_id`
- `org.contrix.session_id`

`device_id` is only present when the session is bound to a device identifier.
