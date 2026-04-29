# Legacy compatibility routes

Contrix-native deployments should use the standard OIDC and coauth API surface.
The remaining legacy routes are either browser redirects kept for old links or
explicit compatibility affordances. Do not use them for new integrations.

## Still supported

These account links remain available as redirects for existing bookmarks and
older user-facing flows:

- `/account`
- `/account/password/change`
- `/account/password/recovery`

The OAuth 2.0 and OIDC endpoints remain the supported integration surface:

- `/.well-known/openid-configuration`
- `/oauth2/auth`
- `/oauth2/token`
- `/oauth2/device`
- `/oauth2/revoke`
- `/oauth2/introspect`
- `/oauth2/userinfo`
- `/oauth2/registration`

Contrix-native service integration should use `/api/v1/server/describe`,
`/api/v1/identity/*`, `/api/v1/directory/*`, and `/api/v1/session-grants`.

## Removed from the current production path

The current `compat` HTTP resource is a no-op in the default router, so these
Matrix / Palpo compatibility endpoints are not served by the production path:

- `/_matrix/client/*/login`
- `/_matrix/client/*/logout`
- `/_matrix/client/*/refresh`
- `/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`
- `/_palpo/client/*`
- `/_palpo/mas/*`

Use `/.well-known/openid-configuration` for discovery and `/oauth2/device` for
CLI/admin device authorization. Matrix and Palpo scopes are legacy adapter
inputs only; new Contrix clients should request `urn:coauth:admin`,
`urn:contrix:client:*`, `urn:contrix:admin:*`, or
`urn:contrix:principal-server:*` as appropriate.
