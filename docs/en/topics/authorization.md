# Authorization and sessions

`coauth` authenticates users and clients, then issues OAuth/OIDC tokens or
Cokret session grants that downstream services can validate.

## Session Types

### Browser sessions

When a user signs in through the web UI, `coauth` creates a browser session and
stores it in an encrypted cookie.

### OAuth sessions

OAuth sessions are created after a client completes an authorization flow. They
bind together:

- the authorized user, when the grant is user-backed
- the requesting client
- the granted scopes
- access and refresh tokens

### Cokret session grants

Principal Servers should validate `ck.session.grant` records for downstream
account and device access. The grant payload includes issuer service DID,
subject principal DID, service account ID, optional device ID, audience,
scopes, expiry, revocation reference, and a proof block.

Session-grant JWTs default to a 300-second lifetime and can be tuned with
`cokret.session_grant_ttl` in the configuration file.

`POST /_coauth/gate/account/session-grants/introspect` accepts either a grant ID or signed
grant JWT plus an optional audience. It returns `active`, a standard status
(`active`, `revoked`, `expired`, `locked`, `suspended`,
`audience_mismatch`, or `not_found`), and non-secret grant metadata. It never
returns the stored JWT, refresh token, session private key, handle, or claim
payloads.

## Grant Types

### Authorization code

Use this for interactive clients where the user can sign in through a browser.
The client redirects the user to `coauth`, receives an authorization code, and
exchanges that code for tokens.

### Device authorization

Use this for devices or CLI tools that cannot comfortably host a browser
redirect. The device displays a code, the user confirms it on another device,
and the client polls until tokens are issued.

### Client credentials

Use this for service-to-service automation. The client authenticates as itself
and receives a token without a user-backed browser session.

## Access Tokens

Access tokens are opaque to clients. `coauth` stores the token metadata server
side:

- subject
- client
- granted scopes
- expiry
- revocation state

Tokens can be revoked by the user, an administrator, or an authorized client
through the revocation endpoint.

## Personal Sessions

Personal access tokens can be issued by administrators for automation or
delegated user operations. They carry predefined scopes and an expiry time, and
can be regenerated or revoked through the admin API.

[Admin API]: ./admin-api.md
