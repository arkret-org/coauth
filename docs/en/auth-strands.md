# Authentication Strands

ASCII sequence diagrams for the four primary `coauth` authentication
strands: OpenID Connect (authorization code), OAuth 2.0 device
authorization grant, WebAuthn / passkey, and account recovery.

These diagrams describe the wire-level happy-path. Failure branches
(MFA challenge, account lock, replay, expired token) take detours that
are documented in the corresponding handler module.

## OIDC authorization code (with PKCE)

```text
Client (SPA)            User-Agent              coauth                  Upstream IdP
    |                       |                       |                       |
    | 1. authorize_request  |                       |                       |
    |---------------------->|                       |                       |
    |  (client_id, scope,   |                       |                       |
    |   code_challenge,     |                       |                       |
    |   state, nonce)       |                       |                       |
    |                       | 2. /authorize         |                       |
    |                       |---------------------->|                       |
    |                       |                       | 3. login UI / cookie  |
    |                       |<----------------------|                       |
    |                       | 4. (optional) upstream SSO redirect           |
    |                       |---------------------------------------------->|
    |                       |<----------------------------------------------|
    |                       | 5. consent / capability gate                  |
    |                       |---------------------->|                       |
    |                       |  6. 302 + ?code&state |                       |
    |                       |<----------------------|                       |
    | 7. POST /token        |                       |                       |
    |  (code, code_verifier,|                       |                       |
    |   client_id)          |                       |                       |
    |--------------------------------------------->|                       |
    | 8. access + id + rt    (sub bound to DID)    |                       |
    |<---------------------------------------------|                       |
```

## OAuth 2.0 device authorization grant

```text
Device                       coauth                       User+Browser
   |                            |                              |
   | 1. POST /device_authorize  |                              |
   |--------------------------->|                              |
   | 2. device_code, user_code, |                              |
   |    verification_uri,       |                              |
   |    expires_in, interval    |                              |
   |<---------------------------|                              |
   | 3. show user_code +        |                              |
   |    verification_uri        |                              |
   |    to operator             |                              |
   |                            | 4. GET verification_uri      |
   |                            |<-----------------------------|
   |                            | 5. login + scope consent     |
   |                            |----------------------------->|
   |                            | 6. user_code accepted        |
   |                            |<-----------------------------|
   | 7. POST /token (polling)   |                              |
   |    grant=device_code       |                              |
   |--------------------------->|                              |
   |    (authorization_pending  |                              |
   |     until step 6)          |                              |
   | 8. access + refresh tokens |                              |
   |<---------------------------|                              |
```

## Passkey / WebAuthn assertion

```text
Browser                                 coauth-frontend         coauth-backend
   |                                          |                       |
   | 1. user clicks "Sign in with passkey"    |                       |
   |----------------------------------------->|                       |
   |                                          | 2. POST /_coauth/     |
   |                                          | account/auth/passkey/ |
   |                                          | auth/start + handle   |
   |                                          |---------------------->|
   |                                          |  3. challenge,        |
   |                                          |     rp_id,            |
   |                                          |     allow_credentials |
   |                                          |<----------------------|
   | 4. navigator.credentials.get(opts)       |                       |
   |<-----------------------------------------|                       |
   | 5. authenticator signs challenge         |                       |
   |    with stored private key               |                       |
   |----------------------------------------->|                       |
   |                                          | 6. POST /_coauth/     |
   |                                          | account/auth/passkey/ |
   |                                          | auth/finish           |
   |                                          | {ceremony_id,         |
   |                                          |  assertion}           |
   |                                          |---------------------->|
   |                                          |    verify origin,     |
   |                                          |    rp_id, signature   |
   |                                          |    counter, UV flag   |
   |                                          | 7. session cookie     |
   |                                          |<----------------------|
   | 8. authenticated session                 |                       |
   |<-----------------------------------------|                       |
```

The start response carries an opaque ceremony id. Its serialised
`webauthn-rs` state is stored in PostgreSQL with a ten-minute expiry and a
separate encrypted browser-cookie binding. Finish atomically deletes that row,
so a second finish, a different browser, an expired ceremony, or a
registration/authentication purpose swap fails closed. The account at finish
comes from the stored ceremony, not from request input.

A verified assertion must include user verification (UV). It creates the same
browser-session cookie used by password and upstream OIDC login, records the
passkey authentication method, and then resumes the existing authorization
continuation in the frontend. It does not mint an unbound bearer credential and
does not replace Arkret principal, device, DPoP, or agent proofs.

## Account recovery (passwordless reset)

```text
User              coauth                Email Service       Device Quorum
  |                  |                       |                  |
  | 1. POST /recovery/start                 |                  |
  |---------------->|                       |                  |
  |    {handle}     |                       |                  |
  |                  | 2. create reset      |                  |
  |                  |    token bound to    |                  |
  |                  |    device fingerprint|                  |
  |                  | 3. enqueue email     |                  |
  |                  |--------------------->|                  |
  |                  |                       | 4. deliver link |
  | 5. click link    |                       |<-----------------|
  |---------------->|                       |                  |
  |    {reset_token}|                       |                  |
  |                  | 6. validate token:   |                  |
  |                  |    - not expired     |                  |
  |                  |    - device match    |                  |
  |                  |    - not consumed    |                  |
  |                  | 7. (high-trust) ask  |                  |
  |                  |    device quorum     |                  |
  |                  |--------------------->|                  |
  |                  |  8. quorum approval  |                  |
  |                  |<---------------------|                  |
  | 9. set new credential (passkey / pwd)   |                  |
  |---------------->|                       |                  |
  |                  | 10. invalidate all   |                  |
  |                  |     refresh tokens   |                  |
  |                  |     for this account |                  |
  |                  | 11. audit log signed |                  |
  |                  |     recovery event   |                  |
  | 12. 200 OK +    |                       |                  |
  |     new session |                       |                  |
  |<----------------|                       |                  |
```

See [`docs/en/topics/password-reset.md`](./topics/password-reset.md)
for the security model behind the recovery strand.
