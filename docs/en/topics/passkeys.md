# Passkeys

Coauth supports username-first WebAuthn passkey login for human service
accounts. Passkeys are phishing-resistant account authenticators; they are not
Arkret DID principal keys, DPoP keys, enrolled device keys, or agent runtime
proofs.

## User flows

- On the login page, enter the account handle, continue, then select **Sign in
  with a passkey**. A successful assertion creates the normal Coauth browser
  session and can resume an in-progress OAuth/OIDC authorization.
- In **Security Center**, a recently authenticated user can add, list, rename,
  and revoke their own passkeys.
- Coauth never accepts an account id or handle at registration finish. Both
  registration calls derive the account from the current active browser
  session.
- Coauth blocks revocation of the account's last passkey. Establish another
  passkey before removing it.
- There is no admin endpoint that silently registers an administrator-controlled
  passkey on another account.

Adding, renaming, and revoking requires an authentication no more than ten
minutes old. A stale session must sign in again. The credential list exposes a
Coauth-internal id, label, creation and last-use timestamps, user-verification
state, and backup/sync hints; it does not expose public keys or full WebAuthn
credential ids.

## Deployment requirements

WebAuthn is origin-bound. Production deployments must use HTTPS and configure
the public external Coauth URL correctly. `localhost` HTTP is accepted for
local development; other insecure origins are not a supported deployment
posture.

At startup Coauth derives:

- RP ID from the public hostname;
- RP origin from the public HTTP base URL;
- RP display name as `Arkret`.

If these values are invalid or inconsistent, the WebAuthn service is not
published and `passkey_login_enabled` is false. Do not work around this by
widening origins. Fix the externally visible URL and reverse-proxy
configuration, keep a stable RP ID across replicas, and make every replica use
the same PostgreSQL database.

Pending registration and authentication state is stored in PostgreSQL for ten
minutes and atomically deleted by finish. This supports start and finish on
different replicas, parallel tabs, and process restarts while rejecting replay,
browser-cookie substitution, purpose substitution, and expiry.

The Passkey endpoints are same-origin account endpoints, not public
credentialed-CORS endpoints. Ceremony binding uses an encrypted `HttpOnly`,
`SameSite=Lax` cookie (`Secure` on HTTPS); mutations require JSON requests and
an active or recent browser session as applicable. Coauth rejects browser
requests whose `Origin` or `Sec-Fetch-Site` identifies a different origin.
Start and finish are subject to the existing per-IP and per-account login
limits, and each ceremony can be consumed only once. Keep Coauth's CSP enabled,
do not add third-party scripts to login or Security Center pages, and do not
configure a wildcard credentialed CORS policy in front of these routes.

Before enabling Passkeys in production, verify all of the following:

- the browser-facing URL uses HTTPS (only literal `localhost` development may
  use HTTP), remains stable, and exactly matches `http.public_base_url`;
- the public hostname is the intended RP ID and is not an IP literal;
- the reverse proxy preserves the configured external scheme and host, accepts
  Passkey account routes only from the same browser origin, and does not replace
  Coauth's CSP or cookie attributes with weaker values;
- every replica uses the same public URL, cookie secrets, configuration, and
  PostgreSQL database, while health probes verify each listener separately;
- a real registration and login are exercised through the production proxy
  before password/OIDC fallback is restricted.

Invalid public URL/RP configuration fails closed by disabling the advertised
Passkey capability. Origin substitution, browser-binding substitution, expiry,
purpose mismatch, and replay fail at the request or ceremony boundary.

## Threat model and controls

- Registration derives the subject from the active browser session. Account
  hints cannot attach a credential to another account, and no administrator
  endpoint can silently create one.
- Authentication finish derives the account from the durable, single-use
  ceremony. The opaque ceremony id is insufficient without the encrypted
  browser-binding cookie.
- RP ID, exact origin, challenge, signature, user presence, and user
  verification are checked by `webauthn-rs`. Coauth additionally enforces
  expiry, operation kind, account/session binding, and counter compare-and-set.
- Account status is rechecked before a normal browser session is issued. OAuth
  continuation then uses the existing server-side grant, redirect URI, PKCE,
  state/nonce, and consent pipeline; Passkey does not create a separate bearer
  grant.
- Credential ids, public keys, assertions, `clientDataJSON`, and
  `authenticatorData` are not returned by lifecycle APIs or written to audit
  metadata. Audit events use only Coauth's internal Passkey id and risk flags.
- Concurrent revocation is serialized per account in PostgreSQL, so two
  requests cannot remove both of the last two Passkeys.
- Username-first availability can still reveal that a handle has a usable
  Passkey through ceremony success versus failure. Per-IP/account rate limits
  reduce bulk probing, but deployments requiring stronger identifier privacy
  should wait for a separately reviewed discoverable-credential flow.
- XSS in Coauth's own origin can initiate browser actions even though it cannot
  read `HttpOnly` cookies. CSP, dependency review, and keeping authentication
  pages free of third-party scripts remain part of the security boundary.

## Authenticator and recovery posture

Authentication requires the authenticator's user-verification flag. Coauth
records backup eligibility/state because a synced passkey has a different risk
profile from a device-bound security key. Coauth does not currently enforce an
attestation model allow-list and does not claim AAL3.

The implementation uses the standard browser WebAuthn API and is intended for
platform authenticators (for example Windows Hello and platform passkey
stores), roaming USB/NFC security keys, and browser-mediated hybrid flows.
Compatibility must be verified against the browsers and authenticators in each
deployment; this document is not a certified device matrix.

The automated compatibility gate currently covers Chrome 150 on Windows with a
CDP CTAP2 virtual platform authenticator (resident key, UV, automatic presence).
Windows Hello, Safari/iCloud Keychain, Chrome/Google Password Manager,
USB/NFC roaming keys, and hybrid QR transport are standards-based targets but
remain unverified in this repository's automated matrix.

Password and email recovery can still be weaker than a passkey. Recovery
restores access to the Coauth service account only. It does not recover or
rotate a DID identity root and does not automatically authorize an Arkret
device. Operators should make that downgrade visible in support and incident
procedures.

Revoking a Passkey prevents new assertions with that credential; it does not
silently revoke already established browser sessions, OAuth sessions, or
proof-bound session grants. Use the existing session/device revocation controls
or lock/disable the account when incident response requires those sessions to
end. Password/email recovery and recovery-generation changes likewise do not
rotate or resurrect Passkeys: active credentials remain active and revoked
credentials remain revoked.
