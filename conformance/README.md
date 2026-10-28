# OIDC conformance harness

The scheduled and manually dispatched workflow builds the OpenID Foundation
Java suite at `11999aad62ec292f36101410d9d5b761d44903ff`, uses a real MongoDB
service, and invokes its `scripts/run-test-plan.py` API runner. No prebuilt
`openid/conformance-suite` image is assumed.

`run-local-official-suite.sh` prepares an isolated Coauth PostgreSQL fixture,
two Basic clients, a distinct POST client, two private-key clients, a real local user, and
HTTPS reverse proxies for Coauth and the suite. Chromium drives the built
Coauth WASM login and consent pages using the official runner's front-channel
URLs and HTTP methods. Java and Coauth trust the temporary issuer certificate. Private configuration,
wrapping keys and TLS keys are deleted after the run. The original official
signed ZIP archives and service logs remain in the private temporary directory
and are deleted with it. Only module/condition outcome summaries and JUnit
outcomes without configuration, HTTP payloads or diagnostic messages are
uploaded. Archive SHA-256 digests preserve a reference to the untouched originals;
the sanitized summaries are not signed certification archives.

## Test scope

`discovery` executes the official `oidcc-config-certification-test-plan`,
including the discovery endpoint validation module. Passing that selection
proves the OIDCC Config profile only; it does not prove the full OP, FAPI or
mTLS profiles.

`basic-op` and `fapi2-baseline` receive generated private configurations and
execute the complete upstream plans, without a filtered module list. This
bootstrap does not imply that either protocol plan passes. An optional
`COAUTH_CONFORMANCE_FULL_PLANS_JSON` override must contain all three profile
names, with real `_official_plan`, registered clients, HTTPS discovery and
`browser` login/consent automation.

`mtls-baseline` remains a strict failure in the local fixture: production
discovery and static/dynamic registration do not implement RFC8705 client
authentication or certificate-bound access tokens. Generating certificates
cannot supply that capability. `all` still attempts Basic OP and FAPI and
fails on any protocol failure or the mTLS gap. The default scheduled selection
remains `all`; these are unfinished acceptance obligations. Checked-in JSON
files are selection inventory, not fake client configurations or a substitute
for official execution.

The upstream `server.login_hint` points to the seeded account, and
`client_secret_post` names its independently registered POST client. Browser
automation only drives test IDs created by its current plan, and stops its
unfinished tests on exit; a failed earlier plan cannot supply a later plan's
login requests. The upstream module list and protocol assertions remain intact.

The integration smoke entry point is `scripts/oidc-conformance.sh`. Without
`COAUTH_RUN_FULL_CONFORMANCE=1` it checks live discovery and reports the plan
inventory. That smoke result is separate from official conformance.

## Pinned suite regression repair

`official-suite-literal-metadata.patch` corrects an upstream JSON member lookup
bug: the endpoint validator iterates literal discovery keys, but the shared
URI reader treats dots as nested path separators. As a result, the legitimate
`org.arkret.api_endpoint` extension is reported missing despite its HTTPS value.
The patch prefers an existing literal member and retains nested-path fallback.
Three JUnit regressions prove namespaced HTTPS acceptance and HTTP/null
rejection. CI applies the patch only to the pinned commit and runs the endpoint
validator unit tests before invoking the real suite. This is a locally repaired
suite result, not an unmodified upstream certification result. Remove the patch
when the upstream literal-member repair is included in the pinned release.

The fixture registers exactly five known metadata extensions through the
suite's supported `server.allow_unexpected_metadata_fields` configuration:
`account_management_uri`, `account_management_actions_supported`,
`org.arkret.api_endpoint`, `org.arkret.did_binding_methods` and
`org.arkret.supported_scopes`. No unexpected-failure or skipped-condition list
is passed to the runner. The live discovery response is never rewritten.

[Official source](https://gitlab.com/openid/conformance-suite)
