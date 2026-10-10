# OIDC conformance harness

The scheduled and manually dispatched workflow builds the OpenID Foundation
Java suite at `11999aad62ec292f36101410d9d5b761d44903ff`, uses a real MongoDB
service, and invokes its `scripts/run-test-plan.py` API runner. No prebuilt
`openid/conformance-suite` image is assumed.

`run-local-official-suite.sh` prepares an isolated Coauth PostgreSQL fixture,
two registered static clients, and HTTPS reverse proxies for Coauth and the
suite. Java trusts the temporary issuer certificate. Private configuration,
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

`all`, `basic-op`, `fapi2-baseline` and `mtls-baseline` require
`COAUTH_CONFORMANCE_FULL_PLANS_JSON`: a JSON object with exactly those three
profile names, each containing a real `_official_plan`, registered client
credentials, HTTPS discovery configuration, and `browser` automation for
real-user login and consent. The mTLS profile also needs the corresponding
registered certificate and key fixture. Missing fixtures fail the full gate;
plan inventory files are not a substitute for official execution. The default
scheduled selection remains `all`.

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
