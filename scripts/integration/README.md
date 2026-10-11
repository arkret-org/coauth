# Coauth business integration

Run from the Coauth repository:

```sh
bash scripts/integration-up.sh --business -JointDir /absolute/path/to/run
```

This serially builds the approval signing example and prepares the current
Coauth service through Cotest's managed Cargo-artifact entry. That entry records
frozen source inputs and executable bytes after an actual successful Cargo build,
including a legitimate cache hit, without changing the executable timestamp.
It then invokes Cotest's canonical single-Station runner. An explicit `-CoauthBin`
uses that caller-provided service binary without rebuilding it. These API and
WebAuthn scenarios use the HTTPS health document and require no frontend bundle.
The runner owns isolated PostgreSQL databases, Coauth,
Coland, mock registration mail, HTTPS, the run-scoped CA, owning Station
identity and process cleanup. Its post-provision hook calls the original
`integration-e2e.sh` entry with those accepted deployment inputs. The
Compose-only invocation remains useful for health/OIDC utilities; it does not
supply canonical account binding and is not a business integration result.

The three required scenarios are:

| Scenario | Positive boundary | Required rejection/readback |
| --- | --- | --- |
| S1 | Account-first registration, accepted two-Event PCR genesis, founding device grant, signed Realm/Strand/message and authenticated stream read | Altered producer signature: `401/signature_invalid`; another accepted principal under the wrong holder grant: `403/capability_denied`; unchanged Event and Commit lists |
| S2 | Actual Chromium virtual authenticator `navigator.credentials.create/get`, normal browser session | Challenge, cross-site origin, ceremony browser binding, real ten-minute expiry, credential/session replay; no additional credential or expired-session login |
| S3 | Two independently registered administrator DIDs, CLI request eligibility, interactive OAuth PKCE bearer, two native-root DetachedJWS approvals, account disable | Forged approver, wrong action/target, another principal's root proof, altered signature, duplicate administrator, threshold one, execution replay, revoked admin bearer; unchanged transition history on rejected writes |

S2 intentionally waits 601 seconds for the product's ten-minute ceremony TTL;
its case has a twelve-minute budget. It does not change the product clock, TTL
or database. Risk-action proposals have no product-contract expiry field; S3
checks actual bearer revocation instead of inventing proposal expiry.

Protocol objects, canonical JSON, signatures, DID/PCR material and operation
selectors come from existing Cotest/Arkret SDK helpers. The approval oracle
accepts recovery custody through stdin, checks it against the registration
root and signs the Coauth product approval transcript with the SDK JWS codec.
It prints only the detached proof and never writes private custody artifacts.
The product requests the Station's closed current native-control evidence,
binds its control-key digest to the proof's exact `did:key` method, and accepts
the same resolution under `AdminAction` freshness. Personal DID documents
remain identity anchors without root or business verification methods.
The local approval timestamp is observed after native resolution and proof
verification; this does not claim an atomic cut across separate services.

The entry requires all three scenarios to run exactly once and pass. Missing
deployment inputs, positive-path 401/404/405/501, runner errors, skipped tests,
expected failures, retries and empty selections cannot yield a passing summary.
Results are in `<run>/coauth-integration/business-summary.json` and
`business-junit.xml`; service and provisioning diagnostics are runner-owned.

Static checks, without starting services:

```sh
node ../cotest/e2e/node_modules/typescript/bin/tsc --project scripts/integration/tsconfig.json
node --test scripts/integration/verify-results.test.mjs
bash -n scripts/integration-{up,smoke,e2e}.sh
```

For an already attached canonical deployment, `integration-e2e.sh` consumes
`COTEST_TOPOLOGY_PATH`, `COTEST_JOINT_RUN_DIR`, `COTEST_WIRE_BIN`,
`COTEST_COAUTH_BASE_URL`, `COTEST_COLAND_BASE_URL`, `COTEST_COLAND_SERVICE_ID`,
`COTEST_OIDC_CLIENT_ID` and the runner CA/SPKI variables. Optional explicit
`COAUTH_INTEGRATION_COAUTH_BIN`, `COAUTH_INTEGRATION_COAUTH_CONFIG`,
`COAUTH_INTEGRATION_APPROVAL_BIN` and `COAUTH_INTEGRATION_OUTPUT_DIR` override
paths. Without overrides, executable paths are derived from Cargo metadata;
the CLI config comes from the live topology's `coauth.config_path` record.
