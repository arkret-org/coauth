import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const input = process.argv[2];
if (!input) throw new Error("IVS results.json path is required");
const report = JSON.parse(readFileSync(input, "utf8"));
const suffix = " @third-party-provider";
const required = [
  ...["offline_token", "lookup"].map(mode => `TP5 ${mode}: real provision, accepted attestation, OOB delivery, Claim and accept`),
  "TP2 original intent and immutable activation survive actual provider restart",
  "TP1 issuance requires an accepted Device and preserves original signed intent",
  "TP3 signed activation remains distinct from withdrawn current delivery authority",
  "TP3 explicit attestation expiry refuses activation and scrubs unbound material",
  "TP4 all six failure classes are indistinguishable and rejected bindings do not consume offline tokens",
  "TP4 three namespace lookup failures invalidate the original token",
  "TP4 URL tokens are rejected before malformed body or operation selector",
  ...["allowlist", "inviter_leave", "revoke"].map(cause => `TP5 current ${cause} stops an already delivered token`),
  "TP5 loss of the actual inviter capability stops present without relying on Realm ownership",
  "TP4 knock_restricted is refused and the original source rate limit is enforced",
].map(title => title + suffix);
const specs = [];
function collect(suite) {
  specs.push(...(suite.specs ?? []));
  for (const child of suite.suites ?? []) collect(child);
}
for (const suite of report.suites ?? []) collect(suite);
if (report.errors?.length || specs.length !== required.length) {
  throw new Error(`Expected exactly ${required.length} IVS cases, received ${specs.length}`);
}
const results = required.map(title => {
  const matching = specs.filter(spec => spec.title === title);
  if (matching.length !== 1 || !matching[0].ok) throw new Error(`IVS case did not pass: ${title}`);
  const tests = matching[0].tests;
  if (tests.length !== 1 || tests[0].status !== "expected" || tests[0].expectedStatus !== "passed" ||
      tests[0].results.length !== 1 || tests[0].results[0].status !== "passed" || tests[0].results[0].retry !== 0) {
    throw new Error(`IVS case must actually pass once without skips/retries: ${title}`);
  }
  return { title, status: "passed", duration_ms: tests[0].results[0].duration };
});
writeFileSync(path.join(path.dirname(input), "summary.json"), JSON.stringify({
  passed: required.length, failed: 0, skipped: 0, retried: 0, results,
}, null, 2) + "\n");
console.log(`[ivs] ${required.length} passed, 0 failed, 0 skipped, 0 retries`);
