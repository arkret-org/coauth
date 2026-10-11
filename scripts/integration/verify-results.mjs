import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const input = process.argv[2];
if (!input) throw new Error("business-results.json path is required");
const report = JSON.parse(readFileSync(input, "utf8"));
const specs = [];
function collect(suite) {
  specs.push(...(suite.specs ?? []));
  for (const child of suite.suites ?? []) collect(child);
}
for (const suite of report.suites ?? []) collect(suite);
const required = ["S1", "S2", "S3"];
if (specs.length !== required.length || report.errors?.length) {
  throw new Error(`Expected exactly 3 business scenarios, received ${specs.length}`);
}
const results = required.map(scenario => {
  const matching = specs.filter(spec => spec.title.startsWith(`${scenario} `));
  if (matching.length !== 1 || !matching[0].ok) throw new Error(`${scenario} did not pass`);
  const tests = matching[0].tests;
  if (tests.length !== 1 || tests[0].status !== "expected" ||
      tests[0].expectedStatus !== "passed" || tests[0].results.length !== 1 ||
      tests[0].results[0].status !== "passed") {
    throw new Error(`${scenario} must run once and pass without skips or expected failures`);
  }
  return { scenario, status: "passed", duration_ms: tests[0].results[0].duration };
});
writeFileSync(path.join(path.dirname(input), "business-summary.json"),
  JSON.stringify({ passed: 3, failed: 0, skipped: 0, results }, null, 2) + "\n");
console.log("[e2e] business results: 3 passed, 0 failed, 0 skipped");
