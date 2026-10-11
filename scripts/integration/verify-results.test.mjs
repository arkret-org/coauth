import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const verifier = fileURLToPath(new URL("verify-results.mjs", import.meta.url));
function run(change = () => {}) {
  const directory = mkdtempSync(path.join(tmpdir(), "coauth-business-gate-"));
  try {
    const report = { suites: [{ specs: ["S1", "S2", "S3"].map(id => ({
      title: `${id} business`, ok: true, tests: [{
        status: "expected", expectedStatus: "passed",
        results: [{ status: "passed", duration: 1 }],
      }],
    })) }], errors: [] };
    change(report);
    const input = path.join(directory, "business-results.json");
    writeFileSync(input, JSON.stringify(report));
    const result = spawnSync(process.execPath, [verifier, input], { encoding: "utf8" });
    return { status: result.status, summary: result.status === 0
      ? JSON.parse(readFileSync(path.join(directory, "business-summary.json"), "utf8")) : undefined };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test("only three actual successful business runs produce a passing summary", () => {
  assert.equal(run().summary.passed, 3);
});
test("missing business scenarios fail closed", () => {
  assert.notEqual(run(report => report.suites[0].specs.pop()).status, 0);
});
test("skip, expected failure, retries, duplicate names and runner errors fail closed", () => {
  for (const status of ["skipped", "failed", "timedOut", "interrupted"]) {
    assert.notEqual(run(report => report.suites[0].specs[0].tests[0].results[0].status = status).status, 0);
  }
  assert.notEqual(run(report => report.suites[0].specs[0].tests[0].expectedStatus = "failed").status, 0);
  assert.notEqual(run(report => report.suites[0].specs[0].tests[0].results.push({ status: "passed" })).status, 0);
  assert.notEqual(run(report => report.suites[0].specs[1].title = "S1 duplicate").status, 0);
  assert.notEqual(run(report => report.errors.push({ message: "startup failed" })).status, 0);
});
