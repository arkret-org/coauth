import path from "node:path";
import { defineConfig } from "../../../cotest/e2e/helpers/arkret-test";

const output = process.env.COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR;
if (!output) throw new Error("COAUTH_THIRD_PARTY_INVITE_OUTPUT_DIR is required");

export default defineConfig({
  testDir: ".", testMatch: "third-party-invites.spec.ts",
  workers: 1, fullyParallel: false, retries: 0, timeout: 360_000,
  outputDir: path.join(output, "test-output"),
  reporter: [["list"], ["json", { outputFile: path.join(output, "results.json") }],
    ["junit", { outputFile: path.join(output, "junit.xml") }]],
  use: { ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    trace: "off", screenshot: "off", video: "off" },
});
