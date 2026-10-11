import path from "node:path";
import { defineConfig } from "../../../cotest/e2e/helpers/arkret-test";

const output = process.env.COAUTH_INTEGRATION_OUTPUT_DIR;
if (!output) throw new Error("COAUTH_INTEGRATION_OUTPUT_DIR is required");
const spki = process.env.COTEST_TLS_SPKI_SHA256;

export default defineConfig({
  testDir: ".",
  testMatch: "business.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  outputDir: path.join(output, "browser-output"),
  reporter: [
    ["list"],
    ["json", { outputFile: path.join(output, "business-results.json") }],
    ["junit", { outputFile: path.join(output, "business-junit.xml") }],
  ],
  use: {
    browserName: "chromium",
    launchOptions: {
      args: spki ? [`--ignore-certificate-errors-spki-list=${spki}`] : [],
    },
    ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
    trace: "off",
    video: "off",
    screenshot: "off",
  },
});
