import { defineConfig, devices } from "@playwright/test";

/**
 * Browser tests against a running demo deployment (CTEM_DEMO_MODE=true), which seeds one account per role.
 * CI runs them against the demo image it has just built; locally, point E2E_BASE_URL at any demo-mode instance.
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1, // one shared demo instance with a per-address rate limit on sign-in
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:10000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
