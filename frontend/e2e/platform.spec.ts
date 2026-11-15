import { expect, test } from "@playwright/test";
import { signInAs, watchForFailures } from "./helpers";

const PAGES: [path: string, heading: string][] = [
  ["/overview", "Overview"], ["/assets", "Assets"], ["/attack-surface", "Attack Surface"], ["/vulnerabilities", "Vulnerabilities"],
  ["/web-api", "Web & API Security"], ["/cloud", "Cloud Security"], ["/identity", "Identity Security"],
  ["/supply-chain", "Containers & Supply Chain"], ["/ai-security", "AI Security"], ["/ai-redteam", "AI Red Team"],
  ["/threat-intel", "Threat Intelligence"], ["/attack-paths", "Attack Paths"], ["/risk", "Risk"], ["/remediation", "Remediation"],
  ["/policies", "Policies"], ["/integrations", "Integrations"], ["/reports", "Reports"], ["/audit", "Audit"], ["/admin", "Administration"],
];

test("the sign-in page offers one account per role", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Demo accounts" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toHaveCount(10); // the form's own button and nine accounts
});

test("a wrong password is refused without saying which part was wrong", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("analyst@demo.example.com");
  await page.getByLabel("Password", { exact: true }).fill("not-the-password");
  await page.locator("form").getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Invalid email or password")).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test("signed-out visitors are sent to the sign-in page", async ({ page }) => {
  await page.goto("/findings");
  await expect(page).toHaveURL(/\/login/);
});

test("every product area renders for an administrator without an error", async ({ page }) => {
  test.setTimeout(180_000);
  const failures = watchForFailures(page);
  await signInAs(page, "org.admin");
  for (const [path, heading] of PAGES) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 }), path).toContainText(heading);
    await expect(page.getByRole("alert").filter({ hasText: /went wrong|failed to load|internal/i }), path).toHaveCount(0);
  }
  expect(failures).toEqual([]);
});

test("AI Security shows how to run the aictem CLI and accepts its inventory", async ({ page }) => {
  await signInAs(page, "security.admin");
  await page.goto("/ai-security?tab=assessments");
  const card = page.locator("section").filter({ hasText: "Discover from inside a repository" });
  await expect(card.getByText("pipx install aictem", { exact: true })).toBeVisible();
  await card.getByRole("tab", { name: "pip", exact: true }).click();
  await expect(card.getByText("pip install aictem", { exact: true })).toBeVisible();
  await expect(card.getByText("aictem discover . --upload --gate high")).toBeVisible();
  await expect(card.getByRole("link", { name: "PyPI" })).toHaveAttribute("href", "https://pypi.org/project/aictem/");

  await page.getByRole("button", { name: "Import results" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("combobox")).toHaveValue("aictem");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toHaveCount(0);
});

test("the sample repository analysis lists the agent, its tools and what is wrong with them", async ({ page }) => {
  test.setTimeout(360_000); // on a fresh instance the worker analyses the sample repository shortly after start-up
  await signInAs(page, "analyst");
  await expect(async () => {
    await page.goto("/ai-security?type=ai_agent");
    await expect(page.getByText("Agent in src/agent.py")).toBeVisible({ timeout: 5_000 });
  }).toPass({ timeout: 300_000, intervals: [5_000] });
  await page.goto("/findings?q=approval%20step");
  await expect(page.getByText(/high-impact tools and no approval step/).first()).toBeVisible();
});

test("filters on the findings table are kept in the address bar", async ({ page }) => {
  await signInAs(page, "analyst");
  await page.goto("/findings?severity=critical");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Findings");
  await page.reload();
  await expect(page).toHaveURL(/severity=critical/);
});

test("a read-only user sees the data but not the controls that change it", async ({ page }) => {
  await signInAs(page, "viewer");
  await page.goto("/ai-security");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("AI Security");
  await expect(page.getByRole("button", { name: "Add AI asset" })).toHaveCount(0);
  await page.goto("/ai-security?tab=assessments");
  await expect(page.getByRole("button", { name: "Import results" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "New assessment" })).toHaveCount(0);
});

test("demo mode refuses to store integration credentials", async ({ page }) => {
  await signInAs(page, "org.admin");
  const { csrf_token } = await (await page.request.get("/api/v1/auth/csrf")).json();
  const response = await page.request.post("/api/v1/integrations", {
    data: { connector: "webhook", name: "e2e", config: { url: "https://hooks.example.com/x" }, credentials: { signing_secret: "e2e-".repeat(4) } },
    headers: { "X-CSRF-Token": csrf_token },
  });
  expect(response.status(), await response.text()).toBe(403);
  expect(await response.text()).toMatch(/demo/i);
});

test("signing out ends the session", async ({ page }) => {
  await signInAs(page, "analyst");
  await page.getByRole("button", { name: /sign out|log out/i }).click();
  await expect(page).toHaveURL(/\/login/);
  await page.goto("/overview");
  await expect(page).toHaveURL(/\/login/);
});
