import { expect, type Page } from "@playwright/test";

/** Sign in with the one-click button of a demo account, identified by the local part of its email. */
export async function signInAs(page: Page, account: string) {
  await page.goto("/login");
  const row = page.getByRole("listitem").filter({ hasText: `${account}@` });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("**/overview");
}

/** Fails the test on an uncaught exception in the page or a 5xx from the API. */
export function watchForFailures(page: Page): string[] {
  const failures: string[] = [];
  page.on("pageerror", (error) => failures.push(`page error: ${error.message}`));
  page.on("response", (response) => {
    if (response.status() >= 500 && response.url().includes("/api/")) failures.push(`${response.status()} ${response.url()}`);
  });
  return failures;
}
