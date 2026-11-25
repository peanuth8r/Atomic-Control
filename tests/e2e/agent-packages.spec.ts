import { asUser } from "./test-identity";
import { test, expect } from "@playwright/test";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

test("administrator generates and downloads an actor-specific Windows ZIP", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await asUser(page, "admin");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  const row = page.locator("tbody tr").filter({ hasText: "WIN-TEST-01" });
  await row
    .getByRole("button", { name: "Generate agent", exact: true })
    .click();
  const modal = page.getByRole("dialog", { name: "Generate Windows agent" });
  await expect(modal.getByText("WIN-TEST-01", { exact: true })).toBeVisible();
  await expect(
    modal.getByLabel("Include a single-use enrollment token", { exact: false }),
  ).toBeDisabled();
  await expect(
    modal.getByRole("button", { name: "Generate and download ZIP" }),
  ).toBeEnabled();
  await modal
    .getByLabel("Control-plane HTTPS URL")
    .fill("https://control.example.test");
  await modal.getByLabel("Include a single-use enrollment token", { exact: false }).uncheck();
  const pending = page.waitForEvent("download");
  await modal
    .getByRole("button", { name: "Generate and download ZIP" })
    .click();
  const download = await pending;
  expect(download.suggestedFilename()).toBe(
    "AtomicControlAgent-WIN-TEST-01.zip",
  );
  await download.saveAs("artifacts/AtomicControlAgent-WIN-TEST-01.zip");
  const bytes = readFileSync("artifacts/AtomicControlAgent-WIN-TEST-01.zip");
  expect(bytes.subarray(0, 2).toString()).toBe("PK");
  expect(bytes.length).toBeGreaterThan(10000);
  await expect(modal.locator(".package-download-result")).toContainText(
    "configuration only",
  );
  await expect(
    modal.locator(".package-download-result .block-code"),
  ).toHaveText(createHash("sha256").update(bytes).digest("hex"));
  await page.screenshot({ path: "artifacts/agent-package-download.png" });
  expect(errors).toEqual([]);
});

test("reserve a Windows host then download its package; operator controls stay restricted", async ({
  page,
}) => {
  await page.goto("/");
  await asUser(page, "admin");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page.getByRole("button", { name: "Add actor" }).click();
  const hostname = "AGENT-" + randomUUID().slice(0, 8).toUpperCase();
  await page.getByLabel("Hostname", { exact: true }).fill(hostname);
  await page
    .getByRole("button", { name: "Register and configure download" })
    .click();
  const modal = page.getByRole("dialog", { name: "Generate Windows agent" });
  await expect(modal.getByText(hostname, { exact: true })).toBeVisible();
  await expect(
    modal.getByText("pending enrollment", { exact: true }),
  ).toBeVisible();
  await expect(
    modal.getByText("No execution profiles are configured.", { exact: false }),
  ).toBeVisible();
  await modal.getByLabel("Include a single-use enrollment token", { exact: false }).uncheck();
  const pending = page.waitForEvent("download");
  await modal
    .getByRole("button", { name: "Generate and download ZIP" })
    .click();
  const download = await pending;
  expect(download.suggestedFilename()).toBe(
    `AtomicControlAgent-${hostname}.zip`,
  );
  await modal.getByRole("button", { name: "Close dialog" }).click();
  await expect(modal).not.toBeVisible();
  const row = page.locator("tbody tr").filter({ hasText: hostname });
  await expect(
    row.getByText("pending enrollment", { exact: true }),
  ).toBeVisible();
  await asUser(page, "operator");
  await expect(
    page.getByRole("button", { name: "Add actor" }),
  ).not.toBeVisible();
  await expect(
    row.getByRole("button", { name: "Generate agent" }),
  ).not.toBeVisible();
});

test("reserve a Linux actor and download its systemd agent", async ({ page }) => {
  await page.goto("/");
  await asUser(page, "admin");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page.getByRole("button", { name: "Add actor", exact: true }).click();
  await page.getByLabel("Operating system", { exact: true }).selectOption("linux");
  const hostname = "linux-" + randomUUID().slice(0, 8);
  await page.getByLabel("Hostname", { exact: true }).fill(hostname);
  await page.getByRole("button", { name: "Register and configure download" }).click();
  const modal = page.getByRole("dialog", { name: "Generate Linux agent" });
  await expect(modal.getByText(hostname, { exact: true })).toBeVisible();
  await expect(modal.getByText("Requires Linux with systemd", { exact: false })).toBeVisible();
  await modal.getByLabel("Include a single-use enrollment token", { exact: false }).uncheck();
  const pending = page.waitForEvent("download");
  await modal.getByRole("button", { name: "Generate and download ZIP" }).click();
  const download = await pending;
  expect(download.suggestedFilename()).toBe(`AtomicControlAgent-${hostname}.zip`);
  await download.saveAs("artifacts/AtomicControlAgent-Linux.zip");
  const bytes = readFileSync("artifacts/AtomicControlAgent-Linux.zip");
  expect(bytes.subarray(0, 2).toString()).toBe("PK");
  await expect(modal.locator(".package-download-result .block-code")).toHaveText(createHash("sha256").update(bytes).digest("hex"));
  await page.screenshot({ path: "artifacts/linux-agent-package.png" });
});
