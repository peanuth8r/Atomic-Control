import { asUser } from "./test-identity";
import { test, expect } from "@playwright/test";
test("operator, approver, standard and administrator evidence, cleanup and audit", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Validation overview" }),
  ).toBeVisible();
  for (const profile of ["Standard User", "Local Administrator"]) {
    await page.getByRole("button", { name: "New execution" }).click();
    await page
      .getByLabel("Atomic test", { exact: true })
      .selectOption({
        label: "T1082 — Fixture system information discovery",
      });
    await page
      .getByLabel("Execution actor", { exact: true })
      .selectOption({ label: "WIN-TEST-01 — online" });
    await page
      .getByLabel("Execution identity", { exact: true })
      .selectOption({
        label:
          profile === "Standard User"
            ? "Standard User — WIN-TEST-01\\atomic-user"
            : "Local Administrator — WIN-TEST-01\\atomic-admin",
      });
    const reason = `Browser verification ${profile} ${Date.now()}`;
    await page.getByLabel("Testing reason").fill(reason);
    if (profile === "Local Administrator")
      await expect(
        page.getByText(
          "Elevated execution requires a separate privileged approver.",
          { exact: false },
        ),
      ).toBeVisible();
    await page.getByRole("button", { name: "Review request" }).click();
    const created = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === "/api/v1/runs" &&
        response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    const response = await created;
    expect(response.status(), await response.text()).toBe(201);
    const evidence = page.getByRole("dialog", { name: "Execution evidence" });
    await expect(evidence).toBeVisible();
    await expect(
      evidence.getByText("pending approval", { exact: true }).first(),
    ).toBeVisible();
    await evidence.getByRole("button", { name: "Close dialog" }).click();
    await asUser(page, "approver");
    await page
      .getByRole("button", { name: "Approvals", exact: false })
      .first()
      .click();
    const row = page.locator(".approval-row").filter({ hasText: reason });
    await row.getByRole("button", { name: "Inspect request" }).click();
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await page
      .getByLabel("Decision reason")
      .fill("Reviewed the exact fixture test, actor, identity and scope");
    await page.getByRole("button", { name: "Confirm", exact: true }).click();
    await expect(
      evidence.locator(".detail-title").getByText("succeeded", { exact: true }),
    ).toBeVisible({ timeout: 15000 });
    await expect(evidence.getByText("verified", { exact: true })).toBeVisible();
    await expect(
      evidence.getByText(
        "Synthetic test evidence: no command was executed.",
        { exact: false },
      ),
    ).toBeVisible();
    await evidence.getByRole("button", { name: "Close dialog" }).click();
    await asUser(page, "operator");
  }
  await page
    .getByRole("button", { name: "Execution History", exact: true })
    .click();
  await page.locator("tbody tr").first().getByRole("button").click();
  await page
    .getByRole("button", { name: "Request cleanup", exact: true })
    .click();
  await page
    .getByLabel("Decision reason")
    .fill("Clean test artifacts in the same reviewed context");
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(
    page
      .getByRole("dialog", { name: "Execution evidence" })
      .locator(".detail-title")
      .getByText("pending approval", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Close dialog" })
    .click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Security audit" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Dashboard", exact: true }).click();
  await page.screenshot({ path: "artifacts/dashboard.png", fullPage: true });
  expect(errors).toEqual([]);
});
test("responsive light theme and viewer restrictions", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await asUser(page, "viewer");
  await expect(
    page.getByRole("button", { name: "New execution" }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Toggle theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({ path: "artifacts/mobile.png", fullPage: true });
});
