import { asUser } from "./test-identity";
import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";

function fixture(guid: string, name: string) {
  return `attack_technique: T1082
display_name: System Information Discovery
atomic_tests:
  - name: ${name}
    auto_generated_guid: ${guid}
    description: Browser upload fixture. No test will be executed.
    supported_platforms: [windows]
    executor:
      name: powershell
      command: Write-Output 'browser catalog fixture'
      cleanup_command: Write-Output 'cleanup fixture'
      elevation_required: false
`;
}

test("administrator uploads YAML, previews changes, imports and separately reviews a definition", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await asUser(page, "admin");
  await page.getByRole("button", { name: "Test Catalog", exact: true }).click();
  await page.getByRole("button", { name: "Upload YAML", exact: true }).click();
  const modal = page.getByRole("dialog", { name: "Catalog imports" });
  const guid = randomUUID();
  const name = `Browser YAML ${guid.slice(0, 8)}`;
  await page.getByLabel("Atomic YAML files", { exact: true }).setInputFiles({
    name: "T1082.yaml",
    mimeType: "text/yaml",
    buffer: Buffer.from(fixture(guid, name)),
  });
  await page.getByLabel("Source Git commit").fill("a".repeat(40));
  await modal.getByRole("button", { name: "Validate and preview" }).click();
  await expect(
    modal.getByRole("heading", { name: "Import preview" }),
  ).toBeVisible();
  await expect(modal.getByRole("button", { name, exact: true })).toBeVisible();
  await expect(
    modal.getByRole("button", { name: "Import reviewed changes" }),
  ).toBeDisabled();
  await modal.getByRole("button", { name, exact: true }).click();
  await expect(
    modal.getByText("New test — no existing definition"),
  ).toBeVisible();
  await modal
    .getByLabel("I reviewed the catalog changes.", { exact: false })
    .check();
  await modal.getByRole("button", { name: "Import reviewed changes" }).click();
  await modal
    .getByRole("button", { name: "Confirm import", exact: true })
    .click();
  await expect(
    modal.getByText(
      "Catalog imported. New and changed definitions remain unapproved.",
    ),
  ).toBeVisible();
  await modal.getByRole("button", { name: "Close dialog" }).click();
  await expect(modal).not.toBeVisible();
  await page.getByLabel("Search catalog").fill(name);
  const row = page.locator("tbody tr").filter({ hasText: guid });
  await expect(
    row.getByText("unreviewed", { exact: true }).last(),
  ).toBeVisible();
  await row.getByRole("button", { name, exact: true }).click();
  const detail = page.getByRole("dialog", { name: "Atomic test definition" });
  await expect(
    detail.getByRole("button", { name: "Configure execution" }),
  ).toBeDisabled();
  await detail.getByLabel("Standard User", { exact: true }).check();
  await detail.getByRole("button", { name: "Approve test" }).click();
  await expect(
    detail.getByText(
      "Definition approved. Each execution still requires human authorization.",
    ),
  ).toBeVisible();
  await detail.getByRole("button", { name: "Close dialog" }).click();
  await expect(row.getByText("low", { exact: true })).toBeVisible();
  await page.screenshot({
    path: "artifacts/catalog-upload.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});

test("invalid upload shows an error and a catalog-only upload cannot be approved", async ({
  page,
}) => {
  await page.goto("/");
  await asUser(page, "admin");
  await page.getByRole("button", { name: "Test Catalog", exact: true }).click();
  await page.getByRole("button", { name: "Upload YAML", exact: true }).click();
  const modal = page.getByRole("dialog", { name: "Catalog imports" });
  await page.getByLabel("Atomic YAML files", { exact: true }).setInputFiles({
    name: "invalid.yaml",
    mimeType: "text/yaml",
    buffer: Buffer.from("atomic_tests: []"),
  });
  await modal.getByRole("button", { name: "Validate and preview" }).click();
  await expect(modal.getByRole("alert")).toContainText("Invalid Atomic schema");
  const guid = randomUUID(),
    name = `Catalog only ${guid.slice(0, 8)}`;
  await page.getByLabel("Atomic YAML files", { exact: true }).setInputFiles({
    name: "T1082.yaml",
    mimeType: "text/yaml",
    buffer: Buffer.from(fixture(guid, name)),
  });
  await modal.getByRole("button", { name: "Validate and preview" }).click();
  await expect(
    modal.getByText("These uploads have no pinned Git commit.", {
      exact: false,
    }),
  ).toBeVisible();
  await modal
    .getByLabel("I reviewed the catalog changes.", { exact: false })
    .check();
  await modal.getByRole("button", { name: "Import reviewed changes" }).click();
  await modal
    .getByRole("button", { name: "Confirm import", exact: true })
    .click();
  await expect(
    modal.getByText(
      "Catalog imported. New and changed definitions remain unapproved.",
    ),
  ).toBeVisible();
  await modal.getByRole("button", { name: "Close dialog" }).click();
  await expect(modal).not.toBeVisible();
  await page.getByLabel("Search catalog").fill(name);
  await page.getByRole("button", { name, exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Approve test" }),
  ).toBeDisabled();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Close dialog" })
    .click();
  await asUser(page, "operator");
  await expect(
    page.getByRole("button", { name: "Upload YAML", exact: true }),
  ).not.toBeVisible();
  await expect(
    page.getByRole("button", { name: "Sync from GitHub", exact: true }),
  ).not.toBeVisible();
});

test("GitHub sync UI displays pinned changes and confirms import", async ({
  page,
}) => {
  const id = randomUUID(),
    guid = randomUUID(),
    revision = "b".repeat(40);
  const record = {
    id,
    source: "github",
    ref: "master",
    revision,
    status: "ready",
    created_by: "dev:admin",
    created_at: Date.now() / 1000,
    updated_at: Date.now() / 1000,
    applied_by: null,
    error: null,
    test_count: 1,
    file_count: 1,
    pinned: true,
  };
  let imported = false;
  await page.route("**/api/v1/catalog/sync", async (route) => {
    expect(route.request().postDataJSON()).toEqual({ ref: "master" });
    await route.fulfill({
      status: 202,
      json: { ...record, status: "fetching", revision: "" },
    });
  });
  await page.route(`**/api/v1/catalog/imports/${id}?*`, (route) =>
    route.fulfill({
      json: {
        ...record,
        status: imported ? "imported" : "ready",
        counts: {
          added: 1,
          changed: 0,
          revision_changed: 0,
          unchanged: 0,
          removed: 0,
          conflict: 0,
        },
        preview_token: "c".repeat(64),
        changes: [
          {
            guid,
            name: "GitHub preview fixture",
            technique: "T1082",
            kind: "added",
            path: "atomics/T1082/T1082.yaml",
            before: null,
            after: { executor: { command: "Write-Output fixture" } },
            previously_approved: false,
          },
        ],
        total: 1,
        limit: 30,
        offset: 0,
      },
    }),
  );
  await page.route(`**/api/v1/catalog/imports/${id}/confirm`, async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      preview_token: "c".repeat(64),
      replace_conflicts: false,
    });
    imported = true;
    await route.fulfill({ json: { ...record, status: "imported" } });
  });
  await page.goto("/");
  await asUser(page, "admin");
  await page.getByRole("button", { name: "Test Catalog", exact: true }).click();
  await page
    .getByRole("button", { name: "Sync from GitHub", exact: true })
    .click();
  const modal = page.getByRole("dialog", { name: "Catalog imports" });
  await page.getByLabel("Branch, tag, or commit").fill("master");
  await modal.getByRole("button", { name: "Fetch preview" }).click();
  await expect(modal.getByText(revision, { exact: true })).toBeVisible();
  await expect(
    modal.getByRole("button", { name: "GitHub preview fixture", exact: true }),
  ).toBeVisible();
  await modal
    .getByLabel("I reviewed the catalog changes.", { exact: false })
    .check();
  await modal.getByRole("button", { name: "Import reviewed changes" }).click();
  await modal
    .getByRole("button", { name: "Confirm import", exact: true })
    .click();
  await expect(
    modal.getByText(
      "Catalog imported. New and changed definitions remain unapproved.",
    ),
  ).toBeVisible();
});
