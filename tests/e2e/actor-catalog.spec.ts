import { expect, test, type Page } from "@playwright/test";
import type { Actor } from "../../apps/frontend/src/types";
const actorId = "11c65173-f831-40e4-8f0f-3602cbf9677f";
const guid = "2336db38-96f5-4939-9c6c-754e8d8bc691";
const revision = "a".repeat(40);

async function setup(page: Page, capable = true, admin = true) {
  const actor: Actor = {
    id: actorId,
    hostname: "linux-actor-fixture",
    registration_state: "enrolled",
    os: "linux",
    os_version: "Linux",
    online: true,
    enabled: true,
    simulated: false,
    last_heartbeat: Date.now() / 1000,
    health: "healthy",
    revision: "",
    agent_version: "0.1.0",
    active_job: null,
    profiles: [
      {
        id: "0184d6de-1f10-4ce8-91c5-00aa2e7de185",
        actor_id: actorId,
        profile_key: "standard-user",
        display_name: "Linux standard user",
        account: "atomic-user",
        expected_sid: "uid:1001",
        privilege: "standard",
        logon_type: "systemd",
        enabled: true,
        healthy: true,
      },
    ],
    profile_sync: {
      supported: true,
      protocol: 1,
      status: "applied",
      generation: 1,
      updated_at: Date.now() / 1000,
      error: "",
      results: {},
    },
    catalog: {
      protocol: capable ? 1 : 0,
      status: "not_configured",
      health: "missing",
      desired_revision: "",
      observed_revision: "",
      generation: 0,
      error: "",
      updated_at: null,
    },
  };
  const state = { actor, installs: 0, packages: 0, options: 0, stale: false };
  const paged = (items: unknown[]) => ({
    items,
    total: items.length,
    offset: 0,
    limit: 200,
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() === "GET") {
      if (path === "/me")
        return route.fulfill({
          json: {
            subject: "human-admin-fixture",
            roles: admin
              ? ["viewer", "operator", "administrator"]
              : ["viewer", "operator"],
            mode: "real",
            dev_auth: false,
            approval_mode: "catalog",
          },
        });
      if (path === "/actors") return route.fulfill({ json: paged([actor]) });
      if (path === `/actors/${actorId}`) return route.fulfill({ json: actor });
      if (path === `/actors/${actorId}/profiles`)
        return route.fulfill({ json: actor.profiles });
      if (path === "/tests")
        return route.fulfill({
          json: paged([
            {
              guid,
              technique: "T1082",
              name: "Catalog fixture",
              revision,
              content_sha256: "c".repeat(64),
              approved: true,
              risk_level: "low",
              allowed_profiles: ["standard-user"],
              active: true,
              execution_ready: true,
              simulated: false,
              catalog_source: "github",
              source_path: "fixture.yaml",
              definition: {
                description: "UI fixture only",
                technique_name: "System Information Discovery",
                supported_platforms: ["linux"],
                executor: { name: "bash", command: "printf synthetic" },
                input_arguments: {},
              },
            },
          ]),
        });
      if (["/runs", "/audit", "/approvals"].includes(path))
        return route.fulfill({ json: paged([]) });
      if (path === `/actors/${actorId}/catalog-options`) {
        state.options++;
        return route.fulfill({
          json: {
            revisions: [
              {
                revision,
                manifest_hash: "b".repeat(64),
                tests: 1950,
                approved_tests: 4,
              },
            ],
            ...actor.catalog,
          },
        });
      }
      if (path === "/agents/package-options")
        return route.fulfill({
          json: {
            mode: "real",
            api_url: "https://control.example.test",
            enrollment_available: true,
            revisions: [revision],
            token_lifetime_seconds: 600,
            format: "zip",
            requires_python: "3.12+",
          },
        });
    }
    if (
      request.method() === "POST" &&
      path === `/actors/${actorId}/catalog-install`
    ) {
      expect(capable && admin).toBe(true);
      expect(request.postDataJSON()).toEqual({
        revision,
        manifest_hash: "b".repeat(64),
        confirmed: true,
      });
      if (state.stale)
        return route.fulfill({
          status: 409,
          json: {
            error: {
              code: "catalog_changed",
              message:
                "Imported catalog changed. Reload and review the selected revision again",
            },
          },
        });
      state.installs++;
      actor.catalog = {
        ...actor.catalog!,
        status: "pending",
        desired_revision: revision,
        generation: 1,
        updated_at: Date.now() / 1000,
      };
      return route.fulfill({ json: actor.catalog });
    }
    if (
      request.method() === "POST" &&
      path === `/actors/${actorId}/agent-package`
    ) {
      expect(request.postDataJSON().include_enrollment).toBe(false);
      state.packages++;
      return route.fulfill({
        body: Buffer.from("fixture ZIP"),
        headers: {
          "Content-Type": "application/zip",
          "Content-Disposition": 'attachment; filename="catalog-agent.zip"',
          "X-Package-Mode": "configuration_only",
          "X-Package-SHA256": "c".repeat(64),
        },
      });
    }
    await route.abort();
    throw new Error(
      `Unexpected catalog UI request: ${request.method()} ${path}`,
    );
  });
  await page.goto("/");
  return state;
}

async function actorSetup(page: Page) {
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-actor-fixture", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await dialog
    .getByRole("button", { name: "Configure catalog", exact: true })
    .click();
  return dialog;
}

test("missing-pin diagnostic links to actor setup and installs only a confirmed imported commit", async ({
  page,
}) => {
  const state = await setup(page);
  await page.getByRole("button", { name: "Execute Test", exact: true }).click();
  await page.getByLabel("Atomic test", { exact: true }).selectOption(guid);
  await page.getByText("Actor eligibility and setup", { exact: true }).click();
  await expect(
    page.getByText("No pinned catalog revision reported", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Open actor setup" }).click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await dialog
    .getByRole("button", { name: "Configure catalog", exact: true })
    .click();
  await dialog.getByLabel("Imported catalog commit").selectOption(revision);
  await expect(
    dialog.getByText("1950 imported definitions", { exact: false }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Install pinned catalog" }),
  ).toBeDisabled();
  expect(state.installs).toBe(0);
  await dialog
    .getByLabel("I reviewed this commit and authorize installation", {
      exact: false,
    })
    .check();
  await dialog.getByRole("button", { name: "Install pinned catalog" }).click();
  await expect(
    dialog.getByText("Waiting for the agent to connect and become idle."),
  ).toBeVisible();
  expect(state.installs).toBe(1);
  state.actor.catalog = {
    ...state.actor.catalog!,
    status: "applied",
    health: "ready",
    observed_revision: revision,
  };
  state.actor.revision = revision;
  await expect(
    dialog.getByText("Catalog verified and ready.", { exact: false }),
  ).toBeVisible({ timeout: 10000 });
  await page.screenshot({ path: "artifacts/actor-catalog-ui.png" });
});

test("older agent gets a configuration-only updater with catalog capability enabled", async ({
  page,
}) => {
  const state = await setup(page, false);
  const dialog = await actorSetup(page);
  await expect(
    dialog.getByText("Catalog management requires an agent update", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Install pinned catalog" }),
  ).toBeDisabled();
  const warning = dialog.locator(".actor-catalog .warning").first();
  const heading = await warning.getByRole("heading").boundingBox();
  const explanation = await warning.locator("p").boundingBox();
  expect(explanation!.y).toBeGreaterThanOrEqual(heading!.y + heading!.height);
  await dialog
    .getByRole("button", { name: "Download catalog-capable agent" })
    .click();
  const update = page.getByRole("dialog", { name: "Generate Linux agent" });
  await expect(
    update.getByLabel("Include a single-use enrollment token", {
      exact: false,
    }),
  ).toBeDisabled();
  const download = page.waitForEvent("download");
  await update
    .getByRole("button", { name: "Generate and download ZIP" })
    .click();
  await download;
  await expect(
    update.getByText("--enable-catalog-sync --check-only", { exact: false }),
  ).toBeVisible();
  expect(state.packages).toBe(1);
  expect(state.installs).toBe(0);
});

test("failed fetch explains the host-side failure and offers an explicit retry", async ({
  page,
}) => {
  const state = await setup(page);
  state.actor.catalog = {
    ...state.actor.catalog!,
    status: "failed",
    error: "fetch_failed",
    desired_revision: revision,
  };
  const dialog = await actorSetup(page);
  await expect(
    dialog.getByText("The agent could not fetch this commit from GitHub.", {
      exact: false,
    }),
  ).toBeVisible();
  await dialog.getByLabel("Imported catalog commit").selectOption(revision);
  await dialog
    .getByLabel("I reviewed this commit and authorize installation", {
      exact: false,
    })
    .check();
  await dialog
    .getByRole("button", { name: "Retry catalog installation" })
    .click();
  expect(state.installs).toBe(1);
});

test("changed import requires a fresh review and operators cannot configure catalogs", async ({
  page,
}) => {
  const state = await setup(page);
  state.stale = true;
  const dialog = await actorSetup(page);
  await dialog.getByLabel("Imported catalog commit").selectOption(revision);
  await dialog
    .getByLabel("I reviewed this commit and authorize installation", {
      exact: false,
    })
    .check();
  await dialog.getByRole("button", { name: "Install pinned catalog" }).click();
  await expect(dialog.getByRole("alert")).toHaveText(
    "Imported catalog changed. Reload and review the selected revision again",
  );
  await dialog.getByRole("button", { name: "Close catalog setup" }).click();
  await dialog
    .getByRole("button", { name: "Configure catalog", exact: true })
    .click();
  await expect(
    dialog.getByLabel("I reviewed this commit and authorize installation", {
      exact: false,
    }),
  ).not.toBeChecked();
  expect(state.installs).toBe(0);
});

test("operators see catalog status but no administration controls or option requests", async ({
  page,
}) => {
  const state = await setup(page, true, false);
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-actor-fixture", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await expect(
    dialog.getByRole("button", { name: "Configure catalog", exact: true }),
  ).toHaveCount(0);
  expect(state.options).toBe(0);
});
