import { expect, test, type Page } from "@playwright/test";
import type { Actor } from "../../apps/frontend/src/types";

const actorId = "17b05e1d-bc52-4659-bb26-65d99c527dbc";
const hostname = "linux-retirement-fixture";

async function setup(
  page: Page,
  {
    administrator = true,
    busy = false,
    blocked = false,
    optionalReason = false,
  } = {},
) {
  const actor: Actor = {
    id: actorId,
    hostname,
    os: "linux",
    os_version: "Linux fixture",
    registration_state: "enrolled",
    agent_version: "0.1.0",
    revision: "a".repeat(40),
    enabled: true,
    online: true,
    last_heartbeat: Date.now() / 1000,
    health: "healthy",
    active_job: busy ? "7a854eb0-d513-4c80-a62e-eed08a87ce11" : null,
    simulated: false,
    profiles: [
      {
        id: "5d3db49d-4a3c-4b6c-830a-e4fc4d11c23f",
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
  };
  const state = { writes: 0, archiveReads: 0, retired: false };
  const paged = (items: unknown[]) => ({
    items,
    total: items.length,
    limit: 200,
    offset: 0,
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace("/api/v1", "");
    if (request.method() === "GET") {
      if (path === "/me")
        return route.fulfill({
          json: {
            subject: "human-retirement-admin",
            roles: administrator
              ? ["viewer", "administrator"]
              : ["viewer", "operator"],
            mode: "real",
            dev_auth: false,
            approval_mode: "catalog",
          },
        });
      if (path === "/actors") {
        if (url.searchParams.get("include_retired") === "true") {
          state.archiveReads++;
          return route.fulfill({ json: paged(state.retired ? [] : [actor]) });
        }
        return route.fulfill({
          json: paged(state.retired ? [] : [actor]),
        });
      }
      if (path === `/actors/${actorId}`) return route.fulfill({ json: actor });
      if (path === `/actors/${actorId}/profiles`)
        return route.fulfill({ json: actor.profiles });
      if (["/tests", "/runs", "/audit", "/approvals"].includes(path))
        return route.fulfill({ json: paged([]) });
    }
    if (request.method() === "POST" && path === `/actors/${actorId}/retire`) {
      expect(administrator).toBe(true);
      state.writes++;
      const body = request.postDataJSON();
      expect(body.hostname).toBe(hostname);
      expect(body.reason).toBe(
        optionalReason
          ? ""
          : "Host decommissioned after approved lab validation",
      );
      if (blocked)
        return route.fulfill({
          status: 409,
          json: {
            error: {
              code: "actor_busy",
              message:
                "Reconcile uncertain outcomes before retiring this actor",
            },
          },
        });
      state.retired = true;
      return route.fulfill({
        json: {
          id: actorId,
          hostname,
          deleted: true,
          deleted_at: Date.now() / 1000,
          deleted_by: "human-retirement-admin",
          reason: body.reason,
        },
      });
    }
    await route.abort();
    throw new Error(
      `Unexpected retirement UI request: ${request.method()} ${path}`,
    );
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page.getByRole("button", { name: hostname, exact: true }).click();
  return state;
}

async function fillConfirmation(page: Page) {
  const modal = page.getByRole("dialog", { name: "Delete actor", exact: true });
  await modal
    .getByLabel("Deletion reason")
    .fill("Host decommissioned after approved lab validation");
  await modal.getByLabel(`Type ${hostname} to confirm`).fill(hostname);
  return modal;
}

test("administrator confirms permanent deletion and the actor leaves registered hosts", async ({
  page,
}) => {
  const state = await setup(page);
  const details = page.getByRole("dialog", { name: "Actor details" });
  await details
    .getByRole("button", { name: "Delete actor…", exact: true })
    .click();
  const confirm = page.getByRole("dialog", {
    name: "Delete actor",
    exact: true,
  });
  await expect(
    confirm.getByRole("button", { name: "Permanently delete actor" }),
  ).toBeDisabled();
  await confirm
    .getByLabel("Deletion reason")
    .fill("Host decommissioned after approved lab validation");
  await confirm.getByLabel(`Type ${hostname} to confirm`).fill("wrong-host");
  await expect(
    confirm.getByRole("button", { name: "Permanently delete actor" }),
  ).toBeDisabled();
  expect(state.writes).toBe(0);
  await confirm.getByRole("button", { name: "Cancel deletion" }).click();
  expect(state.writes).toBe(0);
  await details
    .getByRole("button", { name: "Delete actor…", exact: true })
    .click();
  await expect(page.getByLabel("Deletion reason")).toHaveValue("");
  await fillConfirmation(page);
  await expect(
    page.getByText("The hostname can be reused", { exact: false }),
  ).toBeVisible();
  await page.screenshot({ path: "artifacts/actor-delete-confirmation.png" });
  await page.getByRole("button", { name: "Permanently delete actor" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(state.writes).toBe(1);
  await expect(
    page.getByRole("button", { name: hostname, exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText(
      `Actor ${hostname} deleted. Its hostname is available for reuse; history is preserved.`,
    ),
  ).toBeVisible();
  await expect(page.getByLabel("Show previously retired actors")).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: hostname, exact: true }),
  ).toHaveCount(0);
  await page.screenshot({ path: "artifacts/deleted-actor-ui.png" });
  expect(state.archiveReads).toBe(0);
});

test("retirement remains blocked when the server reports an uncertain execution", async ({
  page,
}) => {
  const state = await setup(page, { blocked: true });
  await page
    .getByRole("button", { name: "Delete actor…", exact: true })
    .click();
  const confirm = await fillConfirmation(page);
  await confirm
    .getByRole("button", { name: "Permanently delete actor" })
    .click();
  await expect(confirm.getByRole("alert")).toHaveText(
    "Reconcile uncertain outcomes before retiring this actor",
  );
  await expect(confirm).toBeVisible();
  expect(state.retired).toBe(false);
  expect(state.writes).toBe(1);
});

test("active work disables retirement before confirmation", async ({
  page,
}) => {
  const state = await setup(page, { busy: true });
  await expect(
    page.getByRole("button", { name: "Delete actor…", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByText("Finish or cancel the active execution", { exact: false }),
  ).toBeVisible();
  expect(state.writes).toBe(0);
});

test("operators cannot see the retirement action", async ({ page }) => {
  const state = await setup(page, { administrator: false });
  await expect(
    page.getByRole("button", { name: "Delete actor…", exact: true }),
  ).toHaveCount(0);
  expect(state.writes).toBe(0);
});

test("deletion reason is optional for current actors", async ({ page }) => {
  const state = await setup(page, { optionalReason: true });
  await page
    .getByRole("button", { name: "Delete actor…", exact: true })
    .click();
  const confirm = page.getByRole("dialog", {
    name: "Delete actor",
    exact: true,
  });
  await expect(
    confirm.getByLabel("Deletion reason (optional)", { exact: true }),
  ).toHaveValue("");
  await confirm.getByLabel(`Type ${hostname} to confirm`).fill(hostname);
  await expect(
    confirm.getByRole("button", { name: "Permanently delete actor" }),
  ).toBeEnabled();
  await confirm
    .getByRole("button", { name: "Permanently delete actor" })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(state.writes).toBe(1);
});
