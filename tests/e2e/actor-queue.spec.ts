import { expect, test, type Page } from "@playwright/test";
import type {
  Actor,
  AtomicTest,
  RunBatch,
} from "../../apps/frontend/src/types";
const actorId = "f0000000-0000-4000-8000-000000000001",
  profileId = "f0000000-0000-4000-8000-000000000002",
  batchId = "f0000000-0000-4000-8000-000000000003";
const catalog: AtomicTest[] = Array.from({ length: 55 }, (_, i) => ({
  guid: `00000000-0000-4000-8000-${String(i + 1).padStart(12, "0")}`,
  name: `Queue fixture ${String(i + 1).padStart(2, "0")}`,
  technique: "T1016.001",
  catalog_source: "local",
  source_path: "",
  active: true,
  approved: true,
  execution_ready: true,
  risk_level: "low",
  allowed_profiles: ["standard-user"],
  revision: "a".repeat(40),
  content_sha256: "b".repeat(64),
  definition: {
    description: "Synthetic browser fixture",
    technique_name: "Internet connection discovery",
    supported_platforms: ["linux"],
    executor: { name: "bash", command: "not executed" },
    input_arguments: {},
  },
}));
const actor: Actor = {
  id: actorId,
  hostname: "queue-fixture-host",
  os: "linux",
  os_version: "Linux fixture",
  registration_state: "enrolled",
  enabled: true,
  online: true,
  health: "healthy",
  agent_version: "0.1.0",
  last_heartbeat: Date.now() / 1000,
  revision: "a".repeat(40),
  active_job: null,
  profiles: [
    {
      id: profileId,
      actor_id: actorId,
      profile_key: "standard-user",
      display_name: "Standard user",
      account: "atomic-user",
      expected_sid: "uid:1001",
      privilege: "standard",
      logon_type: "systemd",
      enabled: true,
      healthy: true,
    },
  ],
};
const paged = (items: unknown[]) => ({
  items,
  total: items.length,
  limit: 200,
  offset: 0,
});
async function setup(
  page: Page,
  { viewer = false, failFirst = false, preloaded = false } = {},
) {
  const state = {
    submissions: [] as { body: Record<string, any>; key: string }[],
    previews: [] as Record<string, any>[],
    controls: [] as string[],
    historyBatch: "",
    batch: null as RunBatch | null,
  };
  const makeBatch = (
    guids = catalog.slice(0, 3).map((t) => t.guid),
  ): RunBatch => ({
    id: batchId,
    actor_id: actorId,
    hostname: actor.hostname,
    execution_profile_id: profileId,
    name: "Network discovery batch",
    reason: "Authorized browser fixture validation",
    requested_by: "fixture:operator",
    approval_mode: "catalog",
    failure_policy: "pause",
    paused: false,
    pause_reason: "",
    cancelled: false,
    status: "queued",
    created_at: Date.now() / 1000,
    expires_at: Date.now() / 1000 + 86400,
    total: guids.length,
    finished: 0,
    counts: { queued: guids.length },
    items: guids.map((guid, i) => ({
      run_id: guid,
      guid,
      name: catalog.find((t) => t.guid === guid)!.name,
      technique: "T1016.001",
      status: "queued",
      queue_position: i + 1,
      risk_level: "low",
    })),
  });
  if (preloaded) state.batch = makeBatch();
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname.replace("/api/v1", "");
    if (request.method() === "GET") {
      if (path === "/me")
        return route.fulfill({
          json: {
            subject: "fixture:operator",
            roles: viewer ? ["viewer"] : ["viewer", "operator"],
            mode: "real",
            dev_auth: false,
            approval_mode: "catalog",
          },
        });
      if (path === "/tests") return route.fulfill({ json: paged(catalog) });
      if (path === "/actors") return route.fulfill({ json: paged([actor]) });
      if (path === `/actors/${actorId}/profiles`)
        return route.fulfill({ json: actor.profiles });
      if (path === `/actors/${actorId}/queue`)
        return route.fulfill({ json: paged(state.batch ? [state.batch] : []) });
      if (path === "/runs") {
        state.historyBatch = url.searchParams.get("batch_id") ?? "";
        return route.fulfill({ json: paged([]) });
      }
      if (["/audit", "/approvals"].includes(path))
        return route.fulfill({ json: paged([]) });
    }
    if (
      request.method() === "POST" &&
      path === `/actors/${actorId}/queue/preview`
    ) {
      expect(viewer).toBe(false);
      const body = request.postDataJSON();
      state.previews.push(body);
      return route.fulfill({
        json: {
          preview_hash: "c".repeat(64),
          selected_count: body.atomic_guids.length,
          eligible_count: body.atomic_guids.length - 1,
          items: body.atomic_guids.map((guid: string, i: number) => ({
            guid,
            name: catalog.find((t) => t.guid === guid)!.name,
            technique: "T1016.001",
            eligible: i !== 1,
            risk_level: i === 1 ? "unavailable" : "low",
            error: i === 1 ? "incompatible_profile" : "",
            message:
              i === 1
                ? "Test is not approved for this platform and profile"
                : "",
          })),
        },
      });
    }
    if (request.method() === "POST" && path === `/actors/${actorId}/queue`) {
      expect(viewer).toBe(false);
      state.submissions.push({
        body: request.postDataJSON(),
        key: request.headers()["idempotency-key"],
      });
      if (failFirst && state.submissions.length === 1)
        return route.fulfill({
          status: 503,
          json: {
            error: {
              code: "temporary_failure",
              message: "Retry the same request",
            },
          },
        });
      state.batch = makeBatch(
        state.submissions
          .at(-1)!
          .body.atomic_guids.filter((_: string, i: number) => i !== 1),
      );
      return route.fulfill({ status: 201, json: state.batch });
    }
    if (
      request.method() === "POST" &&
      path.startsWith(`/run-batches/${batchId}/`)
    ) {
      expect(viewer).toBe(false);
      const action = path.split("/").at(-1)!;
      state.controls.push(action);
      state.batch!.paused = action === "pause";
      state.batch!.cancelled = action === "cancel";
      state.batch!.pause_reason = action === "pause" ? "manual" : "";
      state.batch!.status =
        action === "pause"
          ? "paused"
          : action === "cancel"
            ? "cancelled"
            : "queued";
      return route.fulfill({ json: state.batch });
    }
    await route.abort();
    throw new Error(
      `Unexpected queue fixture request: ${request.method()} ${path}`,
    );
  });
  await page.goto("/");
  return state;
}
async function builder(page: Page) {
  await page.getByRole("button", { name: "Test Catalog", exact: true }).click();
  await page.getByLabel("Search catalog").fill("T1016.001");
  await page
    .getByRole("button", { name: "Select all 55 results", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Queue selected tests", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Build actor queue" });
  await dialog.getByLabel("Queue actor").selectOption(actorId);
  await dialog
    .getByLabel("Execution profile", { exact: true })
    .selectOption(profileId);
  await dialog
    .getByLabel("Execution reason")
    .fill("Authorized browser fixture validation");
  await dialog.getByLabel("Batch name").fill("Network discovery batch");
  return dialog;
}
test("select all results across pages, reorder, preview exclusions and submit", async ({
  page,
}) => {
  const state = await setup(page);
  await page.getByRole("button", { name: "Test Catalog", exact: true }).click();
  await page.getByLabel("Select Queue fixture 01", { exact: true }).check();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByLabel("Select Queue fixture 55", { exact: true }).check();
  await expect(page.getByText("2 selected", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Previous", exact: true }).click();
  await expect(
    page.getByLabel("Select Queue fixture 01", { exact: true }),
  ).toBeChecked();
  const dialog = await builder(page);
  await expect(dialog.getByText("Execution order · 55 selected")).toBeVisible();
  await dialog
    .getByRole("button", { name: "Move Queue fixture 01 down", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "Preview eligibility", exact: true })
    .click();
  await expect(dialog.getByText("54 eligible · 1 excluded")).toBeVisible();
  await expect(
    dialog.getByText("Test is not approved for this platform and profile", {
      exact: true,
    }),
  ).toBeVisible();
  expect(state.previews[0].atomic_guids).toHaveLength(55);
  expect(state.submissions).toHaveLength(0);
  await page.screenshot({
    path: "artifacts/actor-queue-preview.png",
    fullPage: true,
  });
  await dialog
    .getByRole("button", { name: "Queue 54 eligible tests", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", { name: "Actor details" }),
  ).toBeVisible();
  await expect(
    page.getByText("Queued 54 tests on queue-fixture-host.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Network discovery batch" }),
  ).toBeVisible();
  expect(state.submissions).toHaveLength(1);
  expect(state.submissions[0].body.atomic_guids).toEqual(
    state.previews[0].atomic_guids,
  );
  expect(state.submissions[0].body.preview_hash).toBe("c".repeat(64));
  expect(state.submissions[0].body.failure_policy).toBe("continue");
  await page.screenshot({
    path: "artifacts/actor-queue-progress.png",
    fullPage: true,
  });
});
test("retry reuses the exact idempotency key and payload", async ({ page }) => {
  const state = await setup(page, { failFirst: true });
  const dialog = await builder(page);
  await dialog
    .getByRole("button", { name: "Preview eligibility", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "Queue 54 eligible tests", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toHaveText("Retry the same request");
  await dialog
    .getByRole("button", { name: "Queue 54 eligible tests", exact: true })
    .click();
  await expect(dialog).toHaveCount(0);
  expect(state.submissions).toHaveLength(2);
  expect(state.submissions[0]).toEqual(state.submissions[1]);
});
test("changing selection or identity invalidates the preview", async ({
  page,
}) => {
  const state = await setup(page);
  const dialog = await builder(page);
  await dialog
    .getByRole("button", { name: "Preview eligibility", exact: true })
    .click();
  await expect(
    dialog.getByRole("button", {
      name: "Queue 54 eligible tests",
      exact: true,
    }),
  ).toBeVisible();
  await dialog
    .getByRole("button", { name: "Remove Queue fixture 01", exact: true })
    .click();
  await expect(
    dialog.getByRole("button", { name: /Queue \d+ eligible tests/ }),
  ).toHaveCount(0);
  await dialog
    .getByRole("button", { name: "Preview eligibility", exact: true })
    .click();
  await expect(
    dialog.getByRole("button", {
      name: "Queue 53 eligible tests",
      exact: true,
    }),
  ).toBeVisible();
  await dialog.getByLabel("Queue actor").selectOption("");
  await expect(
    dialog.getByRole("button", { name: /Queue \d+ eligible tests/ }),
  ).toHaveCount(0);
  expect(state.submissions).toHaveLength(0);
});
test("operator controls batches and opens filtered history", async ({
  page,
}) => {
  const state = await setup(page, { preloaded: true });
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page.getByRole("button", { name: actor.hostname, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await dialog.getByRole("button", { name: "View queue", exact: true }).click();
  await dialog
    .getByRole("button", { name: "Pause batch", exact: true })
    .click();
  await expect(
    dialog.getByText("Paused: manual.", { exact: false }),
  ).toBeVisible();
  await dialog
    .getByRole("button", { name: "Resume batch", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "Cancel remaining", exact: true })
    .click();
  await expect(dialog.getByText("cancelled", { exact: true })).toBeVisible();
  expect(state.controls).toEqual(["pause", "resume", "cancel"]);
  await dialog
    .getByRole("button", { name: "View batch history", exact: true })
    .click();
  await expect(
    page.getByText("Batch: Network discovery batch", { exact: true }),
  ).toBeVisible();
  await expect.poll(() => state.historyBatch).toBe(batchId);
  await page
    .getByRole("button", { name: "Show all runs", exact: true })
    .click();
  await expect.poll(() => state.historyBatch).toBe("");
});
test("viewer can inspect but cannot select, submit or control work", async ({
  page,
}) => {
  const state = await setup(page, { viewer: true, preloaded: true });
  await page.getByRole("button", { name: "Test Catalog", exact: true }).click();
  await expect(page.getByLabel("Select current page")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Queue selected tests", exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page.getByRole("button", { name: actor.hostname, exact: true }).click();
  await page.getByRole("button", { name: "View queue", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Network discovery batch", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Pause batch", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Cancel remaining", exact: true }),
  ).toHaveCount(0);
  expect(state.controls).toHaveLength(0);
  expect(state.submissions).toHaveLength(0);
});

test("queue submission accepts an empty execution reason", async ({ page }) => {
  const state = await setup(page);
  const dialog = await builder(page);
  await dialog.getByLabel("Execution reason").fill("");
  await dialog
    .getByRole("button", { name: "Preview eligibility", exact: true })
    .click();
  const submit = dialog.getByRole("button", {
    name: /Queue \d+ eligible tests/,
  });
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect(dialog).not.toBeVisible();
  expect(state.submissions[0].body.reason).toBe("");
});
