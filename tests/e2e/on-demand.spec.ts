import { expect, test, type Page } from "@playwright/test";

const actorId = "18d1910c-9720-4dba-bb38-f0425752f487";
const guid = "dff63ce4-d339-432f-ab82-ac97d9b5ad04";
const revision = "a".repeat(40);
async function setup(page: Page) {
  const profile = {
    id: "22a2ad18-aa67-49ad-a097-54b8251fa1d7",
    actor_id: actorId,
    profile_key: "standard-user",
    display_name: "Standard user",
    account: "atomic-user",
    expected_sid: "uid:1001",
    privilege: "standard",
    logon_type: "systemd",
    enabled: true,
    healthy: true,
  };
  const actor = {
    id: actorId,
    hostname: "on-demand-fixture",
    registration_state: "enrolled",
    os: "linux",
    os_version: "Linux fixture",
    online: true,
    enabled: true,
    last_heartbeat: Date.now() / 1000,
    health: "healthy",
    revision: "",
    delivery_mode: "on_demand",
    artifact_protocol: 1,
    agent_version: "0.2.0",
    active_job: null,
    profiles: [profile],
  };
  const atomic = {
    guid,
    technique: "T1082",
    name: "One test fixture",
    revision,
    content_sha256: "b".repeat(64),
    approved: false,
    risk_level: "unreviewed",
    allowed_profiles: [],
    active: true,
    execution_ready: true,
    catalog_source: "github",
    source_path: "atomics/T1082/T1082.yaml",
    artifact: null as unknown,
    file_plan: null as unknown,
    artifact_approved: false,
    definition: {
      description: "UI fixture; never executes",
      technique_name: "System information",
      supported_platforms: ["linux"],
      executor: { name: "bash", command: "printf fixture" },
      input_arguments: {},
    },
  };
  const artifact = {
    protocol: 1,
    digest: "c".repeat(64),
    manifest_hash: "d".repeat(64),
    signature: "fixture signature",
    size: 1234,
    manifest: {
      files: [
        { path: "atomics/T1082/T1082.yaml", size: 200, sha256: "e".repeat(64) },
      ],
    },
  };
  const state = {
    prepares: 0,
    reviews: 0,
    packages: 0,
    actor,
    atomic,
    artifact,
    runs: [] as Record<string, unknown>[],
    reconciles: 0,
  };
  const paged = (items: unknown[]) => ({
    items,
    total: items.length,
    offset: 0,
    limit: 200,
  });
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (req.method() === "GET") {
      if (path === "/me")
        return route.fulfill({
          json: {
            subject: "admin-fixture",
            username: "admin",
            roles: ["viewer", "operator", "administrator"],
            approval_mode: "catalog",
            mode: "real",
            dev_auth: false,
          },
        });
      if (path === "/actors") return route.fulfill({ json: paged([actor]) });
      if (path === `/actors/${actorId}`) return route.fulfill({ json: actor });
      if (path === `/actors/${actorId}/profiles`)
        return route.fulfill({ json: [profile] });
      if (path === "/tests") return route.fulfill({ json: paged([atomic]) });
      if (path === `/tests/${guid}`) return route.fulfill({ json: atomic });
      if (path === `/tests/${guid}/artifact`)
        return route.fulfill({
          json: {
            file_plan: atomic.file_plan,
            artifact: atomic.artifact,
            suggested_assets: [],
            error: "",
          },
        });
      if (path === "/agents/package-options")
        return route.fulfill({
          json: {
            mode: "real",
            api_url: "https://control.example.test",
            enrollment_available: true,
            revisions: [revision],
            token_lifetime_seconds: 600,
          },
        });
      if (path === "/runs") return route.fulfill({ json: paged(state.runs) });
      if (["/audit", "/approvals"].includes(path))
        return route.fulfill({ json: paged([]) });
    }
    if (req.method() === "POST" && path === `/tests/${guid}/artifact/prepare`) {
      expect(req.postDataJSON()).toEqual({
        content_sha256: atomic.content_sha256,
        source_revision: revision,
        asset_paths: [],
        files: [],
      });
      state.prepares++;
      atomic.artifact = artifact;
      return route.fulfill({ json: { artifact } });
    }
    if (req.method() === "POST" && path === `/tests/${guid}/review`) {
      expect(req.postDataJSON().artifact_digest).toBeUndefined();
      expect(req.postDataJSON().content_sha256).toBe(atomic.content_sha256);
      atomic.file_plan = {
        hash: "f".repeat(64),
        manifest: artifact.manifest,
        packaging_version: 1,
      };
      state.reviews++;
      atomic.approved = true;
      atomic.artifact_approved = true;
      atomic.allowed_profiles = ["standard-user"] as never[];
      return route.fulfill({ json: { approved: true } });
    }
    if (
      req.method() === "POST" &&
      path === `/actors/${actorId}/agent-package`
    ) {
      expect(req.postDataJSON().delivery_mode).toBe("on_demand");
      expect(req.postDataJSON().catalog_revision).toBe("");
      expect(req.postDataJSON().include_enrollment).toBe(false);
      state.packages++;
      return route.fulfill({
        body: Buffer.from("fixture ZIP"),
        headers: {
          "Content-Type": "application/zip",
          "Content-Disposition": 'attachment; filename="fixture.zip"',
          "X-Package-Mode": "configuration_only",
          "X-Package-SHA256": "f".repeat(64),
        },
      });
    }
    if (req.method() === "POST" && path.endsWith("/retry-preparation")) {
      expect(req.postDataJSON().reason.length).toBeGreaterThanOrEqual(8);
      const old = state.runs[0];
      const retry = {
        ...old,
        run_id: "e5d8b6c9-6881-4d05-8811-612d4101685f",
        status: "preparing",
        preparation: {
          status: "building",
          attempts: 1,
          retry_at: 0,
          error: "",
          code: "",
        },
      };
      state.runs.push(retry);
      return route.fulfill({ json: retry });
    }
    if (req.method() === "POST" && path.endsWith("/reconcile")) {
      expect(req.postDataJSON().workspace_removed).toBe(true);
      state.reconciles++;
      state.runs[0].workspace_status = "purged";
      return route.fulfill({
        json: { reconciled: true, status: "inconclusive" },
      });
    }
    return route.fulfill({
      status: 404,
      json: { error: { message: `Unexpected fixture path ${path}` } },
    });
  });
  await page.goto("/");
  return state;
}

test("administrator approves supporting files without a separate preparation action", async ({
  page,
}) => {
  const state = await setup(page);
  await page.getByRole("button", { name: "Test Catalog", exact: true }).click();
  await page
    .getByRole("button", { name: "One test fixture", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("button", { name: "Prepare test files", exact: true }),
  ).toHaveCount(0);
  await dialog.getByLabel("Standard User", { exact: true }).check();
  await dialog
    .getByRole("button", { name: "Approve test", exact: true })
    .click();
  await expect(
    dialog.getByText("Supporting files approved.", { exact: false }),
  ).toBeVisible();
  expect(state.prepares).toBe(0);
  expect(state.reviews).toBe(1);
  await page.screenshot({ path: "artifacts/on-demand-test-files.png" });
});

test("on-demand actor needs no catalog pin and removal failure is visible", async ({
  page,
}) => {
  const state = await setup(page);
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "on-demand-fixture", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await expect(
    dialog.getByText("On-demand ready", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByText("No verified catalog revision reported", { exact: true }),
  ).toHaveCount(0);
  Object.assign(state.actor, { workspace_status: "purge_failed" });
  await expect(
    dialog.getByText("Downloaded files could not be removed.", {
      exact: false,
    }),
  ).toBeVisible({ timeout: 10000 });
});

test("package wizard defaults to on-demand and preserves enrollment during an update", async ({
  page,
}) => {
  const state = await setup(page);
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "Generate agent", exact: false })
    .first()
    .click();
  const dialog = page.getByRole("dialog", { name: "Generate Linux agent" });
  await expect(dialog.getByLabel("Test delivery", { exact: true })).toHaveValue(
    "on_demand",
  );
  await expect(
    dialog.getByLabel("Pinned catalog revision", { exact: true }),
  ).toHaveCount(0);
  const download = page.waitForEvent("download");
  await dialog
    .getByRole("button", { name: "Generate and download ZIP", exact: true })
    .click();
  await download;
  await expect(
    dialog.getByText("--enable-on-demand --check-only", { exact: false }),
  ).toBeVisible();
  expect(state.packages).toBe(1);
});

test("administrator recovery requires explicit confirmation of host file removal", async ({
  page,
}) => {
  const state = await setup(page);
  const runId = "71d44155-5540-448b-a81b-a8e8a1173884";
  state.runs.push({
    run_id: runId,
    actor_id: actorId,
    execution_profile_id: state.actor.profiles[0].id,
    status: "inconclusive",
    action: "execute",
    workspace_status: "purge_failed",
    created_at: Date.now() / 1000,
    updated_at: Date.now() / 1000,
    requested_by: "operator-fixture",
    reason: "Isolated UI fixture only",
    result: null,
    parent_id: null,
    cancel_requested: false,
    cleanup_status: "not_requested",
    events: [],
    snapshot: {
      test_name: "Recovery fixture",
      technique: "T1082",
      atomic_guid: guid,
      hostname: state.actor.hostname,
      account: "atomic-user",
      expected_sid: "uid:1001",
      privilege: "standard",
      action: "execute",
      source_revision: revision,
      content_sha256: state.atomic.content_sha256,
      risk_level: "low",
      definition: state.atomic.definition,
      timeout_seconds: 120,
      profile_key: "standard-user",
      artifact: state.artifact,
    },
  });
  await page
    .getByRole("button", { name: "Execution History", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Recovery fixture", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Reconcile actor", exact: true })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Reconcile uncertain execution",
  });
  await dialog
    .getByLabel("Decision reason", { exact: true })
    .fill("Independent host inspection completed");
  await expect(
    dialog.getByRole("button", { name: "Confirm", exact: true }),
  ).toBeDisabled();
  await dialog.getByLabel("I independently verified", { exact: false }).check();
  await dialog.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.reconciles).toBe(1);
});

test("single-run preparation progress and retry are part of execution history", async ({
  page,
}) => {
  const state = await setup(page);
  state.runs.push({
    run_id: "6e872a50-25b4-492c-b5ff-1ebc833ca7df",
    actor_id: actorId,
    execution_profile_id: state.actor.profiles[0].id,
    status: "preparing",
    action: "execute",
    workspace_status: "not_required",
    created_at: Date.now() / 1000,
    updated_at: Date.now() / 1000,
    requested_by: "operator-fixture",
    reason: "Automatic preparation UI fixture",
    result: null,
    parent_id: null,
    cancel_requested: false,
    cleanup_status: "not_requested",
    events: [],
    preparation: {
      status: "building",
      attempts: 1,
      retry_at: 0,
      error: "",
      code: "",
    },
    snapshot: {
      test_name: "Automatic packaging fixture",
      technique: "T1082",
      atomic_guid: guid,
      hostname: state.actor.hostname,
      account: "atomic-user",
      expected_sid: "uid:1001",
      privilege: "standard",
      action: "execute",
      source_revision: revision,
      content_sha256: state.atomic.content_sha256,
      risk_level: "low",
      definition: state.atomic.definition,
      timeout_seconds: 120,
      profile_key: "standard-user",
      file_plan: { hash: "f".repeat(64), packaging_version: 1 },
    },
  });
  await page
    .getByRole("button", { name: "Execution History", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Automatic packaging fixture", exact: true })
    .click();
  let dialog = page.getByRole("dialog", { name: "Execution evidence" });
  await expect(
    dialog.getByRole("heading", {
      name: "Automatic test preparation",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Retry preparation", exact: true }),
  ).toHaveCount(0);
  Object.assign(state.runs[0], {
    status: "preparation_failed",
    preparation: {
      status: "failed",
      attempts: 3,
      retry_at: 0,
      error: "Source temporarily unavailable",
      code: "preparation_unavailable",
    },
  });
  await expect(
    dialog.getByRole("button", { name: "Retry preparation", exact: true }),
  ).toBeVisible({ timeout: 10000 });
  await dialog
    .getByRole("button", { name: "Retry preparation", exact: true })
    .click();
  const decision = page.getByRole("dialog", {
    name: "Retry preparation",
    exact: true,
  });
  await decision
    .getByLabel("Decision reason", { exact: true })
    .fill("Retry after source connectivity was restored");
  await decision.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(decision).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Prepare test files", exact: true }),
  ).toHaveCount(0);
  expect(state.prepares).toBe(0);
});
