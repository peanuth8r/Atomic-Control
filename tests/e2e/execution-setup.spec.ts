import { test, expect, type Page } from "@playwright/test";
import type { Actor, AtomicTest, Profile } from "../../apps/frontend/src/types";

const actorId = "eb382b00-95e5-4c89-a7c3-22305dc27c1b";
const profileId = "23f234cc-a7f4-435c-b929-cb9d5417da8e";
const guid = "6c1225f0-3273-4830-b426-f7aa8bb7a5c8";
const revision = "a".repeat(40);

async function isolatedSetup(
  page: Page,
  administrator = true,
  withProfile = false,
  stale = false,
  approvalMode: "per_run" | "catalog" = "per_run",
  managedProfiles = false,
) {
  const profile: Profile = {
    id: profileId,
    actor_id: actorId,
    profile_key: "standard-user",
    display_name: "Linux standard user",
    account: "atomic-user",
    expected_sid: "uid:1001",
    privilege: "standard",
    logon_type: "systemd",
    enabled: true,
    healthy: approvalMode === "catalog",
  };
  const actor: Actor = {
    id: actorId,
    hostname: "linux-host-fixture",
    os: "linux",
    os_version: "Linux",
    online: true,
    enabled: true,
    registration_state: "enrolled",
    agent_version: "0.1.0",
    last_heartbeat: Date.now() / 1000,
    revision: withProfile ? revision : "",
    health: "healthy",
    active_job: null,
    profiles: withProfile ? [profile] : [],
    simulated: false,
    profile_sync: {
      supported: true,
      protocol: managedProfiles ? 1 : 0,
      status: "not_configured",
      generation: 0,
      updated_at: null,
      results: {},
      error: "",
    },
  };
  const atomic: AtomicTest = {
    guid,
    technique: "T1005",
    name: "Reviewed Linux fixture",
    revision,
    content_sha256: "a".repeat(64),
    definition: {
      description: "UI-only fixture",
      technique_name: "Data from Local System",
      supported_platforms: ["linux"],
      executor: {
        name: "bash",
        command: "printf 'fixture'",
        elevation_required: false,
      },
      input_arguments: {},
    },
    approved: true,
    risk_level: "low",
    allowed_profiles: ["standard-user"],
    active: true,
    execution_ready: true,
    simulated: false,
    catalog_source: "local",
    source_path: "fixture.yaml",
  };
  const state = {
    profileWrites: 0,
    previews: 0,
    accessWrites: 0,
    accessReads: 0,
    grantCount: 0,
    runRequests: 0,
    syncWrites: 0,
    profileDeletes: [] as string[],
    packageWrites: 0,
    actor,
    extraActors: [] as Actor[],
  };
  let operation = "grant";
  let grant = {
    id: "b".repeat(64),
    subject: "human-ui-admin",
    actions: ["execute"],
    actors: [actorId],
    profiles: [profileId],
    tests: [guid],
    risks: ["low"],
  };
  const access = () => ({
    configured: approvalMode === "per_run",
    version: "a".repeat(64),
    grants: state.grantCount ? [grant] : [],
    message:
      approvalMode === "catalog"
        ? "Catalog approval authorizes operator requests. No separate execution-access grants are needed."
        : "Roles and human approval remain required.",
  });
  const paged = (items: unknown[]) => ({
    items,
    total: items.length,
    limit: 200,
    offset: 0,
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    const method = request.method();
    if (method === "GET") {
      if (path === "/admin/agent-settings")
        return route.fulfill({ json: { enrollment_token_minutes: 60 } });
      if (path === "/me")
        return route.fulfill({
          json: {
            subject: "human-ui-admin",
            roles: administrator
              ? ["viewer", "operator", "administrator"]
              : ["viewer", "operator"],
            mode: "real",
            approval_mode: approvalMode,
            dev_auth: false,
          },
        });
      if (path === "/actors")
        return route.fulfill({ json: paged([actor, ...state.extraActors]) });
      if (path === `/actors/${actorId}`) return route.fulfill({ json: actor });
      if (path === `/actors/${actorId}/profiles`)
        return route.fulfill({ json: actor.profiles });
      if (path === "/tests") return route.fulfill({ json: paged([atomic]) });
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
            public_ca: {
              filename: "atomic-control-ca.crt",
              subject: "CN=Fixture control-plane CA",
              sha256: "A1".repeat(32),
              not_after: "2027-11-22T00:00:00+00:00",
              store: "LocalMachine\\Root",
            },
          },
        });
      if (["/runs", "/audit", "/approvals"].includes(path))
        return route.fulfill({ json: paged([]) });
      if (path === "/admin/users/options")
        return route.fulfill({
          json: {
            available: false,
            provider: "",
            message: "Not configured in this fixture",
            access_levels: [],
            minimum_password_length: 12,
            temporary_password: true,
          },
        });
      if (path === "/execution-access") {
        state.accessReads++;
        return route.fulfill({ json: access() });
      }
    }
    if (
      method === "DELETE" &&
      path.startsWith(`/actors/${actorId}/profiles/`)
    ) {
      expect(administrator).toBe(true);
      const id = path.split("/").pop()!;
      state.profileDeletes.push(id);
      actor.profiles = actor.profiles.filter((profile) => profile.id !== id);
      actor.profile_sync = {
        ...actor.profile_sync!,
        status: "pending",
        generation: actor.profile_sync!.generation + 1,
        updated_at: Date.now() / 1000,
        results: {},
      };
      return route.fulfill({
        json: { id, deleted: true, cancelled_requests: 0 },
      });
    }
    if (method === "POST" && path === `/actors/${actorId}/profile-sync`) {
      expect(administrator && managedProfiles).toBe(true);
      state.syncWrites++;
      actor.profile_sync = {
        supported: true,
        protocol: 1,
        status: "pending",
        generation: 2,
        updated_at: Date.now() / 1000,
        results: {},
        error: "",
      };
      return route.fulfill({ json: actor.profile_sync });
    }
    if (method === "POST" && path === `/actors/${actorId}/agent-package`) {
      expect(request.postDataJSON().include_enrollment).toBe(false);
      state.packageWrites++;
      return route.fulfill({
        body: Buffer.from("UI-only fixture ZIP"),
        headers: {
          "Content-Type": "application/zip",
          "Content-Disposition": 'attachment; filename="fixture.zip"',
          "X-Package-Mode": "configuration_only",
          "X-Package-SHA256": "a".repeat(64),
        },
      });
    }
    if (method === "POST" && path === `/actors/${actorId}/profiles`) {
      expect(administrator).toBe(true);
      expect(request.postDataJSON()).toEqual({
        profile_key: "standard-user",
        display_name: profile.display_name,
        account: "atomic-user",
        expected_sid: "uid:1001",
        privilege: "standard",
      });
      state.profileWrites++;
      actor.profiles = [profile];
      return route.fulfill({ status: 200, json: profile });
    }
    if (method === "POST" && path === "/runs" && approvalMode === "catalog") {
      const body = request.postDataJSON();
      expect(body.atomic_guid).toBe(guid);
      expect(body.actor_id).toBe(actorId);
      expect(body.execution_profile_id).toBe(profileId);
      state.runRequests++;
      return route.fulfill({
        status: 201,
        json: {
          run_id: "e5f7830d-7167-4ea7-bf40-fc35361e79f3",
          actor_id: actorId,
          execution_profile_id: profileId,
          status: "queued",
          approval_required: false,
          authorization_source: "catalog",
          approved_by: "catalog-reviewer-fixture",
          requested_by: "human-ui-admin",
          snapshot: {
            test_name: atomic.name,
            technique: "T1005",
            atomic_guid: guid,
            hostname: actor.hostname,
            account: profile.account,
            expected_sid: profile.expected_sid,
            privilege: "standard",
            action: body.action,
            source_revision: revision,
            content_sha256: atomic.content_sha256,
            risk_level: "low",
            definition: atomic.definition,
            timeout_seconds: 120,
            simulated: false,
            profile_key: "standard-user",
          },
          result: null,
          created_at: Date.now() / 1000,
          updated_at: Date.now() / 1000,
          reason: body.reason,
          action: body.action,
          parent_id: null,
          cancel_requested: false,
          cleanup_status: "not_supported",
          events: [],
        },
      });
    }
    if (method === "POST" && path === "/execution-access/preview") {
      const data = request.postDataJSON();
      operation = data.operation;
      if (operation === "grant") {
        expect(data.actor_id).toBe(actorId);
        expect(data.profile_id).toBe(profileId);
        expect(data.test_guid).toBe(guid);
        grant = { ...grant, subject: data.subject, actions: data.actions };
      }
      state.previews++;
      return route.fulfill({
        json: {
          preview_token: "p".repeat(43),
          expires_at: Date.now() / 1000 + 300,
          operation,
          version: "a".repeat(64),
          grant,
          labels:
            operation === "grant"
              ? {
                  actor: actor.hostname,
                  profile: profile.display_name,
                  account: "atomic-user",
                  identity: "uid:1001",
                  privilege: "standard",
                  test: atomic.name,
                }
              : {},
          test_binding:
            operation === "grant"
              ? { revision, hash: atomic.content_sha256, risk: "low" }
              : null,
        },
      });
    }
    if (method === "POST" && path === "/execution-access/apply") {
      expect(request.postDataJSON().confirmed).toBe(true);
      if (stale)
        return route.fulfill({
          status: 409,
          json: {
            error: {
              code: "policy_changed",
              message: "Execution permissions changed. Reload and review again",
            },
          },
        });
      state.accessWrites++;
      state.grantCount = operation === "grant" ? 1 : 0;
      return route.fulfill({
        json: {
          ...access(),
          message:
            "Execution permissions updated. No execution was requested or approved.",
        },
      });
    }
    await route.abort();
    throw new Error(
      `Unexpected request in isolated UI test: ${method} ${path}`,
    );
  });
  return state;
}

test("register Linux UID profile only after review and explain remaining actor exclusions", async ({
  page,
}) => {
  const state = await isolatedSetup(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await dialog.getByRole("button", { name: "Add execution profile" }).click();
  await dialog
    .getByLabel("Display name", { exact: true })
    .fill("Linux standard user");
  await dialog.getByLabel("Local account", { exact: true }).fill("atomic-user");
  await dialog.getByLabel("Numeric UID", { exact: true }).fill("1001");
  await dialog
    .getByRole("button", { name: "Review execution profile" })
    .click();
  expect(state.profileWrites).toBe(0);
  await expect(
    dialog.getByText("atomic-user · uid:1001", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Register execution profile" }),
  ).toBeDisabled();
  await dialog
    .getByLabel("I verified this account and identity", { exact: false })
    .check();
  await dialog
    .getByRole("button", { name: "Register execution profile" })
    .click();
  await expect(
    dialog.getByText("Profile registered.", { exact: false }),
  ).toBeVisible();
  expect(state.profileWrites).toBe(1);
  await expect(dialog.getByText("unhealthy", { exact: true })).toBeVisible();
  await page.screenshot({ path: "artifacts/execution-profile-ui.png" });
  await dialog.getByRole("button", { name: "Close dialog" }).click();
  await page.getByRole("button", { name: "Execute Test", exact: true }).click();
  await page.getByLabel("Atomic test", { exact: true }).selectOption(guid);
  await page.getByText("Actor eligibility and setup", { exact: true }).click();
  await expect(
    page.getByText("No pinned catalog revision reported", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Matching execution profile is not validated and healthy", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Execution actor", { exact: true }).locator("option"),
  ).toHaveCount(2);
});

test("administrator settings omit execution access controls", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true);
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Authorization", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Execution access", exact: true }),
  ).toHaveCount(0);
  await expect(page.getByLabel("OIDC subject", { exact: true })).toHaveCount(0);
  expect(state.accessReads).toBe(0);
  expect(state.accessWrites).toBe(0);
});

test("operators cannot see profile registration or permission-management controls", async ({
  page,
}) => {
  const state = await isolatedSetup(page, false);
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Add execution profile" }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Close dialog" }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Execution access", exact: true }),
  ).toHaveCount(0);
  expect(state.accessReads).toBe(0);
});

test("catalog approval lets an operator queue an approved test in one submission without access-grant setup", async ({
  page,
}) => {
  const state = await isolatedSetup(page, false, true, false, "catalog");
  await page.goto("/");
  await page.getByRole("button", { name: "Execute Test", exact: true }).click();
  await page.getByLabel("Atomic test", { exact: true }).selectOption(guid);
  await page
    .getByLabel("Execution actor", { exact: true })
    .selectOption(actorId);
  await page
    .getByLabel("Execution identity", { exact: true })
    .selectOption(profileId);
  await expect(page.getByLabel("Testing reason", { exact: false })).toBeEmpty();
  await expect(
    page.getByLabel("Testing reason", { exact: false }),
  ).not.toHaveAttribute("required", "");
  await expect(
    page.getByRole("button", { name: "Approvals", exact: true }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: "Run approved test", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", { name: "Execution evidence" }),
  ).toBeVisible();
  await expect(
    page.getByText("Catalog approved by", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("catalog-reviewer-fixture", { exact: true }),
  ).toBeVisible();
  expect(state.runRequests).toBe(1);
  expect(state.accessReads).toBe(0);
  expect(state.accessWrites).toBe(0);
  expect(state.previews).toBe(0);
});

test("catalog mode retains authorization details without execution access controls", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog");
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(
    page.getByText("Catalog approval", { exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("OIDC subject", { exact: true })).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Execution access", exact: true }),
  ).toHaveCount(0);
  expect(state.accessReads).toBe(0);
  expect(state.accessWrites).toBe(0);
});

test("managed Linux profiles show validation errors, retry and report completion without creating a run", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog", true);
  const rootId = "43bd67e4-ce3c-4da1-9944-610cb8caf636";
  state.actor.profiles.push({
    ...state.actor.profiles[0],
    id: rootId,
    profile_key: "local-admin",
    display_name: "Root",
    account: "root",
    expected_sid: "uid:0",
    privilege: "elevated",
    healthy: false,
  });
  state.actor.profile_sync = {
    supported: true,
    protocol: 1,
    status: "validation_failed",
    generation: 1,
    updated_at: Date.now() / 1000,
    error: "",
    results: { [rootId]: { healthy: false, error: "probe_failed" } },
  };
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await expect(
    dialog
      .getByRole("region", { name: "Execution identity" })
      .getByText("Needs attention", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByText("The identity probe failed.", { exact: false }),
  ).toBeVisible();
  await dialog.getByRole("button", { name: "Retry validation" }).click();
  await expect(
    dialog.getByText(
      "The agent will validate profiles automatically when idle.",
    ),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Retry validation" }),
  ).toHaveCount(0);
  await expect(
    dialog.getByRole("button", { name: "Apply profiles" }),
  ).toHaveCount(0);
  expect(state.syncWrites).toBe(1);
  state.actor.profile_sync = {
    ...state.actor.profile_sync!,
    status: "applied",
    results: {},
  };
  state.actor.profiles[1].healthy = true;
  await expect(
    dialog
      .getByRole("region", { name: "Execution identity" })
      .getByText("Ready", { exact: true }),
  ).toBeVisible({ timeout: 10000 });
  await expect(dialog.getByText("healthy", { exact: true })).toHaveCount(2);
  await page.screenshot({ path: "artifacts/managed-profile-sync-ui.png" });
  expect(state.runRequests).toBe(0);
  expect(state.profileWrites).toBe(0);
});

test("legacy Linux agent offers a configuration-only update and precise one-time commands", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog");
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  await expect(
    page.getByText("Agent upgrade required", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Download agent update" }).click();
  const dialog = page.getByRole("dialog", { name: "Generate Linux agent" });
  await expect(
    dialog.getByLabel("Include a single-use enrollment token", {
      exact: false,
    }),
  ).not.toBeChecked();
  await expect(
    dialog.getByLabel("Include a single-use enrollment token", {
      exact: false,
    }),
  ).toBeDisabled();
  const download = page.waitForEvent("download");
  await dialog
    .getByRole("button", { name: "Generate and download ZIP" })
    .click();
  await download;
  await expect(
    dialog.getByText("Enable managed configuration once", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByText("Update-Agent.py --enable-profile-sync", { exact: false }),
  ).toBeVisible();
  expect(state.packageWrites).toBe(1);
  expect(state.syncWrites).toBe(0);
  expect(state.runRequests).toBe(0);
});

test("newly enrolled Linux actor shows startup instructions instead of an upgrade warning", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog");
  state.actor.last_heartbeat = 0;
  state.actor.online = false;
  state.actor.health = "unknown";
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await expect(
    page.getByText("awaiting heartbeat", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Actor details" });
  await expect(
    dialog.getByText("Enrolled — waiting for first heartbeat", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByText("sudo systemctl enable --now atomic-control-agent", {
      exact: false,
    }),
  ).toBeVisible();
  await expect(
    dialog.getByText("Agent upgrade required", { exact: true }),
  ).toHaveCount(0);
  await expect(
    dialog.getByRole("button", { name: "Download agent update" }),
  ).toHaveCount(0);
  expect(state.packageWrites).toBe(0);
  expect(state.runRequests).toBe(0);
});

test("Linux download explains first start, hostname resolution and older missing-directory repair", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog");
  state.actor.registration_state = "pending_enrollment";
  state.actor.last_heartbeat = 0;
  state.actor.online = false;
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "Generate agent", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Generate Linux agent" });
  await expect(
    dialog.getByText("sudo python3 -I install.py", { exact: false }),
  ).toBeVisible();
  await expect(
    dialog.getByText("sudo systemctl enable --now atomic-control-agent", {
      exact: false,
    }),
  ).toBeVisible();
  await dialog
    .getByText("Hostname and startup troubleshooting", { exact: true })
    .click();
  await expect(
    dialog.getByText("127.0.1.1 linux-host-fixture", { exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByText("sudo install -d -o root -g root -m 0755", {
      exact: false,
    }),
  ).toBeVisible();
  await expect(
    dialog.getByText(
      "The placeholder enables a heartbeat; it does not contain Atomic tests.",
    ),
  ).toBeVisible();
  expect(state.packageWrites).toBe(0);
  expect(state.runRequests).toBe(0);
});

test("Windows download explains bundled machine CA trust and shows its fingerprint", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog");
  state.actor.os = "windows";
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "Generate agent", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Generate Windows agent" });
  await expect(dialog.getByLabel("Test delivery", { exact: true })).toHaveValue(
    "on_demand",
  );
  await dialog
    .getByLabel("Test delivery", { exact: true })
    .selectOption("checkout");
  await expect(dialog.getByLabel("Pinned catalog revision")).toHaveValue(
    revision,
  );
  await dialog
    .getByText("Windows installation and reinstall", { exact: true })
    .click();
  await expect(
    dialog.getByText("-StartService", { exact: false }).first(),
  ).toBeVisible();
  const trust = dialog.getByRole("region", {
    name: "Bundled control-plane CA",
  });
  await expect(
    trust.getByText("CN=Fixture control-plane CA", { exact: true }),
  ).toBeVisible();
  await expect(
    trust.getByText(Array(32).fill("A1").join(":"), { exact: true }),
  ).toBeVisible();
  await expect(trust).toContainText(
    "No separate certificate copy or import is needed",
  );
  await expect(trust).toContainText("-SkipCATrust");
  expect(state.packageWrites).toBe(0);
  expect(state.runRequests).toBe(0);
});

for (const scenario of [
  {
    name: "healthy on-demand",
    sync: "applied",
    online: true,
    healthy: true,
    profiles: true,
    old: false,
    status: "Ready",
    retry: false,
  },
  {
    name: "pending automatically",
    sync: "pending",
    online: true,
    healthy: true,
    profiles: true,
    old: false,
    status: "Waiting for validation",
    retry: false,
  },
  {
    name: "applying automatically",
    sync: "applying",
    online: true,
    healthy: true,
    profiles: true,
    old: false,
    status: "Validating",
    retry: false,
  },
  {
    name: "offline with previous validation",
    sync: "applied",
    online: false,
    healthy: true,
    profiles: true,
    old: false,
    status: "Waiting for agent",
    retry: false,
  },
  {
    name: "without profiles",
    sync: "applied",
    online: true,
    healthy: true,
    profiles: false,
    old: false,
    status: "Needs a profile",
    retry: false,
  },
  {
    name: "unhealthy after heartbeat",
    sync: "applied",
    online: true,
    healthy: false,
    profiles: true,
    old: false,
    status: "Needs attention",
    retry: true,
  },
  {
    name: "failed application",
    sync: "failed",
    online: true,
    healthy: false,
    profiles: true,
    old: false,
    status: "Needs attention",
    retry: true,
  },
  {
    name: "stalled idle validation",
    sync: "pending",
    online: true,
    healthy: true,
    profiles: true,
    old: true,
    status: "Needs attention",
    retry: true,
  },
  {
    name: "offline pending validation",
    sync: "pending",
    online: false,
    healthy: true,
    profiles: true,
    old: true,
    status: "Waiting for agent",
    retry: false,
  },
]) {
  test(`execution identity is compact for ${scenario.name}`, async ({
    page,
  }) => {
    const state = await isolatedSetup(
      page,
      true,
      scenario.profiles,
      false,
      "catalog",
      true,
    );
    state.actor.delivery_mode = "on_demand";
    state.actor.artifact_protocol = 1;
    state.actor.revision = "";
    state.actor.online = scenario.online;
    state.actor.profiles.forEach((profile) => {
      profile.healthy = scenario.healthy;
    });
    state.actor.profile_sync = {
      ...state.actor.profile_sync!,
      status: scenario.sync,
      generation: 42,
      updated_at: Date.now() / 1000 - (scenario.old ? 240 : 0),
    };
    await page.goto("/");
    await page.getByRole("button", { name: "Actors", exact: true }).click();
    await page
      .getByRole("button", { name: "linux-host-fixture", exact: true })
      .click();
    const dialog = page.getByRole("dialog", { name: "Actor details" });
    const identity = dialog.getByRole("region", { name: "Execution identity" });
    await expect(identity.getByRole("status")).toHaveText(scenario.status);
    await expect(
      identity.getByRole("button", { name: "Retry validation" }),
    ).toHaveCount(scenario.retry ? 1 : 0);
    await expect(
      dialog.getByRole("button", { name: "Apply profiles" }),
    ).toHaveCount(0);
    await expect(
      dialog.getByRole("heading", { name: "Managed profile synchronization" }),
    ).toHaveCount(0);
    await expect(identity).not.toContainText("generation");
    if (scenario.name === "healthy on-demand") {
      await identity.scrollIntoViewIfNeeded();
      await page.screenshot({
        path: "/tmp/atomic-execution-identity-ready.png",
        fullPage: true,
      });
    }
    expect(state.syncWrites).toBe(0);
    expect(state.runRequests).toBe(0);
  });
}

test("operators see identity failures without administrator recovery controls", async ({
  page,
}) => {
  const state = await isolatedSetup(page, false, true, false, "catalog", true);
  state.actor.profile_sync = { ...state.actor.profile_sync!, status: "failed" };
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  const identity = page.getByRole("region", { name: "Execution identity" });
  await expect(identity.getByRole("status")).toHaveText("Needs attention");
  await expect(identity.getByRole("button")).toHaveCount(0);
  expect(state.syncWrites).toBe(0);
});

test("execution shows only matching platforms and approved inline tests need no file approval step", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog", true);
  state.actor.delivery_mode = "on_demand";
  state.actor.artifact_protocol = 1;
  state.actor.revision = "";
  state.extraActors.push(
    {
      ...state.actor,
      id: "77b22640-7612-427b-a546-26cc50407449",
      hostname: "windows-hidden",
      os: "windows",
    },
    {
      ...state.actor,
      id: "696fcb00-1862-4b63-a605-d174dbb74263",
      hostname: "linux-offline",
      online: false,
    },
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Execute Test", exact: true }).click();
  await page.getByLabel("Atomic test", { exact: true }).selectOption(guid);
  const actors = page.getByLabel("Execution actor", { exact: true });
  await expect(actors.locator("option")).toHaveCount(3);
  await expect(actors).not.toContainText("windows-hidden");
  await expect(actors).toContainText("linux-offline — offline");
  await actors.selectOption(actorId);
  await page
    .getByLabel("Execution identity", { exact: true })
    .selectOption(profileId);
  await page
    .getByLabel("Testing reason", { exact: false })
    .fill("Authorized test on matching Linux platform");
  await page.getByText("Actor eligibility and setup", { exact: true }).click();
  await expect(
    page.getByText(
      "Approve the test and its supporting files in Test Catalog",
      { exact: true },
    ),
  ).toHaveCount(0);
  await expect(page.locator(".actor-readiness")).not.toContainText(
    "windows-hidden",
  );
  await expect(
    page.getByRole("button", { name: "Run approved test", exact: true }),
  ).toBeEnabled();
  await page
    .getByRole("button", { name: "Run approved test", exact: true })
    .click();
  expect(state.runRequests).toBe(1);
});

test("matching platform actors remain visible when offline but cannot run", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog", true);
  state.actor.delivery_mode = "on_demand";
  state.actor.artifact_protocol = 1;
  state.actor.online = false;
  await page.goto("/");
  await page.getByRole("button", { name: "Execute Test", exact: true }).click();
  await page.getByLabel("Atomic test", { exact: true }).selectOption(guid);
  const actors = page.getByLabel("Execution actor", { exact: true });
  await expect(actors).toContainText("linux-host-fixture — offline");
  await actors.selectOption(actorId);
  await page
    .getByLabel("Execution identity", { exact: true })
    .selectOption(profileId);
  await page
    .getByLabel("Testing reason", { exact: false })
    .fill("Authorized offline actor readiness check");
  await expect(
    page.getByRole("button", { name: "Run approved test", exact: true }),
  ).toBeDisabled();
  expect(state.runRequests).toBe(0);
});

for (const platform of ["linux", "windows"] as const) {
  test(`administrator deletes a ${platform} profile after confirmation`, async ({
    page,
  }) => {
    const state = await isolatedSetup(page, true, true, false, "catalog", true);
    state.actor.os = platform;
    state.actor.profile_sync = {
      ...state.actor.profile_sync!,
      status: "applied",
    };
    if (platform === "windows") {
      state.actor.profiles[0].expected_sid = "S-1-5-21-111-222-333-1001";
      state.actor.profiles[0].logon_type = "batch";
    }
    await page.goto("/");
    await page.getByRole("button", { name: "Actors", exact: true }).click();
    await page
      .getByRole("button", { name: "linux-host-fixture", exact: true })
      .click();
    await page
      .getByRole("button", {
        name: "Delete Linux standard user profile",
        exact: true,
      })
      .click();
    const dialog = page.getByRole("dialog", {
      name: "Delete execution profile",
    });
    await expect(dialog).toContainText("Execution history is retained");
    expect(state.profileDeletes).toEqual([]);
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(state.profileDeletes).toEqual([]);
    await page
      .getByRole("button", {
        name: "Delete Linux standard user profile",
        exact: true,
      })
      .click();
    await page
      .getByRole("dialog", { name: "Delete execution profile" })
      .getByRole("button", { name: "Delete profile", exact: true })
      .click();
    await expect(
      page.getByRole("dialog", { name: "Delete execution profile" }),
    ).toHaveCount(0);
    expect(state.profileDeletes).toEqual([profileId]);
    await expect(
      page.getByText("No execution profiles are registered.", { exact: false }),
    ).toBeVisible();
    expect(state.runRequests).toBe(0);
  });
}

test("Windows profiles explain local task provisioning and automatic validation", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog", true);
  state.actor.os = "windows";
  state.actor.profile_sync = {
    ...state.actor.profile_sync!,
    status: "validation_failed",
    results: { [profileId]: { healthy: false, error: "task_missing" } },
  };
  state.actor.profiles[0].healthy = false;
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  await expect(
    page.getByRole("region", { name: "Execution identity" }),
  ).toContainText("Needs attention");
  await expect(
    page.getByText(
      "Provision the password-backed Windows profile tasks locally",
      { exact: false },
    ),
  ).toBeVisible();
  await page.getByText("Windows task setup", { exact: true }).click();
  await expect(
    page.getByText("Profiles download automatically.", { exact: false }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Retry validation", exact: true })
    .click();
  expect(state.syncWrites).toBe(1);
});

test("operators cannot delete execution profiles", async ({ page }) => {
  await isolatedSetup(page, false, true, false, "catalog", true);
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  await expect(
    page.getByRole("button", {
      name: "Delete Linux standard user profile",
      exact: true,
    }),
  ).toHaveCount(0);
});

test("Windows profile updater preserves checkout mode and enrollment", async ({
  page,
}) => {
  const state = await isolatedSetup(page, true, true, false, "catalog");
  state.actor.os = "windows";
  state.actor.delivery_mode = "checkout";
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "linux-host-fixture", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Download agent update", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Generate Windows agent" });
  await expect(dialog.getByLabel("Test delivery", { exact: true })).toHaveValue(
    "checkout",
  );
  await dialog
    .getByRole("button", { name: "Generate and download ZIP", exact: true })
    .click();
  const result = dialog.locator(".package-download-result");
  await expect(result).toContainText("--enable-profile-sync");
  await expect(result).not.toContainText("--enable-on-demand");
  expect(state.packageWrites).toBe(1);
  expect(state.runRequests).toBe(0);
});
