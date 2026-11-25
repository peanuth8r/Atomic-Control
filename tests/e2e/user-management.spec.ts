import { expect, test, type Page } from "@playwright/test";
const levels = [
  {
    value: "viewer",
    label: "Viewer",
    roles: ["viewer"],
    description: "View actors, tests and execution evidence.",
  },
  {
    value: "operator",
    label: "Operator",
    roles: ["viewer", "operator"],
    description: "Request approved tests and queues.",
  },
  {
    value: "approver",
    label: "Approver",
    roles: ["viewer", "approver", "privileged_approver"],
    description: "Approve per-run requests.",
  },
  {
    value: "administrator",
    label: "Administrator",
    roles: [
      "viewer",
      "operator",
      "approver",
      "privileged_approver",
      "administrator",
    ],
    description: "Manage application users and settings.",
  },
];
async function setup(
  page: Page,
  {
    admin = true,
    available = true,
    failFirst = false,
    duplicate = false,
    staleRoles = false,
    self = false,
    inherited = false,
    deleteFailure = false,
    deleteStale = false,
  } = {},
) {
  const state = {
    writes: [] as { body: Record<string, any>; key: string }[],
    optionsReads: 0,
    enrollmentMinutes: 60,
    enrollmentWrites: [] as number[],
    roleWrites: [] as Record<string, any>[],
    listReads: 0,
    deleted: false,
    deleteWrites: [] as Record<string, any>[],
    user: {
      id: "a9d8d76a-e091-4c4a-bd5a-df73680b2450",
      username: self ? "existing.admin" : "existing.operator",
      first_name: "Existing",
      last_name: "User",
      email: "existing@example.test",
      enabled: true,
      roles: levels.find(
        (level) => level.value === (self ? "administrator" : "operator"),
      )!.roles,
      direct_roles: levels.find(
        (level) => level.value === (self ? "administrator" : "operator"),
      )!.roles,
      access_level: self ? "administrator" : "operator",
      editable: !inherited,
      edit_reason: inherited
        ? "Group, composite or custom role assignments must be managed in Keycloak."
        : "",
      version: "a".repeat(64),
      access_on_hold: false,
    },
  };
  const paged = { items: [], total: 0, limit: 200, offset: 0 };
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (path === "/admin/agent-settings" && request.method() === "PUT") {
      expect(admin).toBe(true);
      state.enrollmentMinutes = request.postDataJSON().enrollment_token_minutes;
      state.enrollmentWrites.push(state.enrollmentMinutes);
      return route.fulfill({
        json: { enrollment_token_minutes: state.enrollmentMinutes },
      });
    }
    if (request.method() === "GET") {
      if (path === "/admin/agent-settings")
        return route.fulfill({
          json: { enrollment_token_minutes: state.enrollmentMinutes },
        });
      if (path === "/me")
        return route.fulfill({
          json: {
            subject: self ? state.user.id : "fixture:admin",
            roles: admin ? ["viewer", "administrator"] : ["viewer", "operator"],
            mode: "real",
            dev_auth: false,
            approval_mode: "catalog",
          },
        });
      if (["/tests", "/actors", "/runs", "/audit", "/approvals"].includes(path))
        return route.fulfill({ json: paged });
      if (path === "/execution-access")
        return route.fulfill({
          json: { available: false, reason: "Catalog approval", grants: [] },
        });
      if (path === "/admin/users") {
        expect(admin && available).toBe(true);
        state.listReads++;
        const q =
          new URL(request.url()).searchParams.get("q")?.toLowerCase() ?? "";
        return route.fulfill({
          json: {
            items:
              !state.deleted && state.user.username.toLowerCase().includes(q)
                ? [state.user]
                : [],
            offset: 0,
            next_offset: 1,
            has_more: false,
          },
        });
      }
      if (path === `/admin/users/${state.user.id}`)
        return route.fulfill({
          status: state.deleted ? 404 : 200,
          json: state.user,
        });
      if (path === "/admin/users/options") {
        state.optionsReads++;
        expect(admin).toBe(true);
        return route.fulfill({
          json: {
            available,
            provider: "Keycloak",
            message: available
              ? ""
              : "Configure the Keycloak user-management client on the control plane.",
            minimum_password_length: 12,
            temporary_password: true,
            access_levels: levels,
          },
        });
      }
    }
    if (
      request.method() === "DELETE" &&
      path === `/admin/users/${state.user.id}`
    ) {
      expect(admin && !self).toBe(true);
      const body = request.postDataJSON();
      state.deleteWrites.push(body);
      if (deleteStale && state.deleteWrites.length === 1) {
        state.user.version = "d".repeat(64);
        return route.fulfill({
          status: 409,
          json: {
            error: {
              code: "user_changed",
              message: "This account changed. Refresh the user before deleting",
            },
          },
        });
      }
      if (deleteFailure && state.deleteWrites.length === 1)
        return route.fulfill({
          status: 503,
          json: {
            error: {
              code: "user_deletion_incomplete",
              message:
                "Deletion could not be confirmed. Account access is on hold; retry the same deletion or refresh users",
            },
          },
        });
      expect(body.confirm_username).toBe(state.user.username);
      expect(body.expected_version).toBe(state.user.version);
      state.deleted = true;
      return route.fulfill({
        json: {
          id: state.user.id,
          username: state.user.username,
          deleted: true,
          replayed: false,
        },
      });
    }
    if (
      request.method() === "POST" &&
      path === `/admin/users/${state.user.id}/roles`
    ) {
      expect(admin).toBe(true);
      const body = request.postDataJSON();
      state.roleWrites.push(body);
      if (staleRoles && state.roleWrites.length === 1) {
        state.user.version = "b".repeat(64);
        state.user.roles = [
          ...levels.find((level) => level.value === "approver")!.roles,
        ].sort();
        state.user.direct_roles = state.user.roles;
        state.user.access_level = "approver";
        return route.fulfill({
          status: 409,
          json: {
            error: {
              code: "user_roles_changed",
              message:
                "This user's roles changed. Refresh the user before saving",
            },
          },
        });
      }
      expect(body.expected_version).toBe(state.user.version);
      state.user.roles = [
        ...levels.find((level) => level.value === body.access_level)!.roles,
      ].sort();
      state.user.direct_roles = state.user.roles;
      state.user.access_level = body.access_level;
      state.user.version = "c".repeat(64);
      return route.fulfill({
        json: { ...state.user, changed: true, sessions_revoked: true },
      });
    }
    if (request.method() === "POST" && path === "/admin/users") {
      expect(admin).toBe(true);
      state.writes.push({
        body: request.postDataJSON(),
        key: request.headers()["idempotency-key"],
      });
      if (duplicate)
        return route.fulfill({
          status: 409,
          json: {
            error: {
              code: "user_exists",
              message:
                "This username is already in use. Existing accounts are not changed",
            },
          },
        });
      if (failFirst && state.writes.length === 1)
        return route.fulfill({
          status: 503,
          json: {
            error: {
              code: "user_management_unavailable",
              message: "Retry the unchanged request",
            },
          },
        });
      const body = state.writes.at(-1)!.body;
      return route.fulfill({
        status: 201,
        json: {
          id: "733af82b-cfe9-4c19-b013-95f8969d7f1f",
          username: body.username,
          access_level: body.access_level,
          roles: levels.find((level) => level.value === body.access_level)!
            .roles,
          temporary_password: true,
          enabled: true,
          replayed: false,
        },
      });
    }
    await route.abort();
    throw new Error(
      `Unexpected user-management fixture request: ${request.method()} ${path}`,
    );
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  return state;
}
async function fill(page: Page) {
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Create user", exact: true });
  await dialog.getByLabel("Username", { exact: true }).fill("new.operator");
  await dialog.getByLabel("First name (optional)", { exact: true }).fill("New");
  await dialog
    .getByLabel("Last name (optional)", { exact: true })
    .fill("Operator");
  await dialog
    .getByLabel("Email (optional)", { exact: true })
    .fill("operator@example.test");
  await dialog
    .getByLabel("Access level", { exact: true })
    .selectOption("operator");
  await dialog
    .getByLabel("Temporary password", { exact: true })
    .fill("Fixture-only password 123!");
  return dialog;
}
test("admin creates user with explicit access and required first-login password change", async ({
  page,
}) => {
  const state = await setup(page);
  const dialog = await fill(page);
  await expect(
    dialog.getByRole("button", { name: "Create user", exact: true }),
  ).toBeDisabled();
  await dialog
    .getByLabel("Confirm temporary password", { exact: true })
    .fill("mismatch");
  await expect(
    dialog.getByRole("button", { name: "Create user", exact: true }),
  ).toBeDisabled();
  expect(state.writes).toHaveLength(0);
  await dialog
    .getByLabel("Confirm temporary password", { exact: true })
    .fill("Fixture-only password 123!");
  await page.screenshot({
    path: "artifacts/create-user-dialog.png",
    fullPage: true,
  });
  await dialog
    .getByRole("button", { name: "Create user", exact: true })
    .click();
  await expect(dialog).toHaveCount(0);
  await expect(
    page.getByText("User new.operator created.", { exact: true }),
  ).toBeVisible();
  expect(state.writes).toHaveLength(1);
  expect(state.writes[0].body.access_level).toBe("operator");
  expect(state.writes[0].body.temporary_password).toBe(
    "Fixture-only password 123!",
  );
  expect(state.writes[0].key).toBeTruthy();
  await expect(
    page.getByText("Fixture-only password 123!", { exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Create user", exact: true }).click();
  await expect(
    page.getByLabel("Temporary password", { exact: true }),
  ).toHaveValue("");
  await expect(
    page.getByLabel("Confirm temporary password", { exact: true }),
  ).toHaveValue("");
});
test("network failure retains the same key on an unchanged retry", async ({
  page,
}) => {
  const state = await setup(page, { failFirst: true });
  const dialog = await fill(page);
  await dialog
    .getByLabel("Confirm temporary password", { exact: true })
    .fill("Fixture-only password 123!");
  await dialog
    .getByRole("button", { name: "Create user", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toHaveText(
    "Retry the unchanged request",
  );
  await dialog
    .getByRole("button", { name: "Create user", exact: true })
    .click();
  await expect(dialog).toHaveCount(0);
  expect(state.writes).toHaveLength(2);
  expect(state.writes[0]).toEqual(state.writes[1]);
});
test("duplicate account error stays in form without claiming success", async ({
  page,
}) => {
  const state = await setup(page, { duplicate: true });
  const dialog = await fill(page);
  await dialog
    .getByLabel("Confirm temporary password", { exact: true })
    .fill("Fixture-only password 123!");
  await dialog
    .getByRole("button", { name: "Create user", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText("already in use");
  await expect(
    page.getByText("User new.operator created.", { exact: true }),
  ).toHaveCount(0);
  expect(state.writes).toHaveLength(1);
});
test("operators cannot see or fetch user management", async ({ page }) => {
  const state = await setup(page, { admin: false });
  await expect(
    page.getByRole("heading", { name: "User accounts", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Create user", exact: true }),
  ).toHaveCount(0);
  expect(state.optionsReads).toBe(0);
});
test("unconfigured provider explains unavailable creation", async ({
  page,
}) => {
  const state = await setup(page, { available: false });
  await expect(
    page.getByRole("button", { name: "Create user", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByText(
      "Configure the Keycloak user-management client on the control plane.",
      { exact: true },
    ),
  ).toBeVisible();
  expect(state.writes).toHaveLength(0);
});

test("administrator reviews and changes an existing user access level", async ({
  page,
}) => {
  const state = await setup(page);
  await page
    .getByRole("button", {
      name: "Change roles for existing.operator",
      exact: true,
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Change roles: existing.operator",
    exact: true,
  });
  await expect(
    dialog.getByRole("button", { name: "Save roles", exact: true }),
  ).toBeDisabled();
  await dialog
    .getByLabel("New access level", { exact: true })
    .selectOption("approver");
  await expect(
    dialog.getByText("New roles: viewer, approver, privileged_approver", {
      exact: true,
    }),
  ).toBeVisible();
  expect(state.roleWrites).toHaveLength(0);
  await page.screenshot({
    path: "artifacts/change-user-roles.png",
    fullPage: true,
  });
  await dialog.getByRole("button", { name: "Save roles", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(
    page.getByText(
      "Roles updated for existing.operator. They must sign in again.",
      { exact: true },
    ),
  ).toBeVisible();
  expect(state.roleWrites).toEqual([
    { access_level: "approver", expected_version: "a".repeat(64) },
  ]);
});

test("stale role change requires refreshed user before retrying", async ({
  page,
}) => {
  const state = await setup(page, { staleRoles: true });
  await page
    .getByRole("button", {
      name: "Change roles for existing.operator",
      exact: true,
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Change roles: existing.operator",
    exact: true,
  });
  await dialog
    .getByLabel("New access level", { exact: true })
    .selectOption("viewer");
  await dialog.getByRole("button", { name: "Save roles", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("roles changed");
  await dialog
    .getByRole("button", { name: "Refresh user", exact: true })
    .click();
  await expect(
    dialog.getByText("approver, privileged_approver, viewer", { exact: true }),
  ).toBeVisible();
  await dialog.getByRole("button", { name: "Save roles", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.roleWrites[1].expected_version).toBe("b".repeat(64));
});

test("administrator cannot select their own demotion", async ({ page }) => {
  const state = await setup(page, { self: true });
  await page
    .getByRole("button", {
      name: "Change roles for existing.admin",
      exact: true,
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Change roles: existing.admin",
    exact: true,
  });
  await expect(
    dialog.getByRole("option", { name: "Viewer", exact: true }),
  ).toBeDisabled();
  await expect(
    dialog.getByRole("option", { name: "Operator", exact: true }),
  ).toBeDisabled();
  await expect(
    dialog.getByRole("button", { name: "Save roles", exact: true }),
  ).toBeDisabled();
  expect(state.roleWrites).toHaveLength(0);
});

test("group and composite accounts explain why roles are managed in Keycloak", async ({
  page,
}) => {
  const state = await setup(page, { inherited: true });
  await expect(
    page.getByRole("button", {
      name: "Change roles for existing.operator",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    page.getByText(
      "Group, composite or custom role assignments must be managed in Keycloak.",
      { exact: true },
    ),
  ).toBeVisible();
  expect(state.roleWrites).toHaveLength(0);
});

test("administrator searches existing users", async ({ page }) => {
  const state = await setup(page);
  await expect(
    page.getByRole("button", {
      name: "Change roles for existing.operator",
      exact: true,
    }),
  ).toBeVisible();
  await page.getByLabel("Search users", { exact: true }).fill("missing-user");
  await expect(
    page.getByText("No matching human users.", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("Search users", { exact: true }).fill("existing");
  await expect(
    page.getByRole("button", {
      name: "Change roles for existing.operator",
      exact: true,
    }),
  ).toBeVisible();
  expect(state.listReads).toBeGreaterThanOrEqual(3);
});

test("admin confirms the exact username before permanently deleting a user", async ({
  page,
}) => {
  const state = await setup(page);
  await page
    .getByRole("button", { name: "Delete user existing.operator", exact: true })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Delete user: existing.operator",
    exact: true,
  });
  await expect(
    dialog.getByText("Execution and audit", { exact: false }),
  ).toBeVisible();
  const submit = dialog.getByRole("button", {
    name: "Permanently delete user",
    exact: true,
  });
  await expect(submit).toBeDisabled();
  await dialog
    .getByLabel("Type the username to confirm deletion")
    .fill("different.user");
  await expect(submit).toBeDisabled();
  expect(state.deleteWrites).toHaveLength(0);
  await dialog
    .getByLabel("Type the username to confirm deletion")
    .fill("existing.operator");
  await page.screenshot({ path: "artifacts/delete-user.png", fullPage: true });
  await submit.click();
  await expect(dialog).not.toBeVisible();
  await expect(
    page
      .getByRole("status")
      .filter({ hasText: "User existing.operator deleted." }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", {
      name: "Delete user existing.operator",
      exact: true,
    }),
  ).toHaveCount(0);
  expect(state.deleteWrites).toEqual([
    { confirm_username: "existing.operator", expected_version: "a".repeat(64) },
  ]);
});

test("admin cannot delete their own account", async ({ page }) => {
  const state = await setup(page, { self: true });
  await expect(
    page.getByRole("button", {
      name: "Delete user existing.admin",
      exact: true,
    }),
  ).toBeDisabled();
  expect(state.deleteWrites).toHaveLength(0);
});

test("failed user deletion remains open and can be retried without claiming success", async ({
  page,
}) => {
  const state = await setup(page, { deleteFailure: true });
  await page
    .getByRole("button", { name: "Delete user existing.operator", exact: true })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Delete user: existing.operator",
    exact: true,
  });
  await dialog
    .getByLabel("Type the username to confirm deletion")
    .fill("existing.operator");
  await dialog
    .getByRole("button", { name: "Permanently delete user", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Deletion could not be confirmed",
  );
  expect(state.deleted).toBe(false);
  await dialog
    .getByRole("button", { name: "Permanently delete user", exact: true })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(state.deleteWrites).toHaveLength(2);
  expect(state.deleteWrites[0]).toEqual(state.deleteWrites[1]);
});

test("stale deletion requires a refreshed account and new confirmation", async ({
  page,
}) => {
  const state = await setup(page, { deleteStale: true });
  await page
    .getByRole("button", { name: "Delete user existing.operator", exact: true })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Delete user: existing.operator",
    exact: true,
  });
  await dialog
    .getByLabel("Type the username to confirm deletion")
    .fill("existing.operator");
  await dialog
    .getByRole("button", { name: "Permanently delete user", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText("Refresh the user");
  await dialog
    .getByRole("button", { name: "Refresh user", exact: true })
    .click();
  await expect(
    dialog.getByLabel("Type the username to confirm deletion"),
  ).toHaveValue("");
  await dialog
    .getByLabel("Type the username to confirm deletion")
    .fill("existing.operator");
  await dialog
    .getByRole("button", { name: "Permanently delete user", exact: true })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(state.deleteWrites[1].expected_version).toBe("d".repeat(64));
});

test("administrator saves enrollment token lifetime and sees it after reload", async ({
  page,
}) => {
  const state = await setup(page);
  const input = page.getByLabel(
    "Initial installation token lifetime (minutes)",
  );
  await expect(input).toHaveValue("60");
  await input.fill("120");
  await page.getByRole("button", { name: "Save enrollment settings" }).click();
  await expect(
    page
      .getByRole("status")
      .filter({ hasText: "Saved. New enrollment tokens" }),
  ).toContainText("120 minutes");
  expect(state.enrollmentWrites).toEqual([120]);
  await page.reload();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(
    page.getByLabel("Initial installation token lifetime (minutes)"),
  ).toHaveValue("120");
});
test("operators cannot see administrator enrollment settings", async ({
  page,
}) => {
  await setup(page, { admin: false });
  await expect(
    page.getByRole("heading", { name: "Agent enrollment", exact: true }),
  ).toHaveCount(0);
});
