import { expect, test, type Page } from "@playwright/test";

async function setup(
  page: Page,
  initialStatus = 200,
  seconds: number | null = null,
  delayAuthorization = false,
) {
  let release!: () => void;
  const waitForAuthorization = delayAuthorization
    ? new Promise<void>((resolve) => {
        release = resolve;
      })
    : Promise.resolve();
  const state = {
    status: initialStatus,
    dataReads: 0,
    roles: ["viewer", "operator"],
  };
  const paged = (items: unknown[]) => ({
    items,
    total: items.length,
    limit: 200,
    offset: 0,
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1", "");
    if (route.request().method() !== "GET")
      throw new Error("Login-gate test must not write application data");
    if (path === "/me") {
      await waitForAuthorization;
      if (state.status !== 200)
        return route.fulfill({
          status: state.status,
          json: {
            error: { code: "unauthenticated", message: "Session unavailable" },
          },
        });
      return route.fulfill({
        json: {
          subject: "human-login-fixture",
          username: "fixture.operator",
          roles: state.roles,
          mode: "real",
          dev_auth: false,
          approval_mode: "catalog",
          session_expires_in: seconds,
        },
      });
    }
    state.dataReads++;
    if (state.status !== 200)
      return route.fulfill({
        status: 401,
        json: { error: { code: "unauthenticated", message: "Session ended" } },
      });
    if (path === "/actors")
      return route.fulfill({
        json: paged([
          {
            id: "51db3142-5bea-43c5-aafe-a3c2240f07cf",
            hostname: "private-host-fixture",
            registration_state: "enrolled",
            os: "linux",
            os_version: "Linux",
            agent_version: "0.1.0",
            revision: "a".repeat(40),
            enabled: true,
            online: true,
            last_heartbeat: Date.now() / 1000,
            health: "healthy",
            active_job: null,
            simulated: false,
            profiles: [],
          },
        ]),
      });
    if (["/tests", "/runs", "/audit", "/approvals"].includes(path))
      return route.fulfill({ json: paged([]) });
    await route.abort();
    throw new Error(`Unexpected API request: ${path}`);
  });
  return { state, release: () => release?.() };
}

async function expectLoginOnly(page: Page) {
  await expect(page.getByLabel("Atomic Control sign-in")).toBeVisible();
  await expect(page.locator(".shell")).toHaveCount(0);
  await expect(page.locator("nav")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "User menu", exact: true }),
  ).toHaveCount(0);
  await expect(page.getByRole("button", { name: "New execution" })).toHaveCount(
    0,
  );
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(
    page.getByText("private-host-fixture", { exact: true }),
  ).toHaveCount(0);
}

test("signed-out visitors see only sign-in and no protected data requests", async ({
  page,
}) => {
  const { state } = await setup(page, 401);
  await page.goto("/");
  await expectLoginOnly(page);
  await expect(
    page.getByRole("link", { name: "Sign in with SSO" }),
  ).toHaveAttribute("href", "/auth/login");
  expect(state.dataReads).toBe(0);
  await page.screenshot({ path: "artifacts/login-only-ui.png" });
});

test("user icon signs out from any page and removes the dashboard", async ({
  page,
}) => {
  const { state } = await setup(page);
  let logoutRequests = 0;
  await page.route("**/auth/logout", async (route) => {
    expect(route.request().method()).toBe("POST");
    logoutRequests++;
    state.status = 401;
    await route.fulfill({ status: 303, headers: { Location: "/" }, body: "" });
  });
  await page.goto("/");
  await expect(page.locator(".operator-avatar")).toContainText(
    "fixture.operator",
  );
  await expect(page.locator(".operator-avatar")).not.toContainText(
    "human-login-fixture",
  );
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(
    page
      .locator(".settings-grid")
      .getByText("fixture.operator", { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .locator(".settings-grid")
      .getByText("human-login-fixture", { exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  const trigger = page.getByRole("button", { name: "User menu", exact: true });
  await trigger.focus();
  await page.keyboard.press("Enter");
  const account = page.getByRole("region", {
    name: "User account",
    exact: true,
  });
  await expect(account).toBeVisible();
  await expect(
    account.getByText("fixture.operator", { exact: true }),
  ).toBeVisible();
  await expect(
    account.getByText("human-login-fixture", { exact: true }),
  ).toHaveCount(0);
  await expect(
    account.getByRole("button", { name: "Sign out", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(account).not.toBeVisible();
  await expect(trigger).toBeFocused();
  await trigger.click();
  await page.getByRole("heading", { name: "Actors", exact: true }).click();
  await expect(account).not.toBeVisible();
  await trigger.click();
  await account.getByRole("button", { name: "Sign out", exact: true }).click();
  await expectLoginOnly(page);
  expect(logoutRequests).toBe(1);
});

test("dashboard stays unmounted while authorization is pending", async ({
  page,
}) => {
  const { state, release } = await setup(page, 200, null, true);
  await page.goto("/");
  await expectLoginOnly(page);
  await expect(
    page.getByRole("heading", { name: "Checking authorization…" }),
  ).toBeVisible();
  expect(state.dataReads).toBe(0);
  release();
  await expect(
    page.getByRole("heading", { name: "Validation overview" }),
  ).toBeVisible();
  await expect(
    page.getByText("private-host-fixture", { exact: true }),
  ).toBeVisible();
});

test("authorization loss clears the dashboard and an open actor dialog on focus", async ({
  page,
}) => {
  const { state } = await setup(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Actors", exact: true }).click();
  await page
    .getByRole("button", { name: "private-host-fixture", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", { name: "Actor details" }),
  ).toBeVisible();
  state.status = 401;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expectLoginOnly(page);
});

test("fixed session deadline clears the dashboard without extending on activity", async ({
  page,
}) => {
  await setup(page, 200, 1);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Validation overview" }),
  ).toBeVisible();
  await expectLoginOnly(page);
  await expect(
    page.getByRole("link", { name: "Sign in with SSO" }),
  ).toBeVisible();
});

test("users without dashboard authorization cannot see the shell", async ({
  page,
}) => {
  const { state } = await setup(page);
  state.roles = ["operator"];
  await page.goto("/");
  await expectLoginOnly(page);
  await expect(
    page.getByText("Your account is not authorized to access this dashboard."),
  ).toBeVisible();
  expect(state.dataReads).toBe(0);
});

test("an unavailable authorization check shows sign-in and retry without dashboard data", async ({
  page,
}) => {
  const { state } = await setup(page, 503);
  await page.goto("/");
  await expectLoginOnly(page);
  await expect(
    page.getByRole("button", { name: "Retry connection" }),
  ).toBeVisible();
  expect(state.dataReads).toBe(0);
  state.status = 200;
  await page.getByRole("button", { name: "Retry connection" }).click();
  await expect(
    page.getByRole("heading", { name: "Validation overview" }),
  ).toBeVisible();
});
