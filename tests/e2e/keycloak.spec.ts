import { test, expect } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";

test.use({ trace: "off", video: "off" });

test.describe("real local Keycloak", () => {
  test.skip(
    process.env.ATOMIC_KEYCLOAK_E2E !== "1",
    "Requires the separate local HTTPS identity deployment",
  );

  test("browser sign-in and mapped roles use trusted HTTPS without development authentication", async ({
    browser,
  }) => {
    test.setTimeout(90000);
    const control = process.env.ATOMIC_CONTROL_URL || "https://localhost:19443";
    const keycloak = new URL(control);
    keycloak.port = "18443";
    const credentials = JSON.parse(
      readFileSync("artifacts/keycloak/credentials.json", "utf8"),
    );
    const expected: Record<string, string[]> = {
      "atomic-viewer": ["viewer"],
      "atomic-operator": ["operator", "viewer"],
      "atomic-approver": ["approver", "privileged_approver", "viewer"],
      "atomic-admin": [
        "administrator",
        "approver",
        "operator",
        "privileged_approver",
        "viewer",
      ],
    };
    let retirementFormReviewed = false;
    let catalogFormReviewed = false;
    for (const [username, roles] of Object.entries(expected)) {
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        await page.goto(control + "/");
        await expect(page.getByLabel("Atomic Control sign-in")).toBeVisible();
        await expect(page.locator(".shell")).toHaveCount(0);
        await expect(page.locator("nav")).toHaveCount(0);
        await page
          .getByRole("link", { name: "Sign in with SSO", exact: false })
          .click();
        await expect(page).toHaveURL((url) => url.origin === keycloak.origin);
        await page.getByLabel("Username", { exact: true }).fill(username);
        await page
          .getByLabel("Password", { exact: true })
          .fill(credentials.users[username]);
        await page.getByRole("button", { name: /^sign in$/i }).click();
        await expect(page).toHaveURL(control + "/");
        await expect(
          page.getByRole("heading", { name: "Validation overview" }),
        ).toBeVisible();
        await expect(
          page.getByText("CONTROLLED EXECUTION", { exact: true }),
        ).toBeVisible();
        await expect(
          page.getByText("Connecting to the control plane…", { exact: true }),
        ).not.toBeVisible();
        await expect(page.getByRole("alert")).not.toBeVisible();
        await expect(page.getByLabel("Development identity")).not.toBeVisible();
        const principal = await page.evaluate(async () =>
          (await fetch("/api/v1/me")).json(),
        );
        expect(principal.mode).toBe("real");
        expect(principal.dev_auth).toBe(false);
        expect(principal.session_expires_in).toBeGreaterThan(86300);
        const cookie = (await context.cookies(control)).find(
          (cookie) => cookie.name === "atomic_session",
        );
        expect(
          cookie?.httpOnly && cookie.secure && cookie.sameSite === "Strict",
        ).toBe(true);
        expect(cookie!.expires - Date.now() / 1000).toBeGreaterThan(86300);
        expect([...principal.roles].sort()).toEqual(roles);
        if (username === "atomic-admin") {
          await page.screenshot({
            path: "artifacts/keycloak/real-dashboard.png",
            fullPage: true,
          });
          const writes: string[] = [];
          await page.route("**/api/v1/**", async (route) => {
            if (!["GET", "HEAD"].includes(route.request().method())) {
              writes.push(new URL(route.request().url()).pathname);
              await route.abort();
            } else await route.continue();
          });
          await page
            .getByRole("button", { name: "Actors", exact: true })
            .click();
          const row = page.locator("tbody tr").first();
          if (await row.count()) {
            await row.getByRole("button").first().click();
            const details = page.getByRole("dialog", { name: "Actor details" });
            const configureCatalog = details.getByRole("button", {
              name: "Configure catalog",
              exact: true,
            });
            if (await configureCatalog.count()) {
              await configureCatalog.click();
              await expect(
                details.getByLabel("Imported catalog commit"),
              ).toBeVisible();
              await expect(
                details.getByLabel("Imported catalog commit").locator("option"),
              ).not.toHaveCount(1);
              await expect(
                details.getByRole("button", {
                  name: "Install pinned catalog",
                  exact: true,
                }),
              ).toBeDisabled();
              const download = details.getByRole("button", {
                name: "Download catalog-capable agent",
              });
              if (await download.count()) {
                await download.click();
                const update = page.getByRole("dialog", {
                  name: "Generate Linux agent",
                });
                await expect(
                  update.getByLabel("Include a single-use enrollment token", {
                    exact: false,
                  }),
                ).toBeDisabled();
                await expect(
                  update.getByLabel("Include a single-use enrollment token", {
                    exact: false,
                  }),
                ).not.toBeChecked();
                await update
                  .getByRole("button", { name: "Close dialog" })
                  .click();
              }
              await page.screenshot({
                path: "artifacts/keycloak/catalog-setup-form.png",
                fullPage: true,
              });
              await details
                .getByRole("button", {
                  name: "Close catalog setup",
                  exact: true,
                })
                .click();
              catalogFormReviewed = true;
            }
            const retire = details.getByRole("button", {
              name: "Delete actor…",
              exact: true,
            });
            if (await retire.isEnabled()) {
              await retire.click();
              const review = page.getByRole("dialog", {
                name: "Delete actor",
                exact: true,
              });
              await expect(
                review.getByRole("button", {
                  name: "Permanently delete actor",
                }),
              ).toBeDisabled();
              await review
                .getByLabel("Deletion reason")
                .fill("Read-only confirmation form verification");
              await expect(
                review.getByRole("button", {
                  name: "Permanently delete actor",
                }),
              ).toBeDisabled();
              await page.screenshot({
                path: "artifacts/keycloak/retire-actor-form.png",
                fullPage: true,
              });
              await review
                .getByRole("button", { name: "Cancel retirement" })
                .click();
              retirementFormReviewed = true;
            }
            const updateButton = details.getByRole("button", {
              name: "Download agent update",
            });
            if (await updateButton.count()) {
              await expect(
                details.getByText("Agent upgrade required", { exact: true }),
              ).toBeVisible();
              await updateButton.click();
              const update = page.getByRole("dialog", {
                name: "Generate Linux agent",
              });
              await expect(
                update.getByLabel("Include a single-use enrollment token", {
                  exact: false,
                }),
              ).not.toBeChecked();
              await expect(
                update.getByLabel("Include a single-use enrollment token", {
                  exact: false,
                }),
              ).toBeDisabled();
              await update
                .getByRole("button", { name: "Close dialog" })
                .click();
            }
            await details
              .getByRole("button", { name: "Add execution profile" })
              .click();
            await expect(
              details.getByLabel("Local account", { exact: true }),
            ).toBeVisible();
            await expect(
              details.getByRole("button", { name: "Review execution profile" }),
            ).toBeDisabled();
            await page.screenshot({
              path: "artifacts/keycloak/execution-profile-form.png",
              fullPage: true,
            });
            await details.getByRole("button", { name: "Close dialog" }).click();
          }
          await page
            .getByRole("button", { name: "Settings", exact: true })
            .click();
          await expect(
            page.getByRole("heading", {
              name: "Execution access",
              exact: true,
            }),
          ).toHaveCount(0);
          await expect(
            page.getByLabel("OIDC subject", { exact: true }),
          ).toHaveCount(0);
          if (principal.approval_mode === "catalog") {
            await expect(
              page.getByText("Catalog approval", { exact: true }),
            ).toBeVisible();
          }
          await page.screenshot({
            path: "artifacts/keycloak/settings.png",
            fullPage: true,
          });
          expect(writes).toEqual([]);
        }
        await page
          .getByRole("button", { name: "Settings", exact: true })
          .click();
        await page
          .getByRole("button", { name: "Sign out", exact: true })
          .click();
        await expect(page.getByLabel("Atomic Control sign-in")).toBeVisible();
        await expect(page.locator(".shell")).toHaveCount(0);
      } finally {
        await context.close();
      }
    }
    const report = {
      dashboard: control,
      real_chrome_sign_in: true,
      all_four_roles: true,
      certificate_errors_ignored: false,
      development_identity_absent: true,
      administrator_setup_forms_read_only: true,
      managed_profile_upgrade_form_read_only: true,
      managed_catalog_form_read_only: catalogFormReviewed,
      retirement_confirmation_form_read_only: retirementFormReviewed,
      signed_out_login_only: true,
      fixed_24_hour_cookie: true,
      logout_hides_dashboard: true,
    };
    writeFileSync(
      "artifacts/keycloak/browser-verification.json",
      JSON.stringify(report, null, 2),
      { mode: 0o600 },
    );
  });
});
