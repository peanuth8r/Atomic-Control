import { type Page } from '@playwright/test';
// Only the isolated tests/support server recognizes this cookie.
export async function asUser(page: Page, user: string) {
  const heading = await page.locator(".page-heading h1").textContent();
  const origin = new URL(page.url());
  await page.context().addCookies([{ name: 'atomic_test_user', value: user, url: origin.origin }]);
  await page.reload();
  if (heading && heading !== "Validation overview") await page.getByRole("button", {name: heading, exact:true}).click();
}
