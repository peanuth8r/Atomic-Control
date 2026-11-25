import { test, expect } from '@playwright/test';
import { createHash, randomUUID } from 'node:crypto';
import { asUser } from './test-identity';

test('custom API submission retains files for administrator review without execution', async ({ page }) => {
  await page.goto('/');
  await asUser(page, 'operator');
  const guid = randomUUID();
  const name = `Custom submission ${guid}`;
  const path = 'atomics/T1082/src/custom-fixture.txt';
  const bytes = Buffer.from('isolated fixture; never executed');
  const content = `attack_technique: T1082
display_name: System Information Discovery
atomic_tests:
- name: ${name}
  auto_generated_guid: ${guid}
  description: Browser review fixture only.
  supported_platforms: [windows]
  executor:
    name: command_prompt
    command: echo fixture
`;
  let executionRequests = 0;
  page.on('request', (request) => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/v1/runs') executionRequests++;
  });
  const added = await page.request.post('/api/v1/catalog/custom-tests', {
    headers: { 'Idempotency-Key': guid },
    data: { content, files: [{ path, content_base64: bytes.toString('base64') }] },
  });
  expect(added.status()).toBe(201);
  expect((await added.json()).status).toBe('submitted');
  await asUser(page, 'admin');
  await page.getByRole('button', { name: 'Test Catalog', exact: true }).click();
  await page.getByLabel('Search catalog').fill(guid);
  const row = page.locator('tbody tr').filter({ hasText: guid });
  await expect(row).toContainText('Custom test');
  await row.getByRole('button', { name, exact: true }).click();
  const files = page.getByRole('region', { name: 'Supporting test files' });
  await expect(files.getByText('Submitted supporting files await your review', { exact: false })).toBeVisible();
  await expect(files.getByRole('listitem').getByText(path, { exact: true })).toBeVisible();
  await expect(files.getByText(createHash('sha256').update(bytes).digest('hex'), { exact: true })).toBeVisible();
  await page.getByLabel('Standard User', { exact: true }).check();
  await page.getByRole('button', { name: 'Approve test', exact: true }).click();
  await expect(page.getByText('Definition approved.', { exact: false })).toBeVisible();
  const detail = await page.request.get(`/api/v1/tests/${guid}`);
  expect((await detail.json()).approved).toBe(true);
  expect(executionRequests).toBe(0);
});
