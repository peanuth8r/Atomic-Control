import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: '../../tests/e2e',
  timeout: 30000,
  use: {
    baseURL: process.env.ATOMIC_DASHBOARD_TEST_URL || 'http://127.0.0.1:15173',
    headless: true,
    launchOptions: {
      executablePath:
        process.env.ATOMIC_CHROME_PATH ||
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    },
  },
  reporter: 'list',
  outputDir: '../../artifacts/playwright',
});
