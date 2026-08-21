import { defineConfig, devices } from '@playwright/test';

const suite = process.env.E2E_SUITE || 'compatibility';

export default defineConfig({
  testDir: './specs',
  testMatch: suite === 'certwarden-api' ? '**/cert-warden.spec.ts' : undefined,
  grep: suite === 'compatibility' ? /@compatibility/ : undefined,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  outputDir: 'test-results',
  use: {
    baseURL: process.env.ZORAXY_URL || 'http://localhost:8000',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chromium'] },
    },
  ],
});
