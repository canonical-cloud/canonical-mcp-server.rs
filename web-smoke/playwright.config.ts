import { defineConfig, devices } from '@playwright/test';

// Minimal Playwright config for the canonical.cloud browser-smoke. It drives
// headless Chromium against the LIVE marketing surface, so it is scheduled /
// manual only (see .github/workflows/web-smoke.yml) and never a PR gate.
export default defineConfig({
  testDir: '.',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // Live sites are occasionally flaky (cold starts, transient 5xx); retry
  // before failing the scheduled job.
  retries: 2,
  reporter: [['list']],
  use: {
    headless: true,
    navigationTimeout: 30_000,
    actionTimeout: 15_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
