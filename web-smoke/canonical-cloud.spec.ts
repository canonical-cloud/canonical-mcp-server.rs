import { test, expect } from '@playwright/test';

// Browser-smoke for the canonical.cloud web surface.
//
// Primary, reliably-live surface: https://canonical.cloud — the marketing site
// served by canonical-web-server.rs (the Astro static build is the server's
// fallback for the apex). This carries the one HARD assertion that makes the
// job meaningful.
const PRIMARY = 'https://canonical.cloud';

// Secondary surface: the same Astro site published to GitHub Pages at the
// canonical.plus custom domain. Per the stack docs its DNS may still be
// delegated to Squarespace, so this check is TOLERANT — it logs and soft-skips
// rather than failing the job.
const MIRROR = 'https://canonical.plus';

// Stable, on-brand strings from the Astro build (src/pages/index.astro +
// BaseLayout.astro): the hero headline and the "| canonical.cloud" title
// suffix. Chosen to survive copy/layout tweaks better than exact markup.
const HERO_TEXT = 'Compliance Audits';
const BRAND_TITLE = /canonical\.cloud/i;

test('canonical.cloud marketing site is live and on-brand', async ({ page }) => {
  const response = await page.goto(PRIMARY, { waitUntil: 'domcontentloaded' });
  expect(response, `no response from ${PRIMARY}`).not.toBeNull();
  expect(
    response!.status(),
    `unexpected status from ${PRIMARY}`,
  ).toBeLessThan(400);
  await expect(page).toHaveTitle(BRAND_TITLE);
  await expect(page.locator('body')).toContainText(HERO_TEXT);
});

test('canonical.plus mirror (tolerant; DNS may still be on Squarespace)', async ({
  page,
}) => {
  let response;
  try {
    response = await page.goto(MIRROR, {
      waitUntil: 'domcontentloaded',
      timeout: 15_000,
    });
  } catch (error) {
    test.skip(
      true,
      `${MIRROR} unreachable (${(error as Error).message}); tolerating non-primary surface.`,
    );
    return;
  }

  if (!response || response.status() >= 400) {
    test.skip(
      true,
      `${MIRROR} not serving the Pages mirror yet (status ${response?.status() ?? 'none'}); tolerating.`,
    );
    return;
  }

  const body = await page.locator('body').innerText();
  if (body.includes(HERO_TEXT)) {
    // The Pages mirror is live and on-brand — assert it too.
    await expect(page).toHaveTitle(/canonical/i);
  } else {
    // Reachable but not (yet) the Pages mirror — likely a Squarespace
    // placeholder while DNS handoff is pending. Tolerate.
    console.warn(
      `${MIRROR} reachable but not yet the canonical.cloud Pages mirror; tolerating.`,
    );
  }
});
