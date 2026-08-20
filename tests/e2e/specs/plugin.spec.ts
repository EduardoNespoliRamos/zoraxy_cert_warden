import { test, expect } from '@playwright/test';

const PLUGIN_UI = '/plugin.ui/com.eduardoramos.zoraxy.certwarden/';

test('plugin UI loads and shows default certificate', async ({ page }) => {
  await page.goto(PLUGIN_UI);
  await expect(page.locator('h1')).toContainText('Certificate File Sync');
  await expect(page.locator('#overview-content')).toContainText('Configured certificates');
});

test('certificate card shows Healthy status', async ({ page }) => {
  await page.goto(PLUGIN_UI);
  const card = page.locator('.cert-card').first();
  await expect(card).toBeVisible({ timeout: 15000 });
  await expect(card.locator('.status-healthy')).toContainText('Healthy');
});

test('edit modal opens and validates', async ({ page }) => {
  await page.goto(PLUGIN_UI);
  const card = page.locator('.cert-card').first();
  await card.locator('button:has-text("Edit")').click();
  await expect(page.locator('#modal')).toBeVisible();
  await page.locator('#btn-validate').click();
  await expect(page.locator('#modal-message')).toContainText('Certificate is valid', { timeout: 5000 });
});
