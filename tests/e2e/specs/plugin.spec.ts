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

test('name editing and enabled state follow add and edit behavior', async ({ page }) => {
  await page.goto(PLUGIN_UI);
  const card = page.locator('.cert-card').first();
  await expect(card).toBeVisible({ timeout: 15000 });
  await card.getByRole('button', { name: 'Edit' }).click();

  const name = page.locator('#cert-name');
  const enabled = page.locator('#cert-enabled');
  const originalName = await name.inputValue();
  const originalEnabled = await enabled.isChecked();
  await expect(name).toHaveAttribute('readonly', '');

  let savedBody: { name?: string; enabled?: boolean } | undefined;
  await page.route('**/api/certificates/*', async route => {
    if (route.request().method() === 'PUT') {
      savedBody = route.request().postDataJSON();
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
      return;
    }
    await route.continue();
  });
  await page.locator('#btn-save').click();
  await expect(page.locator('#modal')).toBeHidden();
  expect(savedBody).toMatchObject({ name: originalName, enabled: originalEnabled });

  await page.locator('#btn-add').click();
  await expect(name).toBeEditable();
  await expect(enabled).toBeChecked();
});

test('status refresh requests do not overlap', async ({ page }) => {
  let activeRequests = 0;
  let maximumActiveRequests = 0;
  let requestCount = 0;
  await page.route('**/api/status', async route => {
    requestCount += 1;
    activeRequests += 1;
    maximumActiveRequests = Math.max(maximumActiveRequests, activeRequests);
    await new Promise(resolve => setTimeout(resolve, 250));
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        status: 'Healthy', certificates: 0, healthy: 0, errors: 0,
        unknown: 0, disabled: 0, items: []
      })
    });
    activeRequests -= 1;
  });

  await page.goto(PLUGIN_UI);
  await page.locator('#btn-refresh').evaluate(button => {
    button.dispatchEvent(new Event('click'));
    button.dispatchEvent(new Event('click'));
    button.dispatchEvent(new Event('click'));
  });
  await expect(page.locator('#overview-content')).toContainText('Configured certificates: 0');
  expect(requestCount).toBe(1);
  expect(maximumActiveRequests).toBe(1);
});
