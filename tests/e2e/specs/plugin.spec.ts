import { test, expect, Page } from '@playwright/test';

const PLUGIN_UI = '/plugin.ui/com.eduardoramos.zoraxy.certwarden/';

const defaultCertificate = {
  name: 'example-certificate',
  enabled: true,
  source: {
    certificate: '/cert_warden_plugin/certchain0.pem',
    private_key: '/cert_warden_plugin/key0.pem'
  },
  destination: {
    target_directory: '/opt/zoraxy/config/conf/certs',
    target_name: 'example-certificate'
  },
  sync: { auto_sync: true, filesystem_watch: true, poll_interval_seconds: 10 },
  fallback: false
};

async function resetConfig(page: Page) {
  await page.goto(PLUGIN_UI);
  const response = await page.evaluate(async config => {
    const token = document.querySelector('meta[name="zoraxy.csrf.Token"]')?.getAttribute('content') || '';
    const result = await fetch('./api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify(config)
    });
    return { ok: result.ok, body: await result.text() };
  }, { log_level: 'info', certificates: [defaultCertificate] });
  expect(response.ok, response.body).toBe(true);
  await page.reload();
}

test.beforeEach(async ({ page }) => {
  await resetConfig(page);
});

test('plugin UI loads and shows default certificate', async ({ page }) => {
  await expect(page.locator('h1')).toContainText('Certificate File Sync');
  await expect(page.locator('#overview-content')).toContainText('Configured certificates');
});

test('certificate card shows Healthy status', async ({ page }) => {
  const card = page.locator('.cert-card').first();
  await expect(card).toBeVisible({ timeout: 15000 });
  await expect(card.locator('.status-healthy')).toContainText('Healthy');
});

test('edit modal opens and validates', async ({ page }) => {
  const card = page.locator('.cert-card').first();
  await card.locator('button:has-text("Edit")').click();
  await expect(page.locator('#modal')).toBeVisible();
  await page.locator('#btn-validate').click();
  await expect(page.locator('#modal-message')).toContainText('Certificate is valid', { timeout: 5000 });
});

test('name editing and enabled state follow add and edit behavior', async ({ page }) => {
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

  await page.reload();
  await page.locator('#btn-refresh').evaluate(button => {
    button.dispatchEvent(new Event('click'));
    button.dispatchEvent(new Event('click'));
    button.dispatchEvent(new Event('click'));
  });
  await expect(page.locator('#overview-content')).toContainText('Configured certificates: 0');
  expect(requestCount).toBe(1);
  expect(maximumActiveRequests).toBe(1);
});

test('CRUD, status, manual sync, empty deletion, and path policy errors work through Zoraxy', async ({ page }) => {
  await page.locator('#btn-add').click();
  await page.locator('#cert-name').fill('outside-policy');
  await page.locator('#cert-source-cert').fill('/etc/passwd');
  await page.locator('#cert-target-name').fill('outside-policy');
  await page.locator('#btn-save').click();
  await expect(page.locator('#modal-message')).toContainText('invalid request');
  await page.locator('.close').click();

  await page.locator('#btn-add').click();
  await page.locator('#cert-name').fill('e2e-crud');
  await page.locator('#cert-target-name').fill('e2e-crud');
  await page.locator('#cert-auto-sync').uncheck();
  await page.locator('#btn-save').click();

  const card = page.locator('.cert-card[data-cert-name="e2e-crud"]');
  await expect(card).toBeVisible();
  await expect(page.locator('#overview-content')).toContainText('Configured certificates: 2');

  await card.getByRole('button', { name: 'Edit' }).click();
  await page.locator('#cert-enabled').uncheck();
  await page.locator('#cert-target-name').fill('e2e-crud-updated');
  await page.locator('#btn-save').click();
  await expect(card).toContainText('Enabled: No');

  await card.getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#cert-enabled')).not.toBeChecked();
  await page.locator('#cert-enabled').check();
  await page.locator('#btn-save').click();
  await expect(card).toContainText('Enabled: Yes');

  await card.getByRole('button', { name: 'Sync Now' }).click();
  await expect(card.locator('.status-healthy')).toContainText('Healthy');

  page.once('dialog', dialog => dialog.accept());
  await card.getByRole('button', { name: 'Edit' }).click();
  await page.locator('#btn-delete').click();
  await expect(card).toHaveCount(0);

  const defaultCard = page.locator('.cert-card[data-cert-name="example-certificate"]');
  page.once('dialog', dialog => dialog.accept());
  await defaultCard.getByRole('button', { name: 'Edit' }).click();
  await page.locator('#btn-delete').click();
  await expect(page.locator('#cert-list')).toContainText('No certificates configured.');
  await expect(page.locator('#overview-content')).toContainText('Configured certificates: 0');
  await expect(page.locator('#overview-content').locator('.status-healthy')).toContainText('Healthy');
});
