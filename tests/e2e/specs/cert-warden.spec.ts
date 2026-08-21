import { expect, Page, request as playwrightRequest, test } from '@playwright/test';

const PLUGIN_UI = '/plugin.ui/com.eduardoramos.zoraxy.certwarden/';
const CONTROL_URL = process.env.CERT_WARDEN_CONTROL_URL || 'http://localhost:8080';
const REMOTE_URL = 'https://cert-warden-mock:8443';

type StatusItem = {
  name: string;
  status: string;
  source_fingerprint: string;
  destination_fingerprint: string;
  destination_bundle_digest: string;
  key_match: boolean;
  cert_warden_query?: {
    status: string;
    http_status?: number;
    failure_kind?: string;
  };
};

async function pluginAPI(page: Page, path: string, method = 'GET', body?: unknown) {
  return page.evaluate(async ({ path, method, body }) => {
    const token = document.querySelector('meta[name="zoraxy.csrf.Token"]')?.getAttribute('content') || '';
    const response = await fetch(`./api/${path}`, {
      method,
      headers: {
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        'X-CSRF-Token': token,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    return { ok: response.ok, status: response.status, text };
  }, { path, method, body });
}

async function statusItem(page: Page, name: string): Promise<StatusItem> {
  const response = await pluginAPI(page, 'status');
  expect(response.ok, response.text).toBe(true);
  const status = JSON.parse(response.text);
  const item = status.items.find((candidate: StatusItem) => candidate.name === name);
  expect(item, `status for ${name}`).toBeTruthy();
  return item;
}

async function setScenario(scenario: string) {
  const context = await playwrightRequest.newContext();
  try {
    const response = await context.post(`${CONTROL_URL}/test/scenario/${scenario}`);
    expect(response.ok(), await response.text()).toBe(true);
  } finally {
    await context.dispose();
  }
}

async function currentScenario(): Promise<string> {
  const context = await playwrightRequest.newContext();
  try {
    const response = await context.get(`${CONTROL_URL}/health`);
    expect(response.ok(), await response.text()).toBe(true);
    const body = await response.json();
    return body.scenario;
  } finally {
    await context.dispose();
  }
}

async function waitForScenario(expected: string, timeout = 5_000) {
  await expect.poll(async () => currentScenario(), {
    message: `wait for mock scenario ${expected}`,
    timeout,
  }).toBe(expected);
}

async function createRemoteCertificate(page: Page, name: string, autoSync = false) {
  await page.getByRole('button', { name: 'Add Certificate' }).click();
  await expect(page.locator('#modal')).toBeVisible();
  await page.locator('#cert-name').fill(name);
  await page.locator('#cert-source-type').selectOption('cert_warden');
  await page.locator('#cert-warden-server-url').fill(REMOTE_URL);
  await page.locator('#cert-warden-certificate-name').fill('remote.example.com');
  await page.locator('#cert-warden-certificate-api-key').fill('cert-api-key');
  await page.locator('#cert-warden-private-key-api-key').fill('key-api-key');
  await page.locator('#cert-target-name').fill(name);
  if (!autoSync) await page.locator('#cert-auto-sync').uncheck();
  await page.locator('#cert-poll-interval').fill('60');
  if (autoSync) await expect(page.locator('#cert-auto-sync')).toBeChecked();
  await page.locator('#btn-save').click();
  await expect(page.locator('#modal')).toBeHidden({ timeout: 30_000 });
  return page.locator(`.cert-card[data-cert-name="${name}"]`);
}

test.describe('Cert Warden API source', () => {
  let name: string;

  test.beforeEach(async ({ page }, testInfo) => {
    name = `remote-${testInfo.workerIndex}-${testInfo.retry}-${Date.now()}`;
    const context = await playwrightRequest.newContext();
    try {
      const reset = await context.post(`${CONTROL_URL}/test/reset`);
      expect(reset.ok(), await reset.text()).toBe(true);
    } finally {
      await context.dispose();
    }
    await waitForScenario('valid-a');

    await page.goto(PLUGIN_UI);
    const resetConfig = await pluginAPI(page, 'config', 'POST', { log_level: 'info', certificates: [] });
    expect(resetConfig.ok, resetConfig.text).toBe(true);
    await page.reload();
  });

  test('connects and masks configured credentials @compatibility', async ({ page }) => {
    const card = await createRemoteCertificate(page, name);
    await expect(card).toBeVisible();
    await expect(card.locator('[data-status-group="cert-warden-query"] .status-healthy')).toContainText('Connected');
    await expect(card.locator('h3 .status-healthy')).toContainText('Healthy');

    const response = await pluginAPI(page, 'certificates');
    expect(response.ok, response.text).toBe(true);
    expect(response.text).not.toContain('cert-api-key');
    expect(response.text).not.toContain('key-api-key');
    const configured = JSON.parse(response.text).find((item: { name: string }) => item.name === name);
    expect(configured.cert_warden_credentials).toEqual({
      certificate_api_key_configured: true,
      private_key_api_key_configured: true,
    });

    await card.getByRole('button', { name: 'Edit' }).click();
    await expect(page.locator('#cert-warden-certificate-api-key')).toHaveAttribute('type', 'password');
    await expect(page.locator('#cert-warden-private-key-api-key')).toHaveAttribute('type', 'password');
    await expect(page.locator('#cert-warden-certificate-api-key')).toHaveValue('');
    await expect(page.locator('#cert-warden-private-key-api-key')).toHaveValue('');
    await expect(page.locator('#certificate-api-key-help')).toContainText('Configured');
    await expect(page.locator('#private-key-api-key-help')).toContainText('Configured');
  });

  test('tests unsaved connection settings without creating an entry', async ({ page }) => {
    await page.getByRole('button', { name: 'Add Certificate' }).click();
    await expect(page.locator('#modal')).toBeVisible();
    await page.locator('#cert-source-type').selectOption('cert_warden');
    await expect(page.locator('#cert-warden-source-fields')).toBeVisible();
    await page.locator('#cert-warden-server-url').fill(REMOTE_URL);
    await page.locator('#cert-warden-certificate-name').fill('remote.example.com');
    await page.locator('#cert-warden-certificate-api-key').fill('cert-api-key');
    await page.locator('#cert-warden-private-key-api-key').fill('key-api-key');
    await expect(page.locator('#btn-validate')).toBeVisible();
    await page.locator('#btn-validate').click();
    await expect(page.locator('#modal-message')).toContainText('connection and certificate are valid');
    await expect(page.locator('.cert-card')).toHaveCount(0);
  });

  test('renews valid-a to valid-b with Sync Now', async ({ page }) => {
    const card = await createRemoteCertificate(page, name);
    const before = await statusItem(page, name);
    expect(before.status).toBe('Healthy');
    expect(before.cert_warden_query?.status).toBe('Healthy');

    await setScenario('valid-b');
    await waitForScenario('valid-b');
    await card.getByRole('button', { name: 'Sync Now' }).click();

    await expect.poll(async () => (await statusItem(page, name)).destination_fingerprint).not.toBe(before.destination_fingerprint);
    const after = await statusItem(page, name);
    expect(after.status).toBe('Healthy');
    expect(after.cert_warden_query?.status).toBe('Healthy');
    expect(after.source_fingerprint).toBe(after.destination_fingerprint);
    expect(after.key_match).toBe(true);
  });

  test('automatically polls and installs valid-b at the minimum interval', async ({ page }) => {
    test.setTimeout(90_000);
    await createRemoteCertificate(page, name, true);
    const before = await statusItem(page, name);
    expect(before.status).toBe('Healthy');

    await setScenario('valid-b');
    await waitForScenario('valid-b');
    await expect.poll(
      async () => (await statusItem(page, name)).destination_fingerprint,
      { timeout: 80_000 },
    ).not.toBe(before.destination_fingerprint);

    const after = await statusItem(page, name);
    expect(after.status).toBe('Healthy');
    expect(after.cert_warden_query?.status).toBe('Healthy');
    expect(after.source_fingerprint).toBe(after.destination_fingerprint);
    expect(after.key_match).toBe(true);
  });

  test('reports authentication errors without replacing destination state', async ({ page }) => {
    await createRemoteCertificate(page, name);
    const before = await statusItem(page, name);
    await setScenario('unauthorized');
    await waitForScenario('unauthorized');

    const sync = await pluginAPI(page, `certificates/${encodeURIComponent(name)}/sync`, 'POST');
    expect(sync.ok).toBe(false);
    const after = await statusItem(page, name);
    expect(after.status).toBe('Error');
    expect(after.cert_warden_query).toMatchObject({ status: 'Error', http_status: 401, failure_kind: 'authentication' });
    expect(after.destination_fingerprint).toBe(before.destination_fingerprint);
    expect(after.destination_bundle_digest).toBe(before.destination_bundle_digest);
    expect(after.key_match).toBe(true);

    const card = page.locator(`.cert-card[data-cert-name="${name}"]`);
    await page.locator('#btn-refresh').click();
    await expect(card.locator('[data-status-group="destination"] .status-healthy')).toContainText('Healthy');
  });

  for (const scenario of ['malformed-pem', 'mismatched-pair']) {
    test(`rejects ${scenario} without replacing the destination`, async ({ page }) => {
      await createRemoteCertificate(page, name);
      const before = await statusItem(page, name);
      await setScenario(scenario);
      await waitForScenario(scenario);

      const sync = await pluginAPI(page, `certificates/${encodeURIComponent(name)}/sync`, 'POST');
      expect(sync.ok).toBe(false);
      const after = await statusItem(page, name);
      expect(after.status).toBe('Error');
      expect(after.destination_fingerprint).toBe(before.destination_fingerprint);
      expect(after.destination_bundle_digest).toBe(before.destination_bundle_digest);
    });
  }

  for (const failure of [
    { scenario: 'not-found', httpStatus: 404, kind: 'not_found' },
    { scenario: 'server-error', httpStatus: 500, kind: 'server' },
    { scenario: 'oversized-response', httpStatus: 200, kind: 'response_too_large' },
  ]) {
    test(`classifies ${failure.scenario} without replacing the destination`, async ({ page }) => {
      await createRemoteCertificate(page, name);
      const before = await statusItem(page, name);
      await setScenario(failure.scenario);
      await waitForScenario(failure.scenario);

      const sync = await pluginAPI(page, `certificates/${encodeURIComponent(name)}/sync`, 'POST');
      expect(sync.ok).toBe(false);
      const after = await statusItem(page, name);
      expect(after.status).toBe('Error');
      expect(after.cert_warden_query).toMatchObject({
        status: 'Error',
        http_status: failure.httpStatus,
        failure_kind: failure.kind,
      });
      expect(after.destination_fingerprint).toBe(before.destination_fingerprint);
      expect(after.destination_bundle_digest).toBe(before.destination_bundle_digest);
      expect(after.key_match).toBe(true);
    });
  }
});
