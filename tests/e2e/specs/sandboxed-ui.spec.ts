import { test, expect, Frame, Page } from '@playwright/test';

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

function pluginBaseURL(): string {
  return process.env.ZORAXY_URL || 'http://localhost:8000';
}

async function loadSandboxedPlugin(page: Page): Promise<Frame> {
  const pluginURL = new URL(PLUGIN_UI, pluginBaseURL()).href;

  // Navigate to the plugin UI to establish the Zoraxy session/cookies on this origin.
  // Then replace the page with a sandboxed iframe pointing to the same plugin URL.
  // Keeping the parent page same-origin ensures cookies are sent with the iframe request.
  await page.goto(pluginURL);
  await page.waitForSelector('#btn-add', { timeout: 15_000 });

  await page.evaluate(url => {
    document.open();
    document.write(`
      <!DOCTYPE html>
      <html>
        <head><title>Sandboxed Plugin Test</title></head>
        <body style="margin:0">
          <iframe
            id="plugin-frame"
            sandbox="allow-scripts allow-same-origin"
            src="${url}"
            style="width:100vw;height:100vh;border:none;">
          </iframe>
        </body>
      </html>
    `);
    document.close();
  }, pluginURL);

  await expect.poll(
    () => page.mainFrame().childFrames().length,
    { message: 'wait for sandboxed plugin frame', timeout: 15_000 }
  ).toBeGreaterThan(0);
  const frame = page.mainFrame().childFrames()[0];
  if (!frame) throw new Error('sandboxed plugin frame not found');
  await expect(frame.locator('#btn-add')).toBeVisible({ timeout: 15_000 });
  return frame;
}

async function resetConfig(frame: Frame, certificates: unknown[]) {
  const response = await frame.evaluate(async config => {
    const token = document.querySelector('meta[name="zoraxy.csrf.Token"]')?.getAttribute('content') || '';
    const result = await fetch('./api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify(config)
    });
    return { ok: result.ok, body: await result.text() };
  }, { log_level: 'info', certificates });
  expect(response.ok, response.body).toBe(true);
}

test.describe('sandboxed plugin UI @compatibility', () => {
  test.beforeEach(async ({ page }) => {
    let frame = await loadSandboxedPlugin(page);
    await resetConfig(frame, [defaultCertificate]);
    frame = await loadSandboxedPlugin(page);
    await expect(frame.locator('.cert-card')).toBeVisible({ timeout: 15_000 });
  });

  test('saves a new certificate inside a sandboxed iframe', async ({ page }) => {
    const frame = await loadSandboxedPlugin(page);

    await frame.getByRole('button', { name: 'Add Certificate' }).click();
    await expect(frame.locator('#modal')).toBeVisible();
    await frame.locator('#cert-name').fill('sandbox-saved');
    await frame.locator('#cert-source-cert').fill('/cert_warden_plugin/certchain0.pem');
    await frame.locator('#cert-source-key').fill('/cert_warden_plugin/key0.pem');
    await frame.locator('#cert-target-name').fill('sandbox-saved');
    await frame.locator('#cert-auto-sync').uncheck();
    await frame.locator('#btn-save').click();

    await expect(frame.locator('#modal')).toBeHidden();
    const card = frame.locator('.cert-card[data-cert-name="sandbox-saved"]');
    await expect(card).toBeVisible();
    await expect(frame.locator('#overview-content')).toContainText('Configured certificates: 2');
  });

  test('deletes a certificate inside a sandboxed iframe', async ({ page }) => {
    const frame = await loadSandboxedPlugin(page);

    const card = frame.locator('.cert-card[data-cert-name="example-certificate"]');
    await card.getByRole('button', { name: 'Edit' }).click();
    await frame.locator('#btn-delete').click();
    await expect(frame.locator('#btn-delete')).toContainText('Confirm Delete');
    await frame.locator('#btn-delete').click();

    await expect(card).toHaveCount(0);
    await expect(frame.locator('#cert-list')).toContainText('No certificates configured.');
  });
});
