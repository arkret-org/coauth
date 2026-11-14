const { chromium, expect } = require(process.env.COAUTH_PLAYWRIGHT_MODULE || '@playwright/test');
const { setup } = require('./fixtures.cjs');
const fs = require('node:fs/promises');
const path = require('node:path');
const base = process.env.COAUTH_TEST_URL || 'http://127.0.0.1:4183';
const out = path.resolve(process.env.COAUTH_TEST_ARTIFACTS || path.join(__dirname, '../../../artifacts/frontend-design'));

(async () => {
  await fs.mkdir(out, { recursive: true });
  const browser = await chromium.launch({ channel: process.env.COAUTH_BROWSER_CHANNEL || 'msedge' });
  const results = [];
  const revocations = state => state.requests.filter(r => r.method === 'POST' && r.path === '/self/passkeys/passkey-1/revoke');
  for (const locale of ['en', 'zh']) for (const dark of [false, true]) {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    const row = { locale, dark };
    try {
      const state = await setup(page, { base, locale, dark });
      await page.goto(base + '/security');
      const trigger = page.getByRole('button', { name: locale === 'en' ? 'Remove' : '移除', exact: true });
      const dialog = page.getByRole('alertdialog');
      const cancel = dialog.getByRole('button', { name: locale === 'en' ? 'Cancel' : '取消', exact: true });
      await trigger.click();
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText('Windows Hello');
      await expect(dialog).toContainText('passkey-1');
      await expect(cancel).toBeFocused();
      expect(revocations(state)).toHaveLength(0);
      await page.keyboard.press('Escape');
      await expect(dialog).toBeHidden();
      await expect(trigger).toBeFocused();
      expect(revocations(state)).toHaveLength(0);
      await trigger.click();
      await cancel.click();
      await expect(dialog).toBeHidden();
      expect(revocations(state)).toHaveLength(0);
      await trigger.click();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      const contrast = await dialog.locator('.sapid-alert-dialog-confirm').evaluate(element => {
        const style = getComputedStyle(element);
        const luminance = color => color.match(/[\d.]+/g).slice(0, 3).map(Number).map(c => c / 255)
          .map(c => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
          .reduce((sum, c, index) => sum + c * [0.2126, 0.7152, 0.0722][index], 0);
        const [low, high] = [luminance(style.color), luminance(style.backgroundColor)].sort((a, b) => a - b);
        return (high + 0.05) / (low + 0.05);
      });
      expect(contrast).toBeGreaterThanOrEqual(4.5);
      row.confirm_text_contrast = contrast;
      await page.screenshot({ path: path.join(out, `passkey-confirm-${locale}-${dark ? 'dark' : 'light'}.png`) });
      await dialog.getByRole('button', { name: locale === 'en' ? 'Remove passkey' : '确认移除 Passkey', exact: true }).click();
      await expect(trigger).toHaveCount(0);
      expect(revocations(state)).toHaveLength(1);
      expect(state.errors).toEqual([]);
      row.passed = true;
    } catch (error) {
      row.passed = false;
      row.error = String(error);
      await page.screenshot({ path: path.join(out, `passkey-failure-${locale}-${dark}.png`), fullPage: true });
    } finally { await page.close(); }
    results.push(row);
  }
  const page = await browser.newPage();
  const row = { name: 'revoke-failure-preserves-key' };
  try {
    const state = await setup(page, { base, overrides: {
      'POST /self/passkeys/passkey-1/revoke': route => route.fulfill({ status: 503, contentType: 'application/problem+json', body: JSON.stringify({ type: 'about:blank', title: 'Temporarily unavailable', status: 503, detail: 'Please try again.' }) }),
    } });
    await page.goto(base + '/security');
    const trigger = page.getByRole('button', { name: 'Remove', exact: true });
    await trigger.click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Remove passkey', exact: true }).click();
    await expect(page.getByRole('alert').last()).toBeVisible();
    await expect(trigger).toBeEnabled();
    await expect(page.getByLabel('Passkey name', { exact: true })).toHaveValue('Windows Hello');
    expect(revocations(state)).toHaveLength(1);
    await trigger.click();
    await expect(page.getByRole('alertdialog')).toContainText('passkey-1');
    row.passed = true;
  } catch (error) { row.passed = false; row.error = String(error); }
  results.push(row);
  await page.close();
  await browser.close();
  await fs.writeFile(path.join(out, 'passkey-results.json'), JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
  if (results.some(result => !result.passed)) process.exitCode = 1;
})();
