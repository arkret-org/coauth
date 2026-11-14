const { chromium, expect } = require(process.env.COAUTH_PLAYWRIGHT_MODULE || '@playwright/test');
const { setup, viewer, user } = require('./fixtures.cjs');
const fs = require('node:fs/promises');
const path = require('node:path');
const base = process.env.COAUTH_TEST_URL || 'http://127.0.0.1:4183';
const out = path.resolve(process.env.COAUTH_TEST_ARTIFACTS || path.join(__dirname, '../../../artifacts/frontend-preferences'));
(async () => {
  await fs.mkdir(out, { recursive: true });
  const browser = await chromium.launch({ channel: 'msedge' });
  const results = [];
  async function scenario(name, route, run, options = {}) {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    page.setDefaultTimeout(8000);
    const row = { name };
    try {
      const state = await setup(page, { base, ...options });
      await page.goto(base + route);
      await run(page, state);
      expect(state.errors).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.screenshot({ path: path.join(out, name + '.png'), fullPage: true });
      row.passed = true;
    } catch (error) { row.passed = false; row.error = String(error); await page.screenshot({ path: path.join(out, name + '-failure.png'), fullPage: true }); }
    finally { await page.close(); }
    results.push(row); console.log(JSON.stringify(row));
  }
  const changes = state => state.requests.filter(r => r.method === 'PATCH' && r.path === '/self/viewer/profile');
  async function draft(page) {
    await page.getByRole('button', { name: 'Edit profile', exact: true }).click();
    await page.getByLabel('Display name', { exact: true }).fill('保留 Alice / user-authored');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
  }
  await scenario('language-cancel-retains-draft', '/settings', async (page, state) => {
    await draft(page);
    await page.getByRole('button', { name: '中文', exact: true }).click();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog.getByRole('button', { name: 'Keep editing', exact: true })).toBeFocused();
    await page.keyboard.press('Escape');
    expect(changes(state)).toHaveLength(0);
    await page.getByRole('button', { name: 'Edit profile', exact: true }).click();
    await expect(page.getByLabel('Display name', { exact: true })).toHaveValue('保留 Alice / user-authored');
  });
  await scenario('language-save-failure-retains-page', '/settings', async (page, state) => {
    await page.getByRole('button', { name: 'Edit profile', exact: true }).waitFor();
    await page.getByRole('button', { name: '中文', exact: true }).click();
    await expect(page.locator('.language-save-error')).toContainText('Temporarily unavailable');
    await expect(page.getByRole('button', { name: 'EN', exact: true })).toHaveAttribute('aria-pressed', 'true');
    expect(changes(state)).toHaveLength(1);
  }, { overrides: { 'PATCH /self/viewer/profile': route => route.fulfill({ status: 503, json: { error: 'Temporarily unavailable' } }) } });
  await scenario('language-success-translates-content', '/', async (page, state) => {
    await page.getByRole('heading', { name: 'Account overview', exact: true }).waitFor();
    expect(state.requests.filter(r => r.path === '/self/viewer')).toHaveLength(1);
    await page.getByRole('button', { name: '中文', exact: true }).click();
    await expect(page.getByRole('heading', { name: '账号概览', exact: true })).toBeVisible();
    await expect(page.locator('.user-meta')).toContainText('Alice Chen');
    await expect(page.locator('.overview-focused')).not.toContainText('Account overview');
    expect(changes(state)).toHaveLength(1);
  });
  await scenario('language-confirm-discards-once', '/settings', async (page, state) => {
    await draft(page);
    await page.getByRole('button', { name: '中文', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Discard input and apply', exact: true }).click();
    await expect(page.getByRole('button', { name: '编辑资料', exact: true })).toBeVisible();
    await expect(page.getByRole('alertdialog')).toHaveCount(0);
    expect(changes(state)).toHaveLength(1);
  });
  await scenario('anonymous-language-switch-does-not-write-account', '/login?ui_locales=en&kind=continue_authorization_grant&id=grant-1', async (page, state) => {
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor();
    await page.getByRole('button', { name: '中文', exact: true }).click();
    await expect(page.getByRole('heading', { name: '登录', exact: true })).toBeVisible();
    expect(changes(state)).toHaveLength(0);
    const query = new URL(page.url()).searchParams;
    expect(query.get('ui_locales')).toBeNull();
    expect(query.get('id')).toBe('grant-1');
    expect(query.get('kind')).toBe('continue_authorization_grant');
  }, { overrides: { '/self/viewer': { ...viewer, viewer: { __typename: 'Anonymous', id: 'anonymous' }, viewer_session: { __typename: 'Anonymous', id: 'anonymous' } } } });
  let release; let patchStarted;
  const started = new Promise(resolve => patchStarted = resolve);
  const gate = new Promise(resolve => release = resolve);
  await scenario('language-late-edit-needs-confirmation', '/settings', async (page, state) => {
    await page.getByRole('button', { name: 'Edit profile', exact: true }).waitFor();
    await page.getByRole('button', { name: '中文', exact: true }).click();
    await started;
    await draft(page);
    release();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Keep editing', exact: true }).click();
    await expect(page.locator('.language-ready-notice')).toContainText('saved');
    await page.getByRole('button', { name: 'Edit profile', exact: true }).click();
    await expect(page.getByLabel('Display name', { exact: true })).toHaveValue('保留 Alice / user-authored');
    expect(changes(state)).toHaveLength(1);
  }, { overrides: { 'PATCH /self/viewer/profile': async (route, { reply, body }) => { patchStarted(); await gate; return reply({ profile: { ...user.profile, ...body }, principal: user.principal }); } } });
  await scenario('overview-uses-real-pending-and-neutral-passwordless', '/', async page => {
    await expect(page.locator('.overview-focused')).toContainText('pending@example.test');
    await expect(page.locator('.overview-focused')).not.toContainText('No password set');
    await expect(page.locator('.overview-focused')).toContainText('Work laptop');
    await expect(page.locator('.overview-focused')).toContainText('Personal phone');
  }, { overrides: { '/self/viewer/security': {has_password:false,active_sessions_count:3,linked_providers_count:1,verified_emails_count:0,verified_phones_count:0}, '/self/viewer': { ...viewer, viewer: { ...user, __typename: 'User', has_password: false, emails: { total_count: 1, edges: [{ cursor: 'pending', node: { id: 'pending', email: 'pending@example.test', confirmed_at: null, is_primary: true } }] } } } } });
  for (const [route, stage] of [['/recover', '第 1 步'], ['/recover/progress/recovery-1', '第 2 步'], ['/password/recovery?ticket=valid', '第 3 步']]) {
    await scenario('recovery-stage-' + stage.match(/\d/)[0], route, async page => {
      await expect(page.locator('.recovery-stage')).toContainText(stage);
      await expect(page.locator('.login-container')).toContainText(/登录|密码/);
    }, { locale: 'zh' });
  }
  for (const dark of [false, true]) for (const [route, heading] of [
    ['/security', '账号安全'], ['/sessions', '会话'], ['/identities', '身份绑定'],
    ['/notifications', '通知偏好'], ['/upstream/link/locked', '账号已锁定'], ['/upstream/link/mismatch', '账号不匹配'],
  ]) {
    await scenario('chinese-' + route.replaceAll('/', '-') + (dark ? '-dark' : '-light'), route, async page => {
      await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
      if (route === '/security') await expect(page.locator('.account-content')).toContainText('2026-10-20 10:00 +00:00');
      if (route === '/sessions') {
        await expect(page.locator('body')).toContainText(/2.*个活跃会话/);
        await expect(page.locator('body')).toContainText('Inkson desktop');
      }
      if (route.endsWith('locked')) await expect(page.locator('.login-container')).toContainText('alice');
      if (route.endsWith('mismatch')) await expect(page.locator('.login-container')).toContainText('bob');
    }, { locale: 'zh', dark });
  }
  await browser.close();
  await fs.writeFile(path.join(out, 'preferences-results.json'), JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
  if (results.some(row => !row.passed)) process.exitCode = 1;
})();
