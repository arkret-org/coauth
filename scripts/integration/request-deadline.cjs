// Run against an actual Glory/Sapid WASM build. Pass its public directory; NODE_PATH must expose Playwright.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require(process.env.COAUTH_PLAYWRIGHT_MODULE || 'playwright');

assert.ok(process.argv[2], 'pass the static frontend directory reported by cargo metadata');
const assets = path.resolve(process.argv[2]);
const providers = { providers: [], password_login_enabled: true, password_registration_enabled: false };
const siteConfig = {id:null,email_change_allowed:false,password_login_enabled:true,account_deactivation_allowed:false,display_name_change_allowed:false,password_registration_enabled:false,registration_email_delivery_bypass_allowed:false,bootstrap_admin_token_enabled:false,minimum_password_complexity:0,imprint:null,tos_uri:null,policy_uri:null,admin_portal_url:null,plan_management_iframe_uri:null};
const viewer = { viewer: {__typename:'Anonymous',id:'anonymous'},viewer_session:{__typename:'Anonymous',id:'anonymous-session'},site_config:siteConfig };

let active;
const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname.startsWith('/_coauth/')) {
    const endpoint = pathname.slice('/_coauth'.length);
    res.setHeader('Content-Type', 'application/json');
    if (active && endpoint === active.endpoint && !active.recovered) {
      active.requests++;
      active.started ??= Date.now();
      const scenario = active;
      scenario.closed = new Promise(resolve => res.on('close', () => { if (!res.writableFinished) scenario.aborted++; resolve(); }));
      if (active.mode !== 'headers') {
        res.writeHead(active.mode === 'error-body' ? 503 : 200);
        res.write('{'); // Headers arrive, but the JSON body never completes.
      }
      return;
    }
    const payload = endpoint === '/account/auth/providers' ? providers
      : endpoint === '/self/viewer' ? viewer
      : endpoint === '/unused' ? { available_channels: [], preferences: [] }
      : siteConfig;
    res.end(JSON.stringify(payload));
    return;
  }
  try {
    let filename = path.resolve(assets, `.${decodeURIComponent(pathname)}`);
    if (filename !== assets && !filename.startsWith(assets + path.sep)) throw new Error('invalid asset path');
    if (!path.extname(filename)) filename = path.join(assets, 'index.html');
    const bytes = await fs.readFile(filename);
    const mime = { '.html': 'text/html', '.js': 'application/javascript', '.wasm': 'application/wasm', '.css': 'text/css' };
    res.setHeader('Content-Type', mime[path.extname(filename)] || 'application/octet-stream');
    res.end(bytes);
  } catch {
    res.writeHead(404).end();
  }
});

(async () => {
  await fs.access(path.join(assets, 'index.html'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true, channel: process.env.COAUTH_BROWSER_CHANNEL || 'msedge', executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH });
  try {
    for (const scenario of [
      { endpoint: '/account/auth/providers', page: '/login', mode: 'headers', seconds: 5, retry: true },
      { endpoint: '/account/auth/providers', page: '/login', mode: 'body', seconds: 5, retry: true },
      { endpoint: '/account/auth/providers', page: '/login', mode: 'error-body', seconds: 5, retry: true },
      { endpoint: '/self/viewer', page: '/', mode: 'headers', seconds: 5, retry: true },
      { endpoint: '/self/viewer', page: '/', mode: 'body', seconds: 5, retry: true },
    ]) {
      active = { ...scenario, started: null, requests: 0, aborted: 0, recovered: false };
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(origin + scenario.page);
      const alert = page.locator('.alert-critical').first();
      try {
        await alert.waitFor({ timeout: (scenario.seconds + 8) * 1000 });
      } catch (error) {
        console.error({ scenario, active, errors, body: await page.locator('body').innerText() });
        throw error;
      }
      assert.ok(active.started, 'target API request was made');
      const elapsed = Date.now() - active.started;
      assert.ok(elapsed >= (scenario.seconds - 1) * 1000 && elapsed < (scenario.seconds + 5) * 1000, `unexpected deadline: ${elapsed} ms`);
      assert.equal(active.requests, 1, 'no automatic retries');
      await page.waitForFunction(() => !document.querySelector('.loading-screen'));
      await Promise.race([active.closed, new Promise((_, reject) => setTimeout(() => reject(new Error('fetch remained open')), 1000))]);
      assert.ok(active.aborted > 0, 'timed out fetch must be aborted');
      if (scenario.retry) {
        active.recovered = true;
        await page.getByRole('button', { name: 'Try again', exact: true }).click();
        await alert.waitFor({ state: 'detached', timeout: 5000 });
        if (scenario.endpoint === '/account/auth/providers') {
          await page.getByLabel('Username', {exact: true}).waitFor();
        } else {
          await page.waitForURL(url => url.pathname === '/login');
        }
        assert.equal(active.requests, 1);
      }
      assert.deepEqual(errors, [], 'WASM page must not crash');
      console.log(`PASS ${scenario.endpoint} ${scenario.mode}: ${elapsed} ms; retry=${!!scenario.retry}`);
      await page.close();
    }
  } finally {
    await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {
  console.error(error);
  server.closeAllConnections();
  server.close();
  process.exitCode = 1;
});
