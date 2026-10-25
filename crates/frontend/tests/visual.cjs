const {chromium,expect}=require(process.env.COAUTH_PLAYWRIGHT_MODULE||'@playwright/test');
const AxeBuilder=require(process.env.COAUTH_AXE_MODULE||'@axe-core/playwright').default;
const {setup}=require('./fixtures.cjs');const fs=require('node:fs/promises');const path=require('node:path');
(async()=>{const out=path.resolve(__dirname,'../../../artifacts/glory-migration/visual');await fs.mkdir(out,{recursive:true});const browser=await chromium.launch({channel:'msedge'});const rows=[];
for(const [version,base] of [['baseline','http://127.0.0.1:4182'],['glory',process.env.COAUTH_TEST_URL||'http://127.0.0.1:4183']])for(const dark of [false,true])for(const csp of [false,true]){const page=await browser.newPage({viewport:{width:1365,height:1000}});const state=await setup(page,{dark,csp,base});const name=version+(dark?'-dark':'-light')+(csp?'-strict':'');const row={name};try{await page.goto(base+'/');if(version==='baseline')await page.locator('#__dx-toast').evaluate(node=>node.remove()).catch(()=>{});await page.getByRole('button',{name:version==='baseline'?'Edit':'Edit profile',exact:true}).click();const dialog=page.getByRole('dialog');await expect(dialog).toBeVisible();await page.waitForTimeout(350);const desktop=await dialog.boundingBox();await page.screenshot({path:path.join(out,name+'-profile-desktop.png'),fullPage:true});await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(out,name+'-profile-mobile.png'),fullPage:true});const mobile=await dialog.boundingBox();expect(mobile.width).toBeLessThanOrEqual(390);if(version==='glory'){await dialog.getByLabel('Display name',{exact:true}).fill('CSP verified');await dialog.getByRole('button',{name:'Save',exact:true}).click();await expect(dialog).toBeHidden();}row.desktop=desktop;row.mobile=mobile;row.passed=true;}catch(error){row.passed=false;row.error=String(error);}row.errors=state.errors;row.consoleErrors=state.consoleErrors;rows.push(row);await page.close();}
for(const route of ['/login','/register','/settings','/notifications']){const context=await browser.newContext();const page=await context.newPage();const state=await setup(page);await page.goto(state.base+route);await page.locator('.layout-container').waitFor();await page.waitForTimeout(400);const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();rows.push({route,axe:result.violations.map(({id,impact,nodes})=>({id,impact,nodes:nodes.map(node=>node.target)})),passed:!result.violations.some(row=>['critical','serious'].includes(row.impact))});await context.close();}
for(const dark of [false,true]) {
  const row={name:'mobile-settings'+(dark?'-dark':'-light')+'-control-sizes'};const measured=[];
  try {
    for(const [version,base] of [['baseline','http://127.0.0.1:4182'],['glory',process.env.COAUTH_TEST_URL||'http://127.0.0.1:4183']]) {
      const page=await browser.newPage({viewport:{width:390,height:844}});await setup(page,{dark,base});await page.goto(base+'/settings');
      const signout=page.getByRole('button',{name:'Sign out',exact:true});const password=page.getByRole('link',{name:'Change password',exact:true});
      await expect(signout).toBeVisible();await expect(password).toBeVisible();
      const values={version,signout:await signout.boundingBox(),password:await password.boundingBox(),emailOverflow:await page.locator('.user-email').first().evaluate(node=>node.scrollWidth>node.clientWidth+1)};
      if(version==='glory')expect(values.emailOverflow).toBe(false);
      measured.push(values);await page.close();
    }
    for(const control of ['signout','password'])for(const dimension of ['width','height'])expect(Math.abs(measured[0][control][dimension]-measured[1][control][dimension])).toBeLessThanOrEqual(1);
    row.passed=true;row.measurements=measured;
  } catch(error){row.passed=false;row.error=String(error);row.measurements=measured;}
  rows.push(row);
}
await fs.writeFile(path.join(out,'results.json'),JSON.stringify(rows,null,2));console.log(JSON.stringify(rows.map(({name,route,passed,error,axe})=>({name,route,passed,error,axe})),null,2));await browser.close();if(rows.some(row=>!row.passed))process.exitCode=1;})();
