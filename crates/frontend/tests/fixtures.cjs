const created='2026-10-20T10:00:00Z';
const site={id:'site',email_change_allowed:true,password_login_enabled:true,account_deactivation_allowed:true,display_name_change_allowed:true,password_registration_enabled:true,registration_email_delivery_bypass_allowed:false,bootstrap_admin_token_enabled:false,minimum_password_complexity:2,imprint:'Arkret account services',tos_uri:'https://example.test/terms',policy_uri:'https://example.test/privacy',admin_portal_url:'https://admin.example.test',plan_management_iframe_uri:'https://plan.example.test'};
const browserSession={id:'browser-1',display_name:'Work laptop',user_agent:{name:'Edge',model:'Desktop',os:'Windows',device_type:'PC'},last_active_ip:'192.0.2.1',last_active_at:created,created_at:created,last_authentication:{id:'auth-1',created_at:created}};
const oauthSession={id:'app-1',display_name:'Inkson desktop',scope:'openid profile email',client:{id:'client-1',client_id:'inkson',client_name:'Inkson',client_uri:'https://inkson.example.test',logo_uri:null},user_agent:{name:'Inkson',model:'Desktop',os:'Windows',device_type:'PC'},last_active_ip:'192.0.2.1',last_active_at:created,created_at:created};
const pageInfo={has_previous_page:false,has_next_page:false,start_cursor:null,end_cursor:null};
const linked=[{id:'link-1',provider_id:'oidc-example',subject:'alice@example.test',human_account_name:'Alice',provider_name:'Example Identity',provider_brand:'oidc',created_at:created}];
const user={id:'account-1',username:'alice',principal_id:'principal-1',handle:'alice',can_request_admin:true,has_password:true,profile:{display_name:'Alice Chen',avatar_url:null,preferred_locale:'en',updated_at:created},principal:{principal_address:'@alice:example.test',display_name:'Alice Chen'},emails:{total_count:1,edges:[{cursor:'email-1',node:{id:'email-1',email:'alice@example.test',confirmed_at:created,is_primary:true}}]},linked_accounts:linked,browser_sessions:{total_count:2,edges:[{cursor:'b1',node:browserSession},{cursor:'b2',node:{...browserSession,id:'browser-2',display_name:'Personal phone',user_agent:{name:'Chrome',model:'Pixel',os:'Android',device_type:'MOBILE'}}}],page_info:pageInfo},app_sessions:{total_count:1,edges:[{cursor:'a1',node:{__typename:'OAuthSession',...oauthSession}}],page_info:pageInfo}};
const providers={providers:[{id:'oidc-example',authorize_url:'/upstream/authorize/example',human_name:'Example Identity'}],password_login_enabled:true,passkey_login_enabled:true,password_registration_enabled:true,account_recovery_allowed:true,login_hint:null,current_account:null};
const viewer={viewer:{__typename:'User',...user},viewer_session:{__typename:'BrowserSession',...browserSession},site_config:site};
async function setup(page,{dark=false,locale='en',overrides={},csp=false,base='http://127.0.0.1:4183'}={}){
  const errors=[],requests=[],consoleErrors=[];let loggedIn=true;let registrationEmail='alice@example.test';let postAuthAction=null;let notificationPrefs=[{channel:'email',enabled:true},{channel:'sms',enabled:false}];let passkeys=[{id:'passkey-1',label:'Windows Hello',backup_eligible:true,backup_state:true,user_verified:true,created_at:created,last_used_at:created}];
  page.on('pageerror',e=>errors.push(String(e)));page.on('console',message=>{if(message.type()==='error')consoleErrors.push(message.text());});
  await page.addInitScript(({dark,locale})=>{localStorage.setItem('coauth_theme',dark?'dark':'light');localStorage.setItem('arkret.ui.locale.v1',locale);},{dark,locale});
  await page.route('**/*',async route=>{
    const url=new URL(route.request().url());const path=decodeURIComponent(url.pathname);const reply=json=>route.fulfill({json});
    if(url.hostname==='plan.example.test')return route.fulfill({contentType:'text/html',body:'<h1>Plan management</h1><p>Current plan: Team</p>'});
    if(path==='/assets/avatar-fixture.svg')return route.fulfill({contentType:'image/svg+xml',body:'<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48"><rect width="48" height="48" fill="#b45309"/></svg>'});
    if(!path.startsWith('/_coauth')){
      if(csp&&route.request().resourceType()==='document'){const response=await route.fetch();return route.fulfill({response,headers:{...response.headers(),'Content-Security-Policy':"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"}});}
      return route.continue();
    }
    const p=path.slice('/_coauth'.length);
    const method=route.request().method();let body=null;try{body=route.request().postDataJSON()}catch{}
    requests.push({method,path:p,query:url.search,body,headers:route.request().headers()});
    const custom=overrides[method+' '+p]??overrides[p];if(custom!==undefined)return typeof custom==='function'?custom(route,{reply,body,requests}):reply(custom);
    if(method!=='GET'){
      if(p==='/account/auth/login')return reply(body?.password==='wrong'?{status:'error',error:'invalid_credentials'}:{status:'success',viewer:{id:'account-1',handle:'alice',federated_handle:'alice@example.test',principal_address:'@alice:example.test'}});
      if(p==='/account/auth/register'){postAuthAction=body.post_auth_action;registrationEmail=body.email||registrationEmail;return reply({status:'success',id:'registration-1',next_step:'verify_email'});}
      if(p==='/account/auth/register/registration-1/change-email'){registrationEmail=body.email;return reply({status:'updated'});}
      if(p.endsWith('/resend-verification'))return reply({status:'resent'});
      if(p.endsWith('/verify-email')||p.endsWith('/verify-phone'))return reply(body.code==='123456'?{status:'success',next_step:'display_name'}:{status:'error',error:'invalid_code'});
      if(p.endsWith('/display-name'))return reply({status:'success',next_step:'finish'});
      if(p.endsWith('/finish'))return reply({status:'success',post_auth_action:postAuthAction});
      if(p==='/account/auth/recovery')return reply({status:'success',id:'recovery-1'});
      if(p==='/account/password-recovery/resend')return reply({status:'SENT',progress_url:'/recover/progress/recovery-1'});
      if(p.includes('/recovery/')&&p.endsWith('/resend'))return reply({status:'resent'});
      if(p==='/viewer/password'||p==='/account/password-recovery/set')return reply({status:body?.current_password==='wrong'?'WRONG_PASSWORD':'ALLOWED'});
      if(p.includes('/email-auth/')&&p.endsWith('/complete'))return reply({status:body.code==='123456'?'COMPLETED':'INVALID_CODE'});
      if(p.endsWith('/resend'))return reply({status:'resent'});
      if(p==='/account/email-auth/start')return reply({status:'ADDED',email:{id:'email-2',email:body.email,confirmed_at:null,is_primary:false},violations:null});
      if(p.startsWith('/user-emails/'))return reply({status:'REMOVED'});
      if(p.startsWith('/linked-accounts/'))return reply({status:'success'});
      if(p.startsWith('/browser-sessions/')){if(p==='/browser-sessions/browser-1')loggedIn=false;return reply({status:'ENDED'});}
      if(p.startsWith('/oauth-sessions/'))return reply({status:'ENDED'});
      if(p==='/viewer/deactivate'){if(body.password==='wrong')return reply({status:'INCORRECT_PASSWORD'});loggedIn=false;return reply({status:'DEACTIVATED'});}
      if(p==='/self/viewer/profile')return reply({profile:{...user.profile,...body,updated_at:created},principal:{...user.principal,display_name:body.display_name??user.principal.display_name}});
      if(p==='/self/viewer/avatar')return reply({avatar_url:'/assets/avatar-fixture.svg'});
      if(p==='/self/viewer/preferences'){notificationPrefs=body.preferences;return reply({preferences:notificationPrefs});}
      if(p.startsWith('/self/passkeys/')){if(p.endsWith('/revoke'))passkeys=[];else passkeys[0]={...passkeys[0],label:body.label};return reply({status:'ok',id:'passkey-1'});}
      if(p.startsWith('/account/auth/passkey/'))return route.fulfill({status:503,json:{error:'Passkey ceremony is temporarily unavailable.'}});
      if(p.startsWith('/self/oauth/authorization-grants/'))return reply({status:'success',redirect_url:'/callback?code=fixture'});
      if(p.startsWith('/self/device-grants/'))return reply({status:body.action==='deny'?'rejected':'fulfilled'});
      if(p.startsWith('/self/upstream-oauth/link/'))return reply({status:'success',redirect_url:'/'});
      if(p.startsWith('/local/admin/oauth/clients/'))return reply({data:{[body.locale]:{display_name:body.display_name,description:body.description}}});
      errors.push('Unexpected mutation '+method+' '+p);return route.fulfill({status:503,json:{error:'Unexpected mutation'}});
    }
    if(p==='/account/auth/providers')return reply(providers);
    if(p==='/self/site-config')return reply(site);
    if(p==='/self/viewer')return reply(loggedIn?viewer:{...viewer,viewer:{__typename:'Anonymous',id:'anonymous'},viewer_session:{__typename:'Anonymous',id:'anonymous'}});
    if(p==='/self/viewer/security')return reply({has_password:true,active_sessions_count:3,linked_providers_count:1,verified_emails_count:1,verified_phones_count:0});
    if(p==='/self/viewer/preferences')return reply({available_channels:[{channel:'email',enabled:true},{channel:'sms',enabled:false}],preferences:notificationPrefs});
    if(p==='/self/linked-accounts')return reply({accounts:linked});
    if(p==='/self/passkeys')return reply({passkeys});
    if(p.startsWith('/self/sessions/'))return reply(p.endsWith('/app-1')?{__typename:'OAuthSession',...oauthSession}:{__typename:'BrowserSession',...browserSession,id:p.split('/').at(-1)});
    if(p.startsWith('/self/oauth-clients/'))return reply({id:'client-1',client_id:'inkson',client_name:'Inkson',client_uri:'https://inkson.example.test',tos_uri:'https://example.test/terms',policy_uri:'https://example.test/privacy',logo_uri:null});
    if(p.startsWith('/self/oauth/authorization-grants/')||p.startsWith('/self/device-grants/'))return reply({grant_id:'grant-1',client:{id:'client-1',client_id:'inkson',client_name:'Inkson',client_uri:'https://inkson.example.test',logo_uri:null},scope:'openid profile email',user:{principal_address:'@alice:example.test',display_name:'Alice Chen'},policy_violation:false});
    if(p.startsWith('/account/email-auth/'))return reply({id:'email-1',email:'alice@example.test',completed_at:null});
    if(p.startsWith('/account/auth/register/'))return reply({id:'registration-1',handle:'alice',email_pending:true,pending_email:registrationEmail,next_step:'verify_email'});
    if(p.startsWith('/account/auth/recovery/'))return reply({id:'recovery-1',email:'alice@example.test',status:'pending'});
    if(p==='/self/bootstrap-admin-status')return reply({has_admin:true,token_configured:false,setup_required:false});
    if(p.startsWith('/account/password-recovery/'))return reply({status:p.endsWith('/expired')?'expired':p.endsWith('/consumed')?'consumed':'valid',email:'alice@example.test'});
    if(p==='/device-link')return reply({status:'valid',grant_id:'device-1'});
    if(p.startsWith('/local/admin/oauth/clients/'))return reply({data:{en:{display_name:'Inkson',description:'Team communications'},'zh-CN':{display_name:'Inkson',description:'团队协作客户端'}}});
    if(p.startsWith('/self/upstream-oauth/link/')){const id=p.split('/').at(-1);return reply(id==='register'?{state:'register',suggested_handle:'alice',handle_forced:false,suggested_display_name:'Alice Chen',display_name_forced:false,suggested_email:'alice@example.test',email_forced:false,provider_name:'Example Identity',has_tos:true}:id==='mismatch'?{state:'link_mismatch',existing_handle:'bob'}:id==='locked'?{state:'account_locked',handle:'alice'}:id==='error'?{state:'error',code:'link_expired',description:'This link request has expired.'}:{state:'suggest_link',provider_name:'Example Identity',upstream_subject:'alice@example.test'});}
    errors.push('Missing fixture '+route.request().method()+' '+p);return route.fulfill({status:503,json:{error:'Fixture missing '+p}});
  });return {errors,requests,consoleErrors,base};
}
module.exports={setup,site,user,viewer,providers,browserSession,oauthSession};
