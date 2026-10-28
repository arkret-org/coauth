import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  expect, test, withOperationSelectors,
  type APIRequestContext, type APIResponse, type Page,
} from "../../../cotest/e2e/helpers/arkret-test";
import {
  registerCoauthPasswordAccount, registerUnboundCoauthPasswordAccount,
  type CoauthPasswordAccount,
} from "../../../cotest/e2e/helpers/coauth-register";
import { createDpopUserSessionForAccount } from "../../../cotest/e2e/helpers/users";
import {
  createRealmApi, sendMessageApi, scanRealmStreamApi, signedEventEnvelope,
  rawSubmitSignedEventApi, resolveDefaultStrandId,
} from "../../../cotest/e2e/helpers/coland-api";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing integration deployment input ${name}`);
  return value;
}

const coauth = required("COTEST_COAUTH_BASE_URL").replace(/\/$/, "");
const coauthBin = required("COAUTH_INTEGRATION_COAUTH_BIN");
const coauthConfig = required("COAUTH_INTEGRATION_COAUTH_CONFIG");
const approvalBin = required("COAUTH_INTEGRATION_APPROVAL_BIN");
required("COTEST_WIRE_BIN");
required("COTEST_COLAND_BASE_URL");
required("COTEST_COLAND_SERVICE_ID");
required("COTEST_OIDC_CLIENT_ID");

async function jsonOk(response: APIResponse, stage: string): Promise<any> {
  // Do not print authenticated response bodies: they can carry custody or JWTs.
  expect(response.ok(), `${stage}: HTTP ${response.status()}`).toBe(true);
  return response.json();
}

async function protocolRejection(response: APIResponse, status: number, code: string) {
  const body = await response.json();
  // Only expose the registered problem boundary, never authenticated payloads.
  const boundary = `HTTP ${response.status()}, type=${String(body.type)}, code=${String(body.code ?? body.reason_code)}, status=${String(body.status)}`;
  expect(response.status(), boundary).toBe(status);
  expect(body.type, boundary).toBe(`https://arkret.org/problems/${code}`);
}

async function productLogin(request: APIRequestContext, account: { handle: string; password: string }) {
  const result = await jsonOk(await request.post(`${coauth}/_coauth/account/auth/login`, {
    data: { handle: account.handle, password: account.password },
  }), "password browser login");
  expect(result.status).toBe("success");
}

async function browserCredential(page: Page, challenge: any, kind: "create" | "get") {
  return page.evaluate(async ({ challenge, kind }) => {
    const decode = (value: string) => {
      const padded = value.replace(/-/g, "+").replace(/_/g, "/");
      return Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
    };
    const encode = (value: ArrayBuffer | null) => value === null ? null :
      btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const publicKey = challenge.publicKey;
    publicKey.challenge = decode(publicKey.challenge);
    if (kind === "create") {
      publicKey.user.id = decode(publicKey.user.id);
      publicKey.excludeCredentials = (publicKey.excludeCredentials ?? []).map((c: any) => ({ ...c, id: decode(c.id) }));
    } else {
      publicKey.allowCredentials = (publicKey.allowCredentials ?? []).map((c: any) => ({ ...c, id: decode(c.id) }));
    }
    const credential = await (kind === "create"
      ? navigator.credentials.create({ publicKey })
      : navigator.credentials.get({ publicKey })) as PublicKeyCredential;
    if (!credential) throw new Error("browser returned no WebAuthn credential");
    const response = credential.response;
    const common = {
      id: credential.id, rawId: encode(credential.rawId), type: credential.type,
      extensions: credential.getClientExtensionResults(),
    };
    return kind === "create" ? {
      ...common,
      response: {
        clientDataJSON: encode(response.clientDataJSON),
        attestationObject: encode((response as AuthenticatorAttestationResponse).attestationObject),
        transports: (response as AuthenticatorAttestationResponse).getTransports(),
      },
    } : {
      ...common,
      response: {
        clientDataJSON: encode(response.clientDataJSON),
        authenticatorData: encode((response as AuthenticatorAssertionResponse).authenticatorData),
        signature: encode((response as AuthenticatorAssertionResponse).signature),
        userHandle: encode((response as AuthenticatorAssertionResponse).userHandle),
      },
    };
  }, { challenge, kind });
}

async function adminBearer(request: APIRequestContext, account: CoauthPasswordAccount): Promise<string> {
  // Deployment administration explicitly grants request eligibility, not a token.
  execFileSync(coauthBin, ["--config", coauthConfig, "--no-env-overrides", "manage", "promote-admin", account.handle], { stdio: "pipe" });
  await productLogin(request, account);
  const discovery = await jsonOk(await request.get(`${coauth}/.well-known/openid-configuration`), "OIDC discovery");
  const clientId = required("COTEST_OIDC_CLIENT_ID");
  const redirectUri = "http://127.0.0.1/auth/callback";
  const state = randomBytes(24).toString("base64url");
  const verifier = randomBytes(32).toString("base64url");
  const authorize = new URL(discovery.authorization_endpoint);
  Object.entries({
    response_type: "code", client_id: clientId, redirect_uri: redirectUri,
    scope: "openid urn:coauth:admin", state,
    nonce: randomBytes(24).toString("base64url"),
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  }).forEach(([key, value]) => authorize.searchParams.set(key, value));
  const authorization = await request.get(authorize.toString(), { maxRedirects: 0 });
  expect([302, 303, 307, 308]).toContain(authorization.status());
  const approval = new URL(authorization.headers().location, coauth);
  expect(approval.pathname).toContain("/oauth/approval/");
  const id = approval.pathname.split("/").filter(Boolean).at(-1);
  const consentUrl = `${coauth}/_coauth/self/oauth/authorization-grants/${id}/decision`;
  const consent = await jsonOk(await request.get(consentUrl), "admin OAuth consent context");
  expect(typeof consent.csrf_token).toBe("string");
  const decision = await jsonOk(await request.post(consentUrl, {
    headers: { Origin: new URL(coauth).origin },
    data: { action: "approve", csrf_token: consent.csrf_token },
  }), "admin OAuth authorization decision");
  expect(decision.status).toBe("success");
  const callback = new URL(decision.redirect_url);
  expect(callback.searchParams.get("state")).toBe(state);
  const code = callback.searchParams.get("code");
  expect(code).toBeTruthy();
  const token = await jsonOk(await request.post(discovery.token_endpoint, {
    form: {
      grant_type: "authorization_code", client_id: clientId,
      redirect_uri: redirectUri, code: code!, code_verifier: verifier,
    },
  }), "user-bound admin OAuth bearer");
  expect(token.token_type.toLowerCase()).toBe("bearer");
  expect(token.scope.split(" ")).toContain("urn:coauth:admin");
  return token.access_token;
}

function approvalProof(account: CoauthPasswordAccount, proposalId: string, accountId: string, ticket: string, note: string): string {
  const checkpoint = account.principalRegistrationCheckpoint;
  const signed = execFileSync(approvalBin, [], {
    input: JSON.stringify({
      recovery_key: account.recoveryKey, principal_did: account.did,
      root_public_key_multibase: checkpoint.root_public_key_multibase,
      root_verification_method: checkpoint.root_verification_method,
      proposal_id: proposalId, account_id: accountId, action: "disable", ticket,
      approval_note: note, approved_by: account.id,
    }), encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
  });
  return JSON.parse(signed).approval_proof_jws;
}

test("S1 account → accepted PCR → signed Realm/Strand/Event → authenticated read", async ({ request, browser }) => {
  const account = await registerCoauthPasswordAccount(request, coauth, { handle: `int-s1-${randomUUID()}` });
  expect(account.pcrGenesisCommits).toHaveLength(2);
  expect(account.principalRegistrationCheckpoint.binding_receipt).toMatchObject({ binding_state: "bound", principal_id: account.id });
  const session = await createDpopUserSessionForAccount(request, "integration-s1", account);
  expect(session, "accepted founding device session").toBeTruthy();
  const token = session!.grantJwt;
  const realmId = await createRealmApi(request, token, { title: "Coauth integration", ownerId: account.id });
  const strandId = await resolveDefaultStrandId(request, token, realmId);
  expect(strandId).toMatch(/^ak:strand:/);
  const message = await sendMessageApi(request, token, realmId, "integration-real-message");
  const before = await scanRealmStreamApi(request, token, realmId);
  expect(before.events.find(event => event.event_id === message.event_id)).toMatchObject({
    kind: "ak.message.create", realm_id: realmId,
    payload: { strand_id: strandId, content: { kind: "ak.content.text", body: "integration-real-message" } },
  });
  expect(before.commits.find(commit => commit.event_ref === message.event_id)).toMatchObject({
    realm_id: realmId, stream_ref: { kind: "realm", realm_id: realmId },
  });

  const invalid = signedEventEnvelope({ actorId: account.id, realmId, kind: "ak.message.create", payload: {
    strand_id: strandId, track_name: "discussion", content: { kind: "ak.content.text", body: "rejected-invalid-proof" },
  } });
  const proof = invalid.producer_proof as Record<string, string>;
  proof.jws = proof.jws.slice(0, -8) + "AAAAAAAA";
  const rejected = await rawSubmitSignedEventApi(request, token, invalid);
  await protocolRejection(rejected, 401, "signature_invalid");
  const after = await scanRealmStreamApi(request, token, realmId);
  expect(after.events.map(event => event.event_id)).toEqual(before.events.map(event => event.event_id));
  expect(after.commits.map(commit => commit.commit_id)).toEqual(before.commits.map(commit => commit.commit_id));

  const other = await test.step("another accepted principal cannot write with this holder's grant", async () => {
    const created = await registerCoauthPasswordAccount(request, coauth, { handle: `int-other-${randomUUID()}` });
    await createDpopUserSessionForAccount(request, "integration-other", created);
    return created;
  });
  const wrongActor = signedEventEnvelope({ actorId: other.id, realmId, kind: "ak.message.create", payload: {
    strand_id: strandId, track_name: "discussion", content: { kind: "ak.content.text", body: "rejected-wrong-subject" },
  } });
  const wrongSubject = await rawSubmitSignedEventApi(request, token, wrongActor);
  await protocolRejection(wrongSubject, 403, "capability_denied");
  const afterWrongSubject = await scanRealmStreamApi(request, token, realmId);
  expect(afterWrongSubject.events.map(event => event.event_id)).toEqual(before.events.map(event => event.event_id));
  expect(afterWrongSubject.commits.map(commit => commit.commit_id)).toEqual(before.commits.map(commit => commit.commit_id));

  await test.step("real browser denial returns access_denied in query and form_post", async () => {
    await productLogin(request, account);
    const discovery = await jsonOk(await request.get(`${coauth}/.well-known/openid-configuration`), "denial OIDC discovery");
    for (const mode of ["query", "form_post"]) {
      await test.step(`real ${mode} denial callback`, async () => {
        const context = await browser.newContext({
          storageState: await request.storageState(),
          ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
        });
        try {
          // This route is the registered RP callback: observe the actual browser
          // request after the product decision, without constructing its payload.
          const callbackUrl = new URL("http://127.0.0.1/auth/callback");
          await context.route(`${callbackUrl}**`, route => route.fulfill({ status: 200, body: "RP received callback" }));
          const page = await context.newPage();
          const state = randomBytes(24).toString("base64url");
          const authorize = new URL(discovery.authorization_endpoint);
          Object.entries({
            response_type: "code", client_id: required("COTEST_OIDC_CLIENT_ID"),
            redirect_uri: callbackUrl.toString(), scope: "openid",
            response_mode: mode, state, nonce: randomBytes(24).toString("base64url"),
            code_challenge: createHash("sha256").update(randomBytes(32)).digest("base64url"),
            code_challenge_method: "S256",
          }).forEach(([key, value]) => authorize.searchParams.set(key, value));
          const navigation = await page.goto(authorize.toString());
          expect(navigation?.status(), `${mode} approval page`).toBe(200);
          const scriptSrc = await page.locator('script[type="module"][src]').getAttribute("src");
          expect(scriptSrc, `${mode} real frontend entry`).toBeTruthy();
          const scriptUrl = new URL(scriptSrc!, page.url());
          expect(scriptUrl.origin).toBe(new URL(coauth).origin);
          expect(scriptUrl.pathname).toMatch(/^\/(?:assets|wasm)\/coauth-frontend(?:-[^/]+)?\.js$/);
          const asset = await context.request.get(scriptUrl.toString());
          expect(asset.status(), `${mode} served frontend JavaScript`).toBe(200);
          expect(asset.headers()["content-type"]).toMatch(/^(?:text|application)\/(?:javascript|ecmascript)(?:;|$)/);
          const deny = page.getByTestId("coauth-oauth-deny");
          await expect(deny, `${mode} real consent control`).toBeVisible({ timeout: 30_000 });
          const [callback] = await Promise.all([
            page.waitForRequest(reply => {
              const url = new URL(reply.url());
              return reply.isNavigationRequest() && url.origin === callbackUrl.origin && url.pathname === callbackUrl.pathname;
            }, { timeout: 30_000 }),
            (async () => {
              const [decision] = await Promise.all([
                page.waitForResponse(reply => {
                  const url = new URL(reply.url());
                  return url.origin === new URL(coauth).origin && url.pathname.endsWith("/decision") && reply.request().method() === "POST";
                }, { timeout: 30_000 }),
                deny.click({ timeout: 30_000 }),
              ]);
              expect(decision.status(), `${mode} real denial decision`).toBe(200);
            })(),
          ]);
          expect(callback.method()).toBe(mode === "form_post" ? "POST" : "GET");
          const parameters = mode === "form_post"
            ? new URLSearchParams(callback.postData()!) : new URL(callback.url()).searchParams;
          expect(parameters.get("state")).toBe(state);
          expect(parameters.get("error")).toBe("access_denied");
          for (const credential of ["code", "id_token", "access_token"]) expect(parameters.has(credential)).toBe(false);
        } finally {
          await context.close();
        }
      });
    }
  });
});

test("S2 browser WebAuthn registration/assertion, origin/session/challenge/expiry/replay rejection", async ({ browser }) => {
  // The product ceremony has a ten-minute TTL. This test waits for actual
  // expiry rather than injecting a clock, editing storage or relaxing checks.
  test.setTimeout(720_000);
  const context = await browser.newContext({ ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1" });
  const request = withOperationSelectors(context.request);
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  try {
    const handle = `int-s2-${randomUUID()}`;
    const account = await registerUnboundCoauthPasswordAccount(request, coauth, { handle });
    await productLogin(request, account);
    await page.goto(`${coauth}/health`);
    expect(await page.evaluate(() => isSecureContext)).toBe(true);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    } });
    const start = await jsonOk(await request.post(`${coauth}/_coauth/account/auth/passkey/register/start`, { data: {} }), "register ceremony");
    // Obtain the negative attestation before saving a passkey so the browser
    // does not stop at excludeCredentials before the server checks challenge.
    const badChallengeStart = await jsonOk(await request.post(`${coauth}/_coauth/account/auth/passkey/register/start`, { data: {} }), "negative challenge ceremony");
    const badAttestation = await browserCredential(page, badChallengeStart.challenge, "create");
    const clientData = JSON.parse(Buffer.from(badAttestation.response.clientDataJSON!, "base64url").toString("utf8"));
    clientData.challenge = randomBytes(32).toString("base64url");
    badAttestation.response.clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString("base64url");
    expect((await request.post(`${coauth}/_coauth/account/auth/passkey/register/finish`, {
      data: { ceremony_id: badChallengeStart.ceremony_id, attestation: badAttestation },
    })).status()).toBe(400);
    expect((await jsonOk(await request.get(`${coauth}/_coauth/self/passkeys`), "rejected challenge inventory")).passkeys).toHaveLength(0);
    const attestation = await browserCredential(page, start.challenge, "create");
    const registerBody = { ceremony_id: start.ceremony_id, label: "Integration authenticator", attestation };
    const registered = await jsonOk(await request.post(`${coauth}/_coauth/account/auth/passkey/register/finish`, { data: registerBody }), "browser attestation");
    expect(registered.account_id).toBe(start.account_id);
    expect((await request.post(`${coauth}/_coauth/account/auth/passkey/register/finish`, { data: registerBody })).status()).toBe(400);
    const before = await jsonOk(await request.get(`${coauth}/_coauth/self/passkeys`), "passkey inventory");
    expect(before.passkeys).toHaveLength(1);
    expect(before.passkeys[0]).not.toHaveProperty("public_key");
    const crossOrigin = await request.post(`${coauth}/_coauth/account/auth/passkey/register/start`, {
      data: {}, headers: { origin: "https://evil.example", "sec-fetch-site": "cross-site" },
    });
    expect(crossOrigin.status()).toBe(403);
    await jsonOk(await request.post(`${coauth}/_coauth/account/auth/logout`, { data: {} }), "browser logout");
    expect((await request.post(`${coauth}/_coauth/account/auth/passkey/register/start`, { data: {} })).status()).toBe(401);
    const expiredStart = await jsonOk(await request.post(`${coauth}/_coauth/account/auth/passkey/auth/start`, { data: { handle } }), "expiring browser assertion ceremony");
    const expiredAssertion = await browserCredential(page, expiredStart.challenge, "get");
    await test.step("the real ten-minute ceremony TTL expires without creating a session", async () => {
      await page.waitForTimeout(601_000);
      expect((await request.post(`${coauth}/_coauth/account/auth/passkey/auth/finish`, {
        data: { ceremony_id: expiredStart.ceremony_id, assertion: expiredAssertion },
      })).status()).toBe(400);
      const viewer = await jsonOk(await request.get(`${coauth}/_coauth/self/viewer`), "expired assertion session readback");
      expect(viewer.viewer.__typename).toBe("Anonymous");
    });
    const authStart = await jsonOk(await request.post(`${coauth}/_coauth/account/auth/passkey/auth/start`, { data: { handle } }), "assertion ceremony");
    const assertion = await browserCredential(page, authStart.challenge, "get");
    const finishBody = { ceremony_id: authStart.ceremony_id, assertion };
    const other = await browser.newContext();
    try {
      expect((await other.request.post(`${coauth}/_coauth/account/auth/passkey/auth/finish`, { data: finishBody })).status()).toBe(400);
    } finally { await other.close(); }
    // A session mismatch must not consume the original browser's ceremony.
    const authenticated = await jsonOk(await request.post(`${coauth}/_coauth/account/auth/passkey/auth/finish`, { data: finishBody }), "browser assertion");
    expect(authenticated.status).toBe("authenticated");
    expect(authenticated.account_id).toBe(start.account_id);
    expect((await request.post(`${coauth}/_coauth/account/auth/passkey/auth/finish`, { data: finishBody })).status()).toBe(400);
    const after = await jsonOk(await request.get(`${coauth}/_coauth/self/passkeys`), "authenticated passkey inventory");
    expect(after.passkeys).toHaveLength(1);
    expect(after.passkeys[0].id).toBe(before.passkeys[0].id);
  } finally {
    await cdp.detach();
    await context.close();
  }
});

test("S3 two accepted admin DIDs → real OAuth bearers → signed threshold-2 risk action", async ({ playwright }) => {
  const contexts = await Promise.all([0, 1, 2].map(() => playwright.request.newContext({
    ignoreHTTPSErrors: process.env.COTEST_IGNORE_HTTPS === "1",
  })));
  const [first, second, targetRequest] = contexts.map(withOperationSelectors);
  try {
    const firstAccount = await registerCoauthPasswordAccount(first, coauth, { handle: `int-admin-a-${randomUUID()}` });
    const secondAccount = await registerCoauthPasswordAccount(second, coauth, { handle: `int-admin-b-${randomUUID()}` });
    expect(firstAccount.id).not.toBe(secondAccount.id);
    const target = await registerCoauthPasswordAccount(targetRequest, coauth, { handle: `int-target-${randomUUID()}` });
    const bearerA = await adminBearer(first, firstAccount);
    const bearerB = await adminBearer(second, secondAccount);
    const headersA = { authorization: `Bearer ${bearerA}` };
    const headersB = { authorization: `Bearer ${bearerB}` };
    const accounts = await jsonOk(await first.get(`${coauth}/_coauth/admin/accounts?page[first]=100`, { headers: headersA }), "admin account inventory");
    const targetRow = accounts.data.find((row: any) => row.attributes.handle === target.handle);
    expect(targetRow, "registered target in admin inventory").toBeTruthy();
    const targetId = String(targetRow.id).replace(/^(account|user):/, "");
    const base = `${coauth}/_coauth/admin/accounts/${targetId}/risk-action`;
    const ticket = `INTEGRATION-${randomUUID()}`;
    const proposal = await jsonOk(await first.post(base, { headers: headersA, data: { action: "disable", reason: "Integration controlled action", ticket } }), "risk proposal");
    const proposalId = proposal.proposal_id;
    expect(proposal.proposal_state).toBe("draft");
    const approvalA = { action: "disable", ticket, approved_by: firstAccount.id, approval_note: "First independent approval", approval_proof_jws: approvalProof(firstAccount, proposalId, targetId, ticket, "First independent approval") };
    const approvalB = { action: "disable", ticket, approved_by: secondAccount.id, approval_note: "Second independent approval", approval_proof_jws: approvalProof(secondAccount, proposalId, targetId, ticket, "Second independent approval") };
    const history = async () => jsonOk(await first.get(`${base}/history?page[first]=100`, { headers: headersA }), "durable risk history");
    const before = await history();
    expect((await first.post(`${base}/${proposalId}/approve`, { headers: headersA, data: { ...approvalA, approved_by: secondAccount.id } })).status()).toBe(400);
    expect((await first.post(`${base}/${proposalId}/approve`, { headers: headersA, data: { ...approvalA, action: "erase" } })).status()).toBe(400);
    const firstRow = accounts.data.find((row: any) => row.attributes.handle === firstAccount.handle);
    expect(firstRow, "accepted administrator's account").toBeTruthy();
    const firstAccountId = String(firstRow.id).replace(/^(account|user):/, "");
    const wrongTarget = `${coauth}/_coauth/admin/accounts/${firstAccountId}/risk-action/${proposalId}/approve`;
    expect((await first.post(wrongTarget, { headers: headersA, data: approvalA })).status()).toBe(404);
    // A different accepted admin's genuine root proof cannot control the
    // authenticated caller's principal, even when request.approved_by is A.
    expect((await first.post(`${base}/${proposalId}/approve`, {
      headers: headersA, data: { ...approvalA, approval_proof_jws: approvalB.approval_proof_jws },
    })).status()).toBe(400);
    expect(await history()).toEqual(before);
    const badSignature = approvalA.approval_proof_jws.slice(0, -8) + "AAAAAAAA";
    expect((await first.post(`${base}/${proposalId}/approve`, {
      headers: headersA, data: { ...approvalA, approval_proof_jws: badSignature },
    })).status()).toBe(400);
    expect(await history()).toEqual(before);
    const one = await jsonOk(await first.post(`${base}/${proposalId}/approve`, { headers: headersA, data: approvalA }), "first real root approval");
    expect(one.approval_state).toBe("draft");
    expect((await first.post(`${base}/${proposalId}/execute`, { headers: headersA, data: { action: "disable", ticket, execution_note: "Threshold must reject one approval" } })).status()).toBe(400);
    const afterOne = await history();
    expect((await first.post(`${base}/${proposalId}/approve`, { headers: headersA, data: approvalA })).status()).toBe(409);
    expect(await history()).toEqual(afterOne);
    const two = await jsonOk(await second.post(`${base}/${proposalId}/approve`, { headers: headersB, data: approvalB }), "second independent root approval");
    expect(two.approval_state).toBe("approved");
    const execution = await jsonOk(await first.post(`${base}/${proposalId}/execute`, { headers: headersA, data: { action: "disable", ticket, execution_note: "Both approvals verified" } }), "threshold-2 execution");
    expect(execution.execution_state).toBe("mutation_recorded");
    expect(execution.mutation_kind).toBe("account_disabled");
    expect(execution.account.data.attributes.status).toBe("deactivated");
    const current = await jsonOk(await first.get(`${base}/current`, { headers: headersA }), "executed current projection");
    expect(current.data.attributes.lifecycle_state).toBe("mutation_recorded");
    const afterExecution = await history();
    expect(afterExecution.data.length).toBeGreaterThan(before.data.length);
    expect((await first.post(`${base}/${proposalId}/execute`, { headers: headersA, data: { action: "disable", ticket, execution_note: "Replay must not mutate again" } })).status()).toBe(409);
    expect(await history()).toEqual(afterExecution);
    const discovery = await jsonOk(await second.get(`${coauth}/.well-known/openid-configuration`), "revocation discovery");
    const revoked = await second.post(discovery.revocation_endpoint, { form: {
      client_id: required("COTEST_OIDC_CLIENT_ID"), token: bearerB, token_type_hint: "access_token",
    } });
    expect(revoked.status()).toBe(200);
    expect((await second.get(`${base}/current`, { headers: headersB })).status()).toBe(401);
    expect(await history()).toEqual(afterExecution);
  } finally { await Promise.all(contexts.map(context => context.dispose())); }
});
