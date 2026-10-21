// Real owning-Station delegated IVS. All DTO parsing/signing remains in SDK/Rust.
import { channel } from "node:diagnostics_channel";
import { ClientRequest } from "node:http";
import { Socket } from "node:net";


import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test, type APIRequestContext, type APIResponse } from "../../../cotest/e2e/helpers/arkret-test";
import { ProvisioningBridge } from "../../../cotest/e2e/helpers/provisioning-bridge";
import { newDeviceId } from "../../../cotest/e2e/helpers/ids";
import { canonicalJson, retypeEventDerivedId, uuidV7 } from "../../../cotest/e2e/helpers/coland-api";

function required(key: string): string {
  const value = process.env[key]?.trim();
  if (!value) throw new Error(`canonical IVS deployment is missing ${key}`);
  return value.replace(/\/$/, "");
}
const station = required("COTEST_COLAND_BASE_URL");
const coauth = required("COTEST_COAUTH_BASE_URL");
const mockEmail = required("COTEST_MOCK_EMAIL_BASE_URL");
const clientId = required("COTEST_OIDC_CLIENT_ID");
required("COTEST_PROVISION_BIN");
required("COTEST_WIRE_BIN");
required("COTEST_TOPOLOGY_PATH");
const endpoints = { coauthBaseUrl: coauth, colandBaseUrl: station, mockEmailBaseUrl: mockEmail };
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

type InviteTransportSample = {
  sample_index: number;
  native_request_count: number;
  reused_socket: number;
  socket_created_ms: number;
  request_created_ms: number;
  request_start_ms: number;
  socket_assigned_ms: number;
  connect_ms: number;
  tls_ms: number;
  request_finish_ms: number;
  response_ms: number;
  body_end_ms: number;
  api_return_ms: number;
  request_error: number;
  observer_error: number;
};

// Observe the unchanged API call; never read or publish a body, credential or URL.
async function measureInvitePresentTransport<T>(samples: InviteTransportSample[],
  stationHost: string, call: () => Promise<T>): Promise<T> {
  if (samples.length >= 9) return call();
  const started = performance.now();
  const elapsed = () => Math.round((performance.now() - started) * 1000) / 1000;
  const row: InviteTransportSample = {
    sample_index: samples.length + 1, native_request_count: 0, reused_socket: -1,
    socket_created_ms: -1, request_created_ms: -1, request_start_ms: -1,
    socket_assigned_ms: -1, connect_ms: -1, tls_ms: -1,
    request_finish_ms: -1, response_ms: -1, body_end_ms: -1,
    api_return_ms: -1, request_error: 0, observer_error: 0,
  };
  const cleanup: Array<() => void> = [];
  const sockets = new WeakMap<Socket, { created: number; connect: number; tls: number }>();
  const seenRequests = new WeakSet<ClientRequest>();
  let firstRequest: ClientRequest | undefined;
  let socketCount = 0;
  let selectedSocket: Socket | undefined;
  function listen(emitter: NodeJS.EventEmitter, event: string, callback: (...args: any[]) => void) {
    const guarded = (...args: any[]) => {
      try { callback(...args); } catch { row.observer_error = 1; }
    };
    emitter.once(event, guarded);
    cleanup.push(() => emitter.removeListener(event, guarded));
  }
  function observeSocket(message: unknown) {
    try {
      const socket = (message as { socket?: unknown })?.socket;
      if (!(socket instanceof Socket) || sockets.has(socket)) return;
      if (++socketCount > 64) { row.observer_error = 1; return; }
      const phases = { created: elapsed(), connect: -1, tls: -1 };
      sockets.set(socket, phases);
      listen(socket, "connect", () => {
        phases.connect = elapsed();
        if (socket === selectedSocket) row.connect_ms = phases.connect;
      });
      listen(socket, "secureConnect", () => {
        phases.tls = elapsed();
        if (socket === selectedSocket) row.tls_ms = phases.tls;
      });
    } catch { row.observer_error = 1; }
  }
  function selectRequest(message: unknown): ClientRequest | undefined {
    const request = (message as { request?: unknown })?.request;
    if (!(request instanceof ClientRequest) || request.method !== "POST"
      || request.path !== "/_arkret/open/third-party-invites/present"
      || request.getHeader("host") !== stationHost) return;
    if (!seenRequests.has(request)) {
      seenRequests.add(request);
      row.native_request_count += 1;
      if (firstRequest === undefined) {
        firstRequest = request;
        const matchedRequest: ClientRequest = request;
        function bindSocket(socket: Socket) {
          if (selectedSocket) return;
          selectedSocket = socket;
          row.socket_assigned_ms = elapsed();
          row.reused_socket = matchedRequest.reusedSocket ? 1 : 0;
          const phases = sockets.get(socket);
          if (phases) {
            row.socket_created_ms = phases.created;
            row.connect_ms = phases.connect;
            row.tls_ms = phases.tls;
          }
        }
        listen(request, "socket", bindSocket);
        if (request.socket) bindSocket(request.socket);
        listen(request, "finish", () => { row.request_finish_ms = elapsed(); });
        listen(request, "response", response => {
          row.response_ms = elapsed();
          // An end listener does not consume the response or enable flowing mode.
          listen(response, "end", () => { row.body_end_ms = elapsed(); });
        });
        listen(request, "error", () => { row.request_error = 1; });
      }
    }
    return request === firstRequest ? request : undefined;
  }
  function observeCreated(message: unknown) {
    try { if (selectRequest(message)) row.request_created_ms = elapsed(); }
    catch { row.observer_error = 1; }
  }
  function observeStart(message: unknown) {
    try { if (selectRequest(message)) row.request_start_ms = elapsed(); }
    catch { row.observer_error = 1; }
  }
  const subscriptions = [
    [channel("net.client.socket"), observeSocket],
    [channel("http.client.request.created"), observeCreated],
    [channel("http.client.request.start"), observeStart],
  ] as const;
  for (const [source, observer] of subscriptions) source.subscribe(observer);
  try {
    return await call();
  } finally {
    row.api_return_ms = elapsed();
    for (const [source, observer] of subscriptions) source.unsubscribe(observer);
    for (const dispose of cleanup) dispose();
    samples.push(row);
  }
}

async function canonicalPost(request: APIRequestContext, url: string,
  options: NonNullable<Parameters<APIRequestContext["post"]>[1]>) {
  return request.post(url, { ...options,
    headers: { ...options.headers, "content-type": "application/json" },
    // Deliberately malformed strings stay malformed for the before-body gate.
    data: typeof options.data === "string" ? options.data : canonicalJson(options.data),
  });
}

async function ok(response: APIResponse, stage: string): Promise<Record<string, any>> {
  expect(response.status(), `${stage}: HTTP ${response.status()}`).toBe(200);
  return response.json();
}
async function rejected(response: APIResponse, status: number, code: string): Promise<Record<string, any>> {
  const problem = await response.json();
  expect(response.status(), `registered rejection: HTTP ${response.status()}`).toBe(status);
  expect(problem.type).toBe(`https://arkret.org/problems/${code}`);
  return problem;
}
async function user(label: string) {
  const bridge = ProvisioningBridge.start();
  try {
    const facts = await bridge.describeStation(endpoints);
    await bridge.provisionUnboundAccount(endpoints, {
      handle: `ivs-${label}-${randomUUID().slice(0, 8)}`, password: "1amTester!",
    });
    const handoff = await bridge.createAccountHandoff({ coauthBaseUrl: coauth,
      clientId, audienceId: facts.serviceId, deviceLabel: `ivs-${label}` });
    const founded = await bridge.foundPrincipal({ handoffId: handoff.handoffId,
      endpoints, trustDomain: facts.trustDomain, audienceId: facts.serviceId,
      deviceId: newDeviceId(), displayName: `IVS ${label}` });
    await bridge.openGarthClient({ handoffId: handoff.handoffId, colandBaseUrl: station,
      accountId: founded.accountId, deviceId: founded.deviceId });
    return { bridge, handoffId: handoff.handoffId, founded, facts };
  } catch (error) { await bridge.dispose(); throw error; }
}
type User = Awaited<ReturnType<typeof user>>;
async function realm(owner: User, member?: User) {
  const value = await owner.bridge.garthCreateRealm({ handoffId: owner.handoffId, title: "Private IVS acceptance" });
  if (member) await member.bridge.garthJoinRealm({ handoffId: member.handoffId, realmId: value.realmId });
  await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: value.realmId,
    kind: "ak.realm.policy_bundle", payload: { policy_revision: 2, federation_policy: "restricted",
      allowed_third_party_invite_verification_ids: [owner.facts.serviceId] } });
  await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: value.realmId,
    kind: "ak.realm.join_rule", payload: { value: "invite" } });
  return value;
}
async function provision(request: APIRequestContext, owner: User, realmId: string,
  mode: string, seconds = 3600) {
  const recipient = `ivs-${randomUUID()}@example.com`;
  const input = await owner.bridge.signThirdPartyInviteProvision({ handoffId: owner.handoffId,
    requestId: `ak:request:${uuidV7()}`,
    realmId, verificationId: owner.facts.serviceId, oobCodeKind: mode,
    deliveryTargetUri: `mailto:${recipient}`, expiresAt: new Date(Date.now() + seconds * 1000).toISOString(),
    domain: owner.facts.trustDomain });
  const output = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/provision`, { data: input }), "standard IVS provision");
  expect(output.third_party_invite.oob_code_kind).toBe(mode);
  expect(output.invite_id === undefined).toBe(true);
  const serialized = JSON.stringify(output);
  expect(serialized.includes(recipient), "public material excludes the private recipient").toBe(false);
  expect(["invite_token", "token_salt", "pepper", "private_key", "delivery_target_uri"].some(k => Object.hasOwn(output, k))).toBe(false);
  return { input, output, recipient };
}
async function accepted(owner: User, value: Awaited<ReturnType<typeof provision>>, grantId?: string) {
  const submitted = await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId,
    realmId: String(value.output.realm_id), kind: "ak.invite.third_party", payload: {
      third_party_invite: value.output.third_party_invite, expires_at: value.output.expires_at },
    semanticRefs: grantId ? [{ id: grantId, role: "authorized_by", critical: true }] : [] });
  const inviteId = retypeEventDerivedId(String(submitted.event_id), "invite");
  const evidence = await owner.bridge.thirdPartyInviteAcceptanceAttestation({ handoffId: owner.handoffId,
    realmId: String(value.output.realm_id), inviteId, verificationId: owner.facts.serviceId,
    provisioningId: String(value.output.provisioning_id) });
  return { inviteId, evidence, request: { provisioning_id: value.output.provisioning_id,
    acceptance_attestation: evidence.acceptance_attestation } };
}
async function mailbox(request: APIRequestContext, recipient: string): Promise<Record<string, any>[]> {
  const result = await ok(await request.get(`${mockEmail}/mock/email/verification/inbox?to=${encodeURIComponent(recipient)}`), "actual delivery inbox");
  return Array.isArray(result.messages) ? result.messages : [];
}
async function deliveredCode(request: APIRequestContext, recipient: string,
  diagnostic?: { provisioningId: string; fixture: "inviter_left" | "revoked" }) {
  let code: string | undefined;
  try {
    await expect.poll(async () => {
      const messages = await mailbox(request, recipient);
      code = messages.filter(m => m.delivery_status === "delivered").map(m => String(m.body ?? "").match(/Your invitation code is ([A-Za-z0-9_-]+)\./)?.[1]).find(Boolean);
      return Boolean(code);
    }, { timeout: 95_000, message: "provider code must arrive through the configured real transport, including its 60-second first retry" }).toBe(true);
  } catch (error) {
    if (diagnostic) {
      const response = await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
        data: { provisioning_id: diagnostic.provisioningId },
      });
      const status = response.status() === 200 ? await response.json() : {};
      console.info(JSON.stringify({ boundary: "withdrawal_delivery_not_arrived", fixture: diagnostic.fixture,
        status_http: response.status(),
        delivery_state: ["queued", "delivered", "failed"].includes(status.delivery_state) ? status.delivery_state : "unavailable",
        delivery_attempt_count: Number.isSafeInteger(status.delivery_attempt_count) ? status.delivery_attempt_count : null }));
    }
    throw error;
  }
  return code!;
}
async function attemptedCode(request: APIRequestContext, recipient: string) {
  let code: string | undefined;
  await expect.poll(async () => {
    const messages = await mailbox(request, recipient);
    code = messages.filter(m => m.delivery_status === "failed")
      .map(m => String(m.body ?? "").match(/Your invitation code is ([A-Za-z0-9_-]+)\./)?.[1]).find(Boolean);
    return Boolean(code);
  }, { timeout: 35_000, message: "the real transport must receive and refuse an actual delivery attempt" }).toBe(true);
  return code!;
}
async function deliveryFailure(request: APIRequestContext, recipient: string, enabled: boolean) {
  const ack = await ok(await request.post(`${mockEmail}/inspect`, {
    data: { delivery_failure: { to: recipient, enabled } },
  }), "configure isolated transport fault");
  expect(ack.configured).toBe(true);
  expect(ack.enabled).toBe(enabled);
}
function body(subject: User, realmId: string, token: string) {
  return { invite_token: token, realm_id: realmId, subject_account_id: subject.founded.accountId,
    subject_did: subject.founded.did, claim_nonce: `ivs-claim-${randomUUID()}` };
}
function restartProvider() {
  const script = fileURLToPath(new URL("../../../cotest/scripts/control-joint-e2e-service.ps1", import.meta.url));
  const args = ["-NoProfile", "-File", script, "-TopologyPath", required("COTEST_TOPOLOGY_PATH"),
    "-ServerName", "server1", "-ServiceName", "coauth"];
  const before = JSON.parse(execFileSync("pwsh", [...args, "-Action", "status"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  execFileSync("pwsh", [...args, "-Action", "restart"], { stdio: "pipe" });
  const after = JSON.parse(execFileSync("pwsh", [...args, "-Action", "status"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  expect(after.current_process_id === before.current_process_id, "real provider process must change").toBe(false);
}
async function ready(request: APIRequestContext) {
  await expect.poll(async () => {
    const response = await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: `third_party_invite_provisioning:${"A".repeat(43)}` } });
    return response.status();
  }, { timeout: 45_000 }).toBe(404);
}

// Preserve the real provider's five-per-minute source budget across cases.
let completedCase = false;
test.beforeEach(async () => { if (completedCase) await sleep(61_000); });
test.afterEach(() => { completedCase = true; });

for (const mode of ["offline_token", "lookup"]) {
  test(`TP5 ${mode}: real provision, accepted attestation, OOB delivery, Claim and accept @third-party-provider`, async ({ request }) => {
    const owner = await user(`owner-${mode}`); const subject = await user(`subject-${mode}`);
    try {
      const space = await realm(owner);
      const value = await provision(request, owner, space.realmId, mode);
      expect((await mailbox(request, value.recipient)).length, "unbound material must not be delivered").toBe(0);
      const binding = await accepted(owner, value);
      const activations = await Promise.all([0, 1].map(() => canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request })));
      const activated = await ok(activations[0], "first concurrent standard activation");
      const concurrent = await ok(activations[1], "second concurrent standard activation");
      expect(concurrent.activated_at).toBe(activated.activated_at);
      const token = await deliveredCode(request, value.recipient);
      expect(mode === "offline_token" ? /^[A-Z2-9]{40}$/.test(token) : /^[A-Z2-9]{16}_[A-Z2-9]{8}$/.test(token)).toBe(true);
      const retry = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "exact activation retry");
      expect(retry.activated_at).toBe(activated.activated_at);
      const claimInput = body(subject, space.realmId, token);
      const presentations = await Promise.all([0, 1].map(() => canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, { data: claimInput })));
      expect(presentations.map(response => response.status()).sort()).toEqual([200, 404]);
      const proof = await ok(presentations.find(response => response.status() === 200)!, "actual one-use present");
      await rejected(presentations.find(response => response.status() === 404)!, 404, "not_found");
      expect(proof.invite_id).toBe(binding.inviteId);
      const subjectProof = await subject.bridge.signInviteSubject({ handoffId: subject.handoffId,
        inviteId: binding.inviteId, realmId: space.realmId, tokenCommitment: String(proof.token_commitment),
        claimNonce: claimInput.claim_nonce, verificationId: owner.facts.serviceId, bindingProof: proof.binding_proof });
      const claim = await subject.bridge.submitTypedEvent({ handoffId: subject.handoffId,
        realmId: space.realmId, kind: "ak.invite.claim", payload: { invite_id: binding.inviteId,
          subject_account_id: subject.founded.accountId, token_commitment: proof.token_commitment,
          claim_nonce: claimInput.claim_nonce, binding_proof: proof.binding_proof, subject_proof: subjectProof } });
      expect(Boolean(claim.commit), "Station must accept and Commit the actual provider proof").toBe(true);
      const joined = await subject.bridge.submitTypedEvent({ handoffId: subject.handoffId, realmId: space.realmId,
        kind: "ak.invite.accept", payload: { invite_id: binding.inviteId, previous_state: "claimed" } });
      expect(Boolean(joined.commit), "claim must support real membership acceptance").toBe(true);
      await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, { data: claimInput }), 404, "not_found");
      const state = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, { data: { provisioning_id: value.output.provisioning_id } }), "consumed status");
      expect(state.provisioning_state).toBe("consumed");
    } finally { await subject.bridge.dispose(); await owner.bridge.dispose(); }
  });
}

test("TP2 original intent and immutable activation survive actual provider restart @third-party-provider", async ({ request }) => {
  const owner = await user("restart-owner");
  try {
    const space = await realm(owner);
    const value = await provision(request, owner, space.realmId, "offline_token");
    restartProvider(); await ready(request);
    const recoveredUnbound = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "read original provisioning status before retry");
    expect(recoveredUnbound.provisioning_state).toBe("provisioned");
    const replay = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/provision`, { data: value.input }), "provision recovery after process death");
    expect(JSON.stringify(replay) === JSON.stringify(value.output)).toBe(true);
    expect((await mailbox(request, value.recipient)).length).toBe(0);
    const binding = await accepted(owner, value);
    const first = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "first activation");
    restartProvider(); await ready(request);
    const recoveredBound = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "read bound status before activation retry");
    expect(recoveredBound.activated_at).toBe(first.activated_at);
    const recovered = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "activation recovery after process death");
    expect(recovered.activated_at).toBe(first.activated_at);
    await deliveredCode(request, value.recipient);
  } finally { await owner.bridge.dispose(); }
});

test("TP1 issuance requires an accepted Device and preserves original signed intent @third-party-provider", async ({ request }) => {
  const owner = await user("auth-owner");
  try {
    const space = await realm(owner);
    const value = await provision(request, owner, space.realmId, "offline_token");
    const altered = await owner.bridge.signThirdPartyInviteProvision({ handoffId: owner.handoffId,
      requestId: String(value.input.request_id), realmId: space.realmId,
      verificationId: owner.facts.serviceId, oobCodeKind: "offline_token",
      deliveryTargetUri: `mailto:different-${randomUUID()}@example.com`,
      expiresAt: String(value.input.expires_at), domain: owner.facts.trustDomain });
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/provision`, { data: altered }), 409, "duplicate_conflict");
    const forged = structuredClone(value.input);
    forged.request_id = `ak:request:${uuidV7()}`;
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/provision`, { data: forged }), 404, "not_found");
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/provision`, {
      headers: { "arkret-operation": "ak.open.third_party_invite.command.present_token.v1" }, data: value.input,
    }), 422, "unsupported_operation_version");
    expect((await mailbox(request, value.recipient)).length).toBe(0);
    const state = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "original unbound status");
    expect(state.provisioning_state).toBe("provisioned");
  } finally { await owner.bridge.dispose(); }
});

test("TP3 signed activation remains distinct from withdrawn current delivery authority @third-party-provider", async ({ request }) => {
  const owner = await user("activation-owner");
  try {
    const space = await realm(owner);
    const value = await provision(request, owner, space.realmId, "offline_token");
    const binding = await accepted(owner, value);
    const forged = structuredClone(binding.request);
    const forgedAttestation = forged.acceptance_attestation as Record<string, any>;
    forgedAttestation.third_party_invite.max_claims = 2;
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: forged }), 404, "not_found");
    await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
      kind: "ak.invite.revoke", payload: { invite_id: binding.inviteId, previous_state: "pending", target_state: "revoked" } });
    // A still-valid signed activation capability is not a current delivery grant.
    const activation = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "explicit valid activation after withdrawal");
    expect(activation.invite_id).toBe(binding.inviteId);
    await expect.poll(async () => (await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "current withdrawn status")).provisioning_state,
    { timeout: 35_000 }).toBe("revoked");
    expect((await mailbox(request, value.recipient)).length, "withdrawn current invitation must not deliver").toBe(0);
    // A second Invite needs a genuinely new commitment; the accepted create
    // index intentionally never reuses the first commitment, even after revoke.
    const secondValue = await provision(request, owner, space.realmId, "offline_token");
    const second = await accepted(owner, secondValue);
    const reboundEvidence = await owner.bridge.thirdPartyInviteAcceptanceAttestation({
      handoffId: owner.handoffId, realmId: space.realmId, inviteId: second.inviteId,
      verificationId: owner.facts.serviceId, provisioningId: String(value.output.provisioning_id) });
    const changed = { provisioning_id: value.output.provisioning_id,
      acceptance_attestation: reboundEvidence.acceptance_attestation };
    // Preserve the valid binding/digest/protected header; corrupt only the JWS
    // signature. Direct provider ingress must authenticate changed requests too.
    const badSignature = structuredClone(changed);
    const signature = (badSignature.acceptance_attestation as Record<string, any>).signature;
    const parts = String(signature.jws).split(".");
    expect(parts.length).toBe(3);
    const bytes = Buffer.from(parts[2], "base64url");
    expect(bytes.length).toBe(64);
    bytes[0] ^= 1;
    signature.jws = `${parts[0]}.${parts[1]}.${bytes.toString("base64url")}`;
    await rejected(await canonicalPost(request, `${coauth}/_arkret/open/third-party-invites/activate`,
      { data: badSignature }), 404, "not_found");
    const denied = await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`,
      { data: changed }), 409, "duplicate_conflict");
    expect(denied.reason_code ?? denied.details?.reason_code).toBe("third_party_invite_provisioning_already_bound");
    const unchanged = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`,
      { data: { provisioning_id: value.output.provisioning_id } }), "rejected rebind preserves original ledger");
    expect(unchanged.invite_id).toBe(binding.inviteId);
    expect(unchanged.activated_at).toBe(activation.activated_at);
    expect(unchanged.provisioning_state).toBe("revoked");
    expect((await mailbox(request, value.recipient)).length).toBe(0);
    expect((await mailbox(request, secondValue.recipient)).length).toBe(0);
  } finally { await owner.bridge.dispose(); }
});

test("TP3 explicit attestation expiry refuses activation and scrubs unbound material @third-party-provider", async ({ request }) => {
  const owner = await user("expiry-owner");
  try {
    const space = await realm(owner);
    const value = await provision(request, owner, space.realmId, "lookup", 10);
    const binding = await accepted(owner, value);
    const expiry = Date.parse(String((binding.request.acceptance_attestation as Record<string, unknown>).expires_at));
    expect(Number.isFinite(expiry)).toBe(true);
    await sleep(Math.max(0, expiry - Date.now()) + 100);
    const stale = await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), 409, "failed_precondition");
    expect(stale.reason_code ?? stale.details?.reason_code).toBe("third_party_invite_acceptance_stale");
    const state = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "expired private status");
    expect(state.provisioning_state).toBe("expired");
    const replay = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/provision`, {
      data: value.input }), "retained expired intent returns original public material");
    expect(JSON.stringify(replay) === JSON.stringify(value.output)).toBe(true);
    const retained = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "expired intent remains terminal");
    expect(retained.provisioning_state).toBe("expired");
    expect((await mailbox(request, value.recipient)).length).toBe(0);
  } finally { await owner.bridge.dispose(); }
});

test("TP4 all six failure classes are indistinguishable and rejected bindings do not consume offline tokens @third-party-provider", async ({ request }) => {
  // Three real delivery attempts use the original 60/120-second backoff;
  // distinct present groups retain the actual five-per-minute source budget.
  test.setTimeout(720_000);
  const owner = await user("uniform-owner"); const subject = await user("uniform-subject");
  let delegate: User | undefined; let failureRecipient: string | undefined;
  try {
    const space = await realm(owner); const other = await realm(owner);
    const value = await provision(request, owner, space.realmId, "offline_token");
    const binding = await accepted(owner, value);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "activation");
    const token = await deliveredCode(request, value.recipient);
    const input = body(subject, space.realmId, token);
    const headers = { "x-arkret-request-id": `ak:request:${uuidV7()}` };
    const failures: string[] = []; const timings: number[] = [];
    const responseTimings: number[] = []; const assertionTimings: number[] = [];
    const transportSamples: InviteTransportSample[] = [];
    for (const data of [{ ...input, invite_token: "Z".repeat(40) },
      { ...input, realm_id: other.realmId }, { ...input, subject_did: owner.founded.did }]) {
      const started = performance.now();
      const response = await measureInvitePresentTransport(transportSamples, new URL(station).host,
        () => canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, { headers, data }));
      const received = performance.now();
      await rejected(response, 404, "not_found");
      failures.push(await response.text());
      const validated = performance.now();
      timings.push(validated - started);
      responseTimings.push(received - started); assertionTimings.push(validated - received);
    }
    expect(failures.every(value => value === failures[0]), "negative problem bytes must match").toBe(true);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, { data: input }), "offline token survives rejected bindings");
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, { data: input }), 404, "not_found");
    const unavailable: { failureClass: string; realmId: string; token: string }[] = [];

    const expiredRealm = await realm(owner);
    const expiredValue = await provision(request, owner, expiredRealm.realmId, "offline_token", 10);
    const expiredBinding = await accepted(owner, expiredValue);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: expiredBinding.request }), "expiry fixture activation");
    unavailable.push({ failureClass: "expired", realmId: expiredRealm.realmId,
      token: await deliveredCode(request, expiredValue.recipient) });

    const failedRealm = await realm(owner);
    const failedValue = await provision(request, owner, failedRealm.realmId, "offline_token");
    failureRecipient = failedValue.recipient;
    await deliveryFailure(request, failureRecipient, true);
    const failedBinding = await accepted(owner, failedValue);
    const failedActivation = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: failedBinding.request }), "refused transport fixture activation");
    // This is a private failed gateway attempt, not successful OOB delivery.
    const refusedCode = await attemptedCode(request, failureRecipient);
    unavailable.push({ failureClass: "delivery_exhausted", realmId: failedRealm.realmId, token: refusedCode });

    delegate = await user("uniform-delegate");
    const delegatedRealm = await realm(owner, delegate);
    const grant = await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: delegatedRealm.realmId,
      kind: "ak.capability.grant", payload: { grant: { schema: "ak.schema.capability.v1", realm_id: delegatedRealm.realmId,
        issuer_id: { kind: "account", account_id: owner.founded.accountId },
        subject: { kind: "account", account_id: delegate.founded.accountId }, actions: ["ak.invite.third_party"],
        resources: [{ kind: "realm", realm_id: delegatedRealm.realmId }], issued_at: new Date().toISOString(),
        issuer_authority_refs: [{ kind: "realm_root", realm_id: delegatedRealm.realmId,
          authority_event_ref: delegatedRealm.genesisEventId, authority_generation: 0 }] } } });
    const grantId = retypeEventDerivedId(String(grant.event_id), "grant");
    const delegatedValue = await provision(request, delegate, delegatedRealm.realmId, "offline_token");
    const delegatedBinding = await accepted(delegate, delegatedValue, grantId);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: delegatedBinding.request }), "capability fixture activation");
    const delegatedCode = await deliveredCode(request, delegatedValue.recipient);
    const grantCommit = grant.commit as Record<string, unknown>;
    await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: delegatedRealm.realmId,
      kind: "ak.capability.revoke", payload: { grant_id: grantId,
        expected_revision: { commit_id: grantCommit.commit_id, stream_position: grantCommit.stream_position } } });
    unavailable.push({ failureClass: "current_capability_lost", realmId: delegatedRealm.realmId, token: delegatedCode });

    for (const cause of ["inviter_left", "revoked"] as const) {
      const target = await realm(owner);
      const extra = await provision(request, owner, target.realmId, "offline_token");
      const evidence = await accepted(owner, extra);
      await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: evidence.request }), "withdrawal fixture activation");
      const code = await deliveredCode(request, extra.recipient, {
        provisioningId: String(extra.output.provisioning_id), fixture: cause,
      });
      if (cause === "revoked") await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: target.realmId,
        kind: "ak.invite.revoke", payload: { invite_id: evidence.inviteId, previous_state: "pending", target_state: "revoked" } });
      else await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: target.realmId,
        kind: "ak.member.state", payload: { member_id: { kind: "account", account_id: owner.founded.accountId }, membership: "leave" } });
      unavailable.push({ failureClass: cause === "inviter_left" ? "current_inviter_left" : "revoked", realmId: target.realmId, token: code });
    }

    const lookupRealm = await realm(owner);
    const lookupValue = await provision(request, owner, lookupRealm.realmId, "lookup");
    const lookupBinding = await accepted(owner, lookupValue);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: lookupBinding.request }), "lookup failure fixture activation");
    const lookupCode = await deliveredCode(request, lookupValue.recipient);
    const namespace = lookupCode.split("_")[0];
    const wrongLookup = `${namespace}_${lookupCode.endsWith("Z".repeat(8)) ? "Y".repeat(8) : "Z".repeat(8)}`;
    await sleep(61_000);
    for (let attempt = 0; attempt < 3; attempt++) await rejected(await canonicalPost(request,
      `${station}/_arkret/open/third-party-invites/present`, {
        data: body(subject, lookupRealm.realmId, wrongLookup) }), 404, "not_found");
    const invalidated = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: lookupValue.output.provisioning_id } }), "three actual failures invalidate lookup custody");
    expect(invalidated.provisioning_state).toBe("revoked");
    unavailable.push({ failureClass: "lookup_exhausted", realmId: lookupRealm.realmId, token: lookupCode });

    await expect.poll(async () => {
      const state = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
        data: { provisioning_id: failedValue.output.provisioning_id } }), "original bounded delivery retries");
      return state.delivery_state === "failed" && state.delivery_attempt_count === 3;
    }, { timeout: 220_000, message: "the original three real transport refusals must exhaust naturally" }).toBe(true);
    const attempts = await mailbox(request, failureRecipient);
    expect(attempts.length).toBe(3);
    expect(attempts.every(m => m.delivery_status === "failed"), "refused transport must not claim delivery").toBe(true);
    const exhausted = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: failedValue.output.provisioning_id } }), "private delivery exhaustion preserves activation");
    expect(exhausted.provisioning_state).toBe("activated");
    expect(exhausted.invite_id).toBe(failedBinding.inviteId);
    expect(exhausted.activated_at).toBe(failedActivation.activated_at);
    const replayedActivation = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, {
      data: failedBinding.request }), "exact exhausted activation replay");
    expect(replayedActivation.activated_at).toBe(failedActivation.activated_at);
    const afterReplay = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: failedValue.output.provisioning_id } }), "exhausted replay does not restore delivery");
    expect(afterReplay.provisioning_state).toBe("activated");
    expect(afterReplay.delivery_state).toBe("failed");
    expect(afterReplay.delivery_attempt_count).toBe(3);
    await sleep(61_000);
    for (let group = 0; group < 2; group++) {
      if (group > 0) await sleep(61_000);
      for (const negative of unavailable.slice(group * 3, group * 3 + 3)) {
        const started = performance.now();
        const response = await measureInvitePresentTransport(transportSamples, new URL(station).host,
          () => canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
            headers, data: body(subject, negative.realmId, negative.token) }));
        const received = performance.now();
        await rejected(response, 404, "not_found");
        failures.push(await response.text());
        const validated = performance.now();
        timings.push(validated - started);
        responseTimings.push(received - started); assertionTimings.push(validated - received);
      }
    }
    // Public evidence contains only closed fixture classes and measured time.
    // It never includes invite codes, identities, response bodies or mail state.
    await test.info().attach("invite-negative-timings", {
      body: Buffer.from(JSON.stringify({
        boundary: "public_station_present_response",
        samples: ["unknown_token", "wrong_realm", "wrong_subject",
          ...unavailable.map(value => value.failureClass)].map((failureClass, index) => ({
            failure_class: failureClass, duration_ms: timings[index],
            response_received_ms: responseTimings[index],
            assertion_ms: assertionTimings[index],
            transport_phases: transportSamples[index] ?? null,
          })),
        maximum_spread_ms: Math.max(...timings) - Math.min(...timings),
        normative_maximum_spread_ms: 50,
      })),
      contentType: "application/json",
    });
    expect(unavailable.map(value => value.failureClass)).toEqual([
      "expired", "delivery_exhausted", "current_capability_lost", "current_inviter_left", "revoked", "lookup_exhausted",
    ]);
    expect(failures.length).toBe(9);
    expect(failures.every(value => value === failures[0]), "six unavailable classes and malformed bindings must match byte-for-byte").toBe(true);
    expect(Math.max(...timings) - Math.min(...timings), "all negative timing classes must stay within 50ms").toBeLessThanOrEqual(50);
  } finally {
    try { if (failureRecipient) await deliveryFailure(request, failureRecipient, false); }
    finally { if (delegate) await delegate.bridge.dispose(); await subject.bridge.dispose(); await owner.bridge.dispose(); }
  }
});

test("TP4 three namespace lookup failures invalidate the original token @third-party-provider", async ({ request }) => {
  const owner = await user("lookup-owner"); const subject = await user("lookup-subject");
  try {
    const space = await realm(owner); const value = await provision(request, owner, space.realmId, "lookup");
    const binding = await accepted(owner, value);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "activation");
    const token = await deliveredCode(request, value.recipient);
    const namespace = token.split("_")[0];
    const wrongSuffix = token.endsWith("ZZZZZZZZ") ? "YYYYYYYY" : "ZZZZZZZZ";
    for (let attempt = 0; attempt < 3; attempt++) {
      await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
        data: body(subject, space.realmId, `${namespace}_${wrongSuffix}`) }), 404, "not_found");
    }
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
      data: body(subject, space.realmId, token) }), 404, "not_found");
    const state = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "lookup abuse status");
    expect(state.provisioning_state).toBe("revoked");
  } finally { await subject.bridge.dispose(); await owner.bridge.dispose(); }
});

test("TP4 URL tokens are rejected before malformed body or operation selector @third-party-provider", async ({ request }) => {
  const owner = await user("url-owner"); const subject = await user("url-subject");
  try {
    const space = await realm(owner); const value = await provision(request, owner, space.realmId, "offline_token");
    const binding = await accepted(owner, value);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "activation");
    const token = await deliveredCode(request, value.recipient);
    const queryCredential = new URL("/_arkret/open/third-party-invites/present", coauth);
    queryCredential.searchParams.set("invite_token", token);
    const pathCredential = new URL("/_arkret/open/third-party-invites/present", station);
    pathCredential.pathname += "/" + encodeURIComponent(token);
    for (const url of [queryCredential.toString(), pathCredential.toString()]) {
      const failure = await rejected(await canonicalPost(request, url, {
        headers: { "arkret-operation": "invalid" }, data: "{malformed" }), 409, "failed_precondition");
      expect(failure.reason_code ?? failure.details?.reason_code).toBe("third_party_invite_token_in_query");
    }
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
      data: body(subject, space.realmId, token) }), 404, "not_found");
  } finally { await subject.bridge.dispose(); await owner.bridge.dispose(); }
});

for (const withdrawal of ["allowlist", "inviter_leave", "revoke"] as const) {
  test(`TP5 current ${withdrawal} stops an already delivered token @third-party-provider`, async ({ request }) => {
    const owner = await user(`current-${withdrawal}`); const subject = await user(`subject-${withdrawal}`);
    try {
      const space = await realm(owner); const value = await provision(request, owner, space.realmId, "offline_token");
      const binding = await accepted(owner, value);
      await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "activation");
      const token = await deliveredCode(request, value.recipient);
      if (withdrawal === "allowlist") {
        await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
          kind: "ak.realm.policy_bundle", payload: { policy_revision: 3, federation_policy: "restricted",
            allowed_third_party_invite_verification_ids: [] } });
      } else if (withdrawal === "inviter_leave") {
        await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
          kind: "ak.member.state", payload: { member_id: { kind: "account", account_id: owner.founded.accountId }, membership: "leave" } });
      } else {
        await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
          kind: "ak.invite.revoke", payload: { invite_id: binding.inviteId, previous_state: "pending", target_state: "revoked" } });
      }
      await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
        data: body(subject, space.realmId, token) }), 404, "not_found");
      await expect.poll(async () => (await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
        data: { provisioning_id: value.output.provisioning_id } }), "withdrawn private state")).provisioning_state,
      { timeout: 35_000 }).toBe("revoked");
    } finally { await subject.bridge.dispose(); await owner.bridge.dispose(); }
  });
}

test("TP5 loss of the actual inviter capability stops present without relying on Realm ownership @third-party-provider", async ({ request }) => {
  const controller = await user("controller"); const inviter = await user("delegate"); const subject = await user("delegated-subject");
  try {
    const space = await realm(controller, inviter);
    const grant = await controller.bridge.submitTypedEvent({ handoffId: controller.handoffId, realmId: space.realmId,
      kind: "ak.capability.grant", payload: { grant: { schema: "ak.schema.capability.v1", realm_id: space.realmId,
        issuer_id: { kind: "account", account_id: controller.founded.accountId },
        subject: { kind: "account", account_id: inviter.founded.accountId }, actions: ["ak.invite.third_party"],
        resources: [{ kind: "realm", realm_id: space.realmId }], issued_at: new Date().toISOString(),
        issuer_authority_refs: [{ kind: "realm_root", realm_id: space.realmId,
          authority_event_ref: space.genesisEventId, authority_generation: 0 }] } } });
    const grantId = retypeEventDerivedId(String(grant.event_id), "grant");
    const value = await provision(request, inviter, space.realmId, "offline_token");
    const binding = await accepted(inviter, value, grantId);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "delegated activation");
    const token = await deliveredCode(request, value.recipient);
    const commit = grant.commit as Record<string, unknown>;
    await controller.bridge.submitTypedEvent({ handoffId: controller.handoffId, realmId: space.realmId,
      kind: "ak.capability.revoke", payload: { grant_id: grantId,
        expected_revision: { commit_id: commit.commit_id, stream_position: commit.stream_position } } });
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
      data: body(subject, space.realmId, token) }), 404, "not_found");
    await expect.poll(async () => (await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "authority loss state")).provisioning_state,
    { timeout: 35_000 }).toBe("revoked");
  } finally { await subject.bridge.dispose(); await inviter.bridge.dispose(); await controller.bridge.dispose(); }
});

test("TP4 knock_restricted is refused and the original source rate limit is enforced @third-party-provider", async ({ request }) => {
  const owner = await user("knock-owner"); const subject = await user("knock-subject");
  try {
    const space = await realm(owner); const value = await provision(request, owner, space.realmId, "offline_token");
    const binding = await accepted(owner, value);
    await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/activate`, { data: binding.request }), "activation");
    const token = await deliveredCode(request, value.recipient);
    // A restricted entry rule must have a real automatic join gate. Publish
    // it while the original invite rule is still current, then change the
    // rule; do not construct a policy-invalid Realm to test the IVS refusal.
    await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
      kind: "ak.realm.policy_bundle", payload: { policy_revision: 3, federation_policy: "restricted",
        allowed_third_party_invite_verification_ids: [owner.facts.serviceId],
        join_policy: { gates: [{ gate_id: "ivs-restricted-entry", kind: "claim_required", auto_resolve: true,
          required_claims: ["ivs-test"], trusted_issuer_ids: [owner.facts.serviceId] }], combinator: "all" } } });
    await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
      kind: "ak.realm.join_rule", payload: { value: "knock_restricted" } });
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
      data: body(subject, space.realmId, token) }), 422, "unsupported_join_rule");
    // Let the real worker encounter the policy as well as the present gate.
    await sleep(32_000);
    const paused = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/status`, {
      data: { provisioning_id: value.output.provisioning_id } }), "paused original custody");
    expect(paused.provisioning_state).toBe("activated");
    await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
      kind: "ak.realm.join_rule", payload: { value: "invite" } });
    await owner.bridge.submitTypedEvent({ handoffId: owner.handoffId, realmId: space.realmId,
      kind: "ak.realm.policy_bundle", payload: { policy_revision: 4, federation_policy: "restricted",
        allowed_third_party_invite_verification_ids: [owner.facts.serviceId] } });
    const recovered = await ok(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
      data: body(subject, space.realmId, token) }), "same original token after accepted policy restoration");
    expect(recovered.invite_id).toBe(binding.inviteId);
    // Five requests within one actual minute, followed by the registered 429.
    // Do not shorten product budgets or fake time.
    await sleep(61_000);
    const offset = Date.now() % 60_000;
    if (offset > 40_000) await sleep(60_000 - offset + 50);
    for (let attempt = 0; attempt < 5; attempt++) await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
      data: body(subject, space.realmId, "Z".repeat(40)) }), 404, "not_found");
    await rejected(await canonicalPost(request, `${station}/_arkret/open/third-party-invites/present`, {
      data: body(subject, space.realmId, "Z".repeat(40)) }), 429, "rate_limited");
  } finally { await subject.bridge.dispose(); await owner.bridge.dispose(); }
});
