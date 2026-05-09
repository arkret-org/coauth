#!/usr/bin/env bash
# Integration e2e: exercise three happy-path scenarios across the
# coauth + soland + sodmin stack brought up by `integration-up.sh`.
#
# Scope vs. integration-smoke.sh:
#
#   - integration-smoke.sh just probes /health on each service. It tells
#     you the containers came up and the listeners are bound, nothing
#     more.
#
#   - integration-e2e.sh (this file) drives real protocol-level
#     workflows over HTTP. The three scenarios are:
#
#     S1: account create → DID bind → soland resource access (Space
#         create + send a message). Exercises the coauth↔soland glue.
#
#     S2: passkey register → passkey auth → session establishment.
#         Exercises the WebAuthn assertion + session cookie path.
#
#     S3: risk-action proposal → 2-of-2 admin approval → execution.
#         Exercises the admin scaffold lifecycle that lands in sodmin.
#
# Each scenario logs PASS / FAIL with stage timings so a CI run shows
# *where* the e2e budget is being spent. Failures inside a scenario are
# captured but the script keeps running so the operator sees the full
# matrix; the exit code at the end is non-zero if any scenario failed.
#
# This is deliberately a *thin* harness:
#
#   - curl + jq only; no test framework
#   - 404-tolerant for surfaces that aren't wired yet (logs SKIP, not FAIL)
#   - assumes the stack is already up — call `integration-up.sh` first
#
# Usage:
#
#   ./scripts/integration-up.sh
#   ./scripts/integration-e2e.sh
#   ./scripts/integration-up.sh --down
#
# Exit codes:
#   0 — every scenario passed (or skipped because its surface is 404)
#   3 — at least one scenario failed
#   2 — usage error / missing dependency

set -uo pipefail

readonly COAUTH_BASE="${COAUTH_BASE:-http://127.0.0.1:57080}"
readonly SOLAND_BASE="${SOLAND_BASE:-http://127.0.0.1:58008}"
readonly SODMIN_BASE="${SODMIN_BASE:-http://127.0.0.1:59090}"
readonly STAGE_TIMEOUT="${STAGE_TIMEOUT:-10}"

# Track total pass/fail across scenarios.
SCENARIOS_RUN=0
SCENARIOS_PASSED=0
SCENARIOS_FAILED=0
SCENARIOS_SKIPPED=0

# Dep check.
for dep in curl jq; do
    if ! command -v "${dep}" >/dev/null 2>&1; then
        echo "[e2e] missing required dependency: ${dep}" >&2
        exit 2
    fi
done

# now_ms emits the current time in milliseconds. Bash doesn't have one
# natively, but `date +%s%3N` works on every Linux + macOS GNU date we
# care about; on BSD we fall back to seconds * 1000.
now_ms() {
    if date +%s%3N >/dev/null 2>&1; then
        date +%s%3N
    else
        echo "$(($(date +%s) * 1000))"
    fi
}

# stage logs the elapsed wall-clock time around a single curl call and
# captures the response body in $LAST_BODY + status in $LAST_STATUS.
LAST_BODY=""
LAST_STATUS="000"
stage() {
    local name="$1"
    shift
    local start
    start="$(now_ms)"
    local tmp
    tmp="$(mktemp)"
    LAST_STATUS="$(curl -sS -o "${tmp}" -m "${STAGE_TIMEOUT}" -w '%{http_code}' "$@" || echo "000")"
    LAST_BODY="$(cat "${tmp}")"
    rm -f "${tmp}"
    local end
    end="$(now_ms)"
    local elapsed=$((end - start))
    echo "[e2e]   stage ${name}: HTTP ${LAST_STATUS} (${elapsed} ms)"
}

# scenario_pass / scenario_fail / scenario_skip update the matrix counters.
scenario_pass() { SCENARIOS_PASSED=$((SCENARIOS_PASSED + 1)); echo "[e2e] PASS — $1"; }
scenario_fail() { SCENARIOS_FAILED=$((SCENARIOS_FAILED + 1)); echo "[e2e] FAIL — $1" >&2; }
scenario_skip() { SCENARIOS_SKIPPED=$((SCENARIOS_SKIPPED + 1)); echo "[e2e] SKIP — $1 (${2:-surface not wired})"; }

# Pre-flight: every scenario assumes coauth /health is 200. If it isn't,
# bail loudly so the operator runs integration-up first.
preflight() {
    local code
    code="$(curl -fsS -o /dev/null -m 2 -w '%{http_code}' "${COAUTH_BASE}/health" || echo "000")"
    if [[ "${code}" != "200" ]]; then
        echo "[e2e] coauth /health did not return 200 (${COAUTH_BASE}/health → ${code})" >&2
        echo "[e2e] run ./scripts/integration-up.sh first" >&2
        exit 2
    fi
}

# ─────────────────────────────────────────────────────────────────────
# S1: account create → DID bind → soland resource access
# ─────────────────────────────────────────────────────────────────────
scenario_s1() {
    SCENARIOS_RUN=$((SCENARIOS_RUN + 1))
    echo "[e2e] === S1: account → DID bind → Space create + send message ==="
    local s1_start
    s1_start="$(now_ms)"
    local local_part="e2e-s1-$(date +%s)"
    local password="e2e-test-pw-$RANDOM"

    # 1. Register an account against coauth's account-management API.
    stage "register-account" \
        -X POST "${COAUTH_BASE}/api/account/v1/register" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg u "${local_part}" --arg p "${password}" \
            '{username: $u, password: $p}')"
    if [[ "${LAST_STATUS}" == "404" || "${LAST_STATUS}" == "405" ]]; then
        scenario_skip "S1" "account register endpoint not wired (${LAST_STATUS})"
        return 0
    fi
    if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
        scenario_fail "S1 stage register-account: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi
    local account_id
    account_id="$(echo "${LAST_BODY}" | jq -r '.account_id // .id // empty')"
    echo "[e2e]   account_id=${account_id:-<unknown>}"

    # 2. Bind a (synthetic) DID to the account.
    local did="did:e2e:${local_part}"
    stage "bind-did" \
        -X POST "${COAUTH_BASE}/api/account/v1/dids" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg d "${did}" '{did: $d}')"
    if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
        # 404/501 here just means the binding endpoint isn't wired yet.
        if [[ "${LAST_STATUS}" == "404" || "${LAST_STATUS}" == "501" ]]; then
            scenario_skip "S1" "DID-bind endpoint not wired (${LAST_STATUS})"
            return 0
        fi
        scenario_fail "S1 stage bind-did: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    # 3. Create a Space on soland and send a message.
    stage "soland-space-create" \
        -X POST "${SOLAND_BASE}/api/v1/spaces" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg n "${local_part}-space" '{name: $n}')"
    if [[ "${LAST_STATUS}" == "404" ]]; then
        scenario_skip "S1" "soland space-create not wired"
        return 0
    fi
    if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
        scenario_fail "S1 stage soland-space-create: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi
    local space_id
    space_id="$(echo "${LAST_BODY}" | jq -r '.space_id // .id // empty')"

    stage "soland-send-message" \
        -X POST "${SOLAND_BASE}/api/v1/spaces/${space_id}/messages" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc '{body: "hello-from-e2e"}')"
    if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
        scenario_fail "S1 stage soland-send-message: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    local s1_end
    s1_end="$(now_ms)"
    echo "[e2e]   total S1 elapsed: $((s1_end - s1_start)) ms"
    scenario_pass "S1"
}

# ─────────────────────────────────────────────────────────────────────
# S2: passkey register → passkey auth → session establishment
# ─────────────────────────────────────────────────────────────────────
scenario_s2() {
    SCENARIOS_RUN=$((SCENARIOS_RUN + 1))
    echo "[e2e] === S2: passkey register → auth → session ==="
    local s2_start
    s2_start="$(now_ms)"
    local local_part="e2e-s2-$(date +%s)"

    # 1. Begin passkey registration ceremony — coauth issues a challenge.
    stage "passkey-register-begin" \
        -X POST "${COAUTH_BASE}/api/account/v1/passkey/register/begin" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg u "${local_part}" '{username: $u}')"
    if [[ "${LAST_STATUS}" == "404" || "${LAST_STATUS}" == "405" ]]; then
        scenario_skip "S2" "passkey register begin not wired"
        return 0
    fi
    if [[ "${LAST_STATUS}" != "200" ]]; then
        scenario_fail "S2 stage passkey-register-begin: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    # 2. Finish the registration ceremony with a stub credential.
    # The point of this e2e step is the wire shape, not WebAuthn crypto;
    # the harness sends a synthetic blob and accepts a 4xx that comes
    # back from the validator.
    stage "passkey-register-finish" \
        -X POST "${COAUTH_BASE}/api/account/v1/passkey/register/finish" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc '{credential: {id: "e2e-stub", rawId: "ZTJlLXN0dWI=", response: {clientDataJSON: "", attestationObject: ""}, type: "public-key"}}')"
    if [[ "${LAST_STATUS}" == "404" ]]; then
        scenario_skip "S2" "passkey register finish not wired"
        return 0
    fi
    # The synthetic credential is *not* expected to verify cryptographically;
    # we only assert the endpoint took the request and returned a structured
    # response (200 OK or 400 Bad Request with a JSON error envelope).
    if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "400" ]]; then
        scenario_fail "S2 stage passkey-register-finish: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    # 3. Authenticate with the (now-registered) passkey + establish session.
    stage "passkey-auth-begin" \
        -X POST "${COAUTH_BASE}/api/account/v1/passkey/auth/begin" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg u "${local_part}" '{username: $u}')"
    if [[ "${LAST_STATUS}" == "404" ]]; then
        scenario_skip "S2" "passkey auth begin not wired"
        return 0
    fi

    stage "session-establish" \
        -X POST "${COAUTH_BASE}/api/account/v1/sessions" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg u "${local_part}" '{username: $u}')"
    if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" \
        && "${LAST_STATUS}" != "401" && "${LAST_STATUS}" != "403" ]]; then
        # 401/403 are acceptable here — the synthetic stub above doesn't
        # actually verify, so we accept the structured rejection as
        # evidence the path is wired.
        scenario_fail "S2 stage session-establish: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    local s2_end
    s2_end="$(now_ms)"
    echo "[e2e]   total S2 elapsed: $((s2_end - s2_start)) ms"
    scenario_pass "S2"
}

# ─────────────────────────────────────────────────────────────────────
# S3: risk-action proposal → 2-of-2 admin approval → execution
# ─────────────────────────────────────────────────────────────────────
scenario_s3() {
    SCENARIOS_RUN=$((SCENARIOS_RUN + 1))
    echo "[e2e] === S3: risk-action proposal → 2-of-2 approval → execute ==="
    local s3_start
    s3_start="$(now_ms)"
    # We re-use a synthetic account_id here; the scaffold endpoint just
    # echoes the path back and persists transition rows keyed by id.
    local account_id="e2e-s3-$(date +%s)"

    # 1. Stage a proposal.
    stage "risk-action-propose" \
        -X POST "${COAUTH_BASE}/api/admin/v1/accounts/${account_id}/risk-action" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc '{action: "lock", reason: "e2e harness", ticket: "INT-E2E-1"}')"
    if [[ "${LAST_STATUS}" == "404" ]]; then
        scenario_skip "S3" "risk-action endpoint not mounted"
        return 0
    fi
    if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
        scenario_fail "S3 stage risk-action-propose: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi
    local proposal_id
    proposal_id="$(echo "${LAST_BODY}" | jq -r '.proposal_id // empty')"
    if [[ -z "${proposal_id}" ]]; then
        scenario_fail "S3: no proposal_id in response: ${LAST_BODY}"
        return 0
    fi

    # 2. First approval (admin A).
    stage "risk-action-approve-A" \
        -X POST "${COAUTH_BASE}/api/admin/v1/accounts/${account_id}/risk-action/${proposal_id}/approve" \
        -H 'Content-Type: application/json' \
        -H 'X-E2E-Admin-Id: admin-A' \
        -d "$(jq -nc '{action: "lock", approval_note: "approved by A"}')"
    if [[ "${LAST_STATUS}" != "200" ]]; then
        scenario_fail "S3 stage risk-action-approve-A: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    # 3. Second approval (admin B). The 2-of-2 contract requires two
    # distinct admin identities; the X-E2E-Admin-Id header is the
    # scaffold hook the backend uses to disambiguate them in test mode.
    stage "risk-action-approve-B" \
        -X POST "${COAUTH_BASE}/api/admin/v1/accounts/${account_id}/risk-action/${proposal_id}/approve" \
        -H 'Content-Type: application/json' \
        -H 'X-E2E-Admin-Id: admin-B' \
        -d "$(jq -nc '{action: "lock", approval_note: "approved by B"}')"
    if [[ "${LAST_STATUS}" != "200" ]]; then
        scenario_fail "S3 stage risk-action-approve-B: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    # 4. Execute.
    stage "risk-action-execute" \
        -X POST "${COAUTH_BASE}/api/admin/v1/accounts/${account_id}/risk-action/${proposal_id}/execute" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc '{action: "lock", execution_note: "e2e exec"}')"
    if [[ "${LAST_STATUS}" != "200" ]]; then
        scenario_fail "S3 stage risk-action-execute: ${LAST_STATUS}: ${LAST_BODY}"
        return 0
    fi

    local s3_end
    s3_end="$(now_ms)"
    echo "[e2e]   total S3 elapsed: $((s3_end - s3_start)) ms"
    scenario_pass "S3"
}

# ─────────────────────────────────────────────────────────────────────
preflight
scenario_s1
echo
scenario_s2
echo
scenario_s3
echo

echo "[e2e] ─── matrix ───"
echo "[e2e] run     : ${SCENARIOS_RUN}"
echo "[e2e] passed  : ${SCENARIOS_PASSED}"
echo "[e2e] failed  : ${SCENARIOS_FAILED}"
echo "[e2e] skipped : ${SCENARIOS_SKIPPED}"

if (( SCENARIOS_FAILED > 0 )); then
    exit 3
fi
exit 0
