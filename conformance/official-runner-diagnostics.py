"""Observe plan creation errors without exposing configuration or altering requests."""

import json
from pathlib import Path
import re
import runpy
import sys


PREFIX = "COAUTH_OIDF_PLAN_DIAGNOSTIC="
CATEGORIES = {
    "unknown-plan", "invalid-alias", "unknown-variant", "fixed-variant",
    "no-applicable-modules", "unclassified-response", "non-json-response", "accepted",
}
PHASES = {"plan-create", "module-create", "module-start"}
EXCEPTION_CLASSES = {"KeyError", "TypeError", "ValueError", "RuntimeError", "Exception", "AssertionError",
                     "FileNotFoundError", "ServerUnavailableError", "UnrecoverableHTTPError", "ServerUnhealthyError"}
KEY_FIELDS = {"test", "test_name", "testModule", "modules", "name", "id", "status", "variant", "server",
              "client", "client2", "resource", "alias", "jwks", "scope", "dpop_signing_alg"}


def safe_module_name(value):
    return isinstance(value, str) and re.fullmatch(r"(?:oidcc|fapi2)-[a-z0-9-]{1,120}", value) is not None


def plan_diagnostic(response, phase="plan-create"):
    diagnostic = {"phase": phase, "http_status": response.status_code, "category": "unclassified-response"}
    if 200 <= response.status_code < 300:
        diagnostic["category"] = "accepted"
        return diagnostic
    try:
        body = response.json()
    except ValueError:
        diagnostic["category"] = "non-json-response"
        return diagnostic
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, str):
        # Match only fixed official templates; no response text is published.
        templates = (
            (r"No plan with name: .*", "unknown-plan"),
            (r"Invalid alias value .*alias can only contain alphanumeric characters, _ and -\.", "invalid-alias"),
            (r"Unknown variant parameter\(s\) .*", "unknown-variant"),
            (r"Variant '.*' has been set by user, but test plan already sets this variant for module '.*'", "fixed-variant"),
            (r"No test modules in plan '.*' are applicable for specified variant", "no-applicable-modules"),
        )
        for pattern, category in templates:
            if re.fullmatch(pattern, error, re.DOTALL):
                diagnostic["category"] = category
                break
    return diagnostic


def public_failure_diagnostics(path):
    """Validate the observer's fixed schema again before crossing the privacy boundary."""
    seen = set()
    for line in path.read_text().splitlines():
        # The pinned official runner replaces sys.stdout with timestamp_filter.
        line = re.sub(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ", "", line)
        if not line.startswith(PREFIX):
            exception = re.match(r"([A-Za-z]+Error|Exception):\s*(.*)", line)
            if exception and exception[1] in EXCEPTION_CLASSES:
                diagnostic = "official-runner-exception: " + exception[1]
                field = re.fullmatch(r"'([A-Za-z_][A-Za-z0-9_]*)'", exception[2])
                if exception[1] == "KeyError" and field and field[1] in KEY_FIELDS:
                    diagnostic += "; field=" + field[1]
                if diagnostic not in seen:
                    seen.add(diagnostic)
                    yield diagnostic
            continue
        try:
            value = json.loads(line[len(PREFIX):])
        except ValueError:
            continue
        if (isinstance(value, dict) and set(value) in ({"http_status", "category"}, {"phase", "http_status", "category"}, {"phase", "http_status", "category", "module"})
                and type(value["http_status"]) is int and 100 <= value["http_status"] <= 599
                and isinstance(value.get("phase", "plan-create"), str) and value.get("phase", "plan-create") in PHASES
                and ("module" not in value or (value.get("phase") == "module-create" and safe_module_name(value["module"])))
                and isinstance(value["category"], str) and value["category"] in CATEGORIES):
            module = " [" + value["module"] + "]" if "module" in value else ""
            diagnostic = f"official-{value.get('phase', 'plan-create')}{module}: HTTP {value['http_status']}; {value['category']}"
            if diagnostic not in seen:
                seen.add(diagnostic)
                yield diagnostic


def main():
    import httpx

    runner = Path(sys.argv[1]).resolve()
    original_send = httpx.AsyncClient.send

    async def observed_send(client, request, *args, **kwargs):
        response = await original_send(client, request, *args, **kwargs)
        if request.method == "POST":
            phase = {"/api/plan": "plan-create", "/api/runner": "module-create"}.get(request.url.path)
            if re.fullmatch(r"/api/runner/[A-Za-z0-9-]+", request.url.path) and response.status_code != 200:
                phase = "module-start"
            if phase:
                diagnostic = plan_diagnostic(response, phase)
                module = request.url.params.get("test")
                if phase == "module-create" and safe_module_name(module):
                    diagnostic["module"] = module
                # Bypass the official timestamp filter for our fixed-schema line.
                print(PREFIX + json.dumps(diagnostic), file=sys.__stdout__, flush=True)
        return response

    httpx.AsyncClient.send = observed_send
    sys.path.insert(0, str(runner.parent))
    sys.argv = [str(runner), *sys.argv[2:]]
    runpy.run_path(str(runner), run_name="__main__")


if __name__ == "__main__":
    main()
