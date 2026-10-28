"""Observe plan creation errors without exposing configuration or altering requests."""

import json
from pathlib import Path
import re
import runpy
import sys


PREFIX = "COAUTH_OIDF_PLAN_DIAGNOSTIC="
CATEGORIES = {
    "unknown-plan", "invalid-alias", "unknown-variant", "fixed-variant",
    "no-applicable-modules", "unclassified-response", "non-json-response",
}


def plan_diagnostic(response):
    diagnostic = {"http_status": response.status_code, "category": "unclassified-response"}
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
    for line in path.read_text().splitlines():
        if not line.startswith(PREFIX):
            continue
        try:
            value = json.loads(line[len(PREFIX):])
        except ValueError:
            continue
        if (isinstance(value, dict) and set(value) == {"http_status", "category"}
                and type(value["http_status"]) is int and 100 <= value["http_status"] <= 599
                and isinstance(value["category"], str) and value["category"] in CATEGORIES):
            yield f"official-plan-create: HTTP {value['http_status']}; {value['category']}"


def main():
    import httpx

    runner = Path(sys.argv[1]).resolve()
    original_send = httpx.AsyncClient.send

    async def observed_send(client, request, *args, **kwargs):
        response = await original_send(client, request, *args, **kwargs)
        if request.method == "POST" and request.url.path == "/api/plan" and response.status_code != 201:
            print(PREFIX + json.dumps(plan_diagnostic(response)), flush=True)
        return response

    httpx.AsyncClient.send = observed_send
    sys.path.insert(0, str(runner.parent))
    sys.argv = [str(runner), *sys.argv[2:]]
    runpy.run_path(str(runner), run_name="__main__")


if __name__ == "__main__":
    main()
