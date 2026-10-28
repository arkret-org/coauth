"""Invoke the pinned OIDF API runner without ignored failures or skips."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import traceback
from urllib.parse import urlsplit


def drive_local_browser(process):
    """Visit the official runner's front-channel URLs with the real WASM UI."""
    import requests
    from playwright.sync_api import sync_playwright

    credentials = json.loads(Path(os.environ["COAUTH_CONFORMANCE_BROWSER_USER"]).read_text())
    server = os.environ["CONFORMANCE_SERVER"].rstrip("/")
    if server != "https://localhost:8446" or not os.environ.get("CONFORMANCE_DEV_MODE"):
        raise RuntimeError("the local browser driver requires the isolated local suite")
    allowed = {"https://localhost:8445", server}

    def origin(url):
        parsed = urlsplit(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    with requests.Session() as api, sync_playwright() as playwright:
        api.verify = os.environ["CURL_CA_BUNDLE"]
        browser = playwright.chromium.launch()
        contexts = {}
        visited = set()
        try:
            while process.poll() is None:
                response = api.get(server + "/api/runner/running", timeout=30)
                response.raise_for_status()
                for test_id in response.json():
                    if not re.fullmatch(r"[A-Za-z0-9-]+", test_id):
                        raise RuntimeError("unexpected official test identifier")
                    response = api.get(f"{server}/api/runner/{test_id}", timeout=30)
                    if response.status_code in (404, 503):
                        continue
                    response.raise_for_status()
                    for request in response.json().get("browser", {}).get("urlsWithMethod", []):
                        url, method = request["url"], request["method"]
                        if method not in {"GET", "POST"}:
                            raise RuntimeError("unsupported official front-channel HTTP method")
                        if (test_id, url) in visited:
                            continue
                        if origin(url) not in allowed:
                            raise RuntimeError("official front-channel URL is outside the local fixture")
                        if test_id not in contexts:
                            context = browser.new_context(ignore_https_errors=True)
                            context.route("**/*", lambda route: route.continue_() if origin(route.request.url) in allowed else route.abort())
                            contexts[test_id] = context
                        page = contexts[test_id].new_page()
                        try:
                            if method == "POST":
                                # Match upstream BrowserControl: move the supplied URL's
                                # query to a form body, preserving real browser cookies.
                                parsed = urlsplit(url)
                                page.route(url, lambda route: route.continue_(
                                    url=parsed._replace(query="", fragment="").geturl(),
                                    method="POST", post_data=parsed.query,
                                    headers={**route.request.headers, "content-type": "application/x-www-form-urlencoded"},
                                ), times=1)
                            navigation = page.goto(url, wait_until="domcontentloaded", timeout=60000)
                            deadline = time.monotonic() + 120
                            while origin(page.url) != server:
                                # An OP error page can be the correct outcome of a negative module.
                                # Only the official protocol assertions decide whether it passes.
                                if navigation is not None and navigation.status >= 400:
                                    break
                                if time.monotonic() > deadline:
                                    raise RuntimeError("local browser could not finish login/consent")
                                if page.locator("#login-error").is_visible():
                                    raise RuntimeError("the seeded local browser account could not log in")
                                if page.locator("#login-handle").is_visible():
                                    page.locator("#login-handle").fill(credentials["handle"])
                                    page.get_by_test_id("coauth-login-identifier-submit").click()
                                elif page.locator("#login-password").is_visible():
                                    page.locator("#login-password").fill(credentials["password"])
                                    page.get_by_test_id("coauth-login-submit").click()
                                elif page.get_by_test_id("coauth-continue-as-current").is_visible():
                                    page.get_by_test_id("coauth-continue-as-current").click()
                                elif page.get_by_test_id("coauth-oauth-approve").is_visible():
                                    page.get_by_test_id("coauth-oauth-approve").click()
                                page.wait_for_timeout(250)
                            response = api.post(f"{server}/api/runner/browser/{test_id}/visit", params={"url": url}, timeout=30)
                            if response.status_code != 404:
                                response.raise_for_status()
                            visited.add((test_id, url))
                        finally:
                            page.close()
                time.sleep(0.5)
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text())
    if not re.fullmatch(r"[a-z0-9-]+", args.plan):
        parser.error("invalid official plan name")
    plan = args.plan
    for key, value in config.get("variant", {}).items():
        if not isinstance(value, str) or not all(re.fullmatch(r"[a-z0-9_-]+", part) for part in (key, value)):
            parser.error("invalid official variant")
        plan += f"[{key}={value}]"
    if not os.environ.get("CONFORMANCE_SERVER"):
        parser.error("CONFORMANCE_SERVER must identify the running OIDF API server")
    if not os.environ.get("CONFORMANCE_DEV_MODE") and not os.environ.get("CONFORMANCE_TOKEN"):
        parser.error("external OIDF deployments require CONFORMANCE_TOKEN")
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    command = [
        os.environ.get("PYTHON", "python3"), str(source / "scripts/run-test-plan.py"),
        "--no-parallel", "--export-dir", str(results), plan, config_path.name,
    ]
    if config.get("_browser_driver") == "chromium":
        # Raw runner output can contain redirect codes; it stays in the private
        # results tree and never becomes a public evidence artifact.
        with (results / "runner-private.log").open("w") as log:
            process = subprocess.Popen(command, cwd=config_path.parent, stdout=log, stderr=subprocess.STDOUT)
            try:
                try:
                    drive_local_browser(process)
                except Exception:
                    traceback.print_exc(file=log)
                    raise RuntimeError("local real-browser automation failed; private URL diagnostics were withheld") from None
                if process.wait() != 0:
                    raise RuntimeError("the official conformance plan failed; inspect credential-free exported evidence")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    else:
        subprocess.run(command, cwd=config_path.parent, check=True)
    if not list(results.glob("*.zip")):
        raise RuntimeError("the official runner produced no exported test result")


if __name__ == "__main__":
    main()
