"""Invoke the pinned OIDF API runner without ignored failures or skips."""

import argparse
import base64
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback
from urllib.parse import urlsplit
import zipfile


REJECT_MODULE = "fapi2-security-profile-id2-user-rejects-authentication"


class EvidenceExportFailure(RuntimeError):
    """Only fixed stages and HTTP status codes cross the private-log boundary."""


def export_failed_plan_evidence(api, server, results, private_log, returncode):
    """Read the original signed export when an aborted official queue never exported."""
    if type(returncode) is not int:
        raise EvidenceExportFailure("official-runner-exit-required")
    if returncode == 0 or any(results.glob("*.zip")):
        return False
    if server != "https://localhost:8446":
        raise EvidenceExportFailure("isolated-suite-origin-required")
    # The pinned runner prints this exact line after successful plan creation.
    # Multiple references are ambiguous even when they repeat the same ID.
    ids = re.findall(
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} Created test plan, new id: (.*)$",
        private_log.read_text(), re.MULTILINE,
    )
    if len(ids) != 1 or not re.fullmatch(r"[A-Za-z0-9]{13}", ids[0]):
        raise EvidenceExportFailure("single-created-plan-reference-required")
    # LogApi.exportLogsOfPlan uses owner-scoped getTestPlan; public defaults
    # to false. Reuse the browser driver's existing authenticated/TLS session.
    response = api.get(f"{server}/api/plan/export/{ids[0]}", timeout=30, allow_redirects=False)
    if response.status_code != 200:
        raise EvidenceExportFailure(f"http-status-{response.status_code}")
    if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/zip":
        raise EvidenceExportFailure("zip-content-type-required")
    archive = response.content
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            if bundle.testzip() is not None:
                raise EvidenceExportFailure("zip-integrity-failed")
            names = set(bundle.namelist())
            records = [name for name in names if name.startswith("test-log-") and name.endswith(".json")]
            # LogApi.exportLogsOfPlan pairs X.json with X.sig.
            signed_records = bool(records) and all(name.removesuffix(".json") + ".sig" in names for name in records)
    except zipfile.BadZipFile:
        raise EvidenceExportFailure("invalid-zip-response") from None
    # No ZIP entries, signatures, or outcome fields are reconstructed here.
    with (results / "failed-official-plan.zip").open("xb") as destination:
        destination.write(archive)
    # A shape mismatch must fail without discarding the original private bytes
    # or the authoritative condition failures available to the privacy filter.
    if not signed_records:
        raise EvidenceExportFailure("original-signed-module-records-required")
    return True


class BrowserFailure(RuntimeError):
    """Only fixed phases and validated module names may enter public logs."""

    def __init__(self, module, phase):
        safe_module = module if isinstance(module, str) and re.fullmatch(r"[a-z0-9-]+", module) else "unknown-module"
        super().__init__(f"{safe_module}: {phase}")


def consent_action(module):
    return "deny" if module == REJECT_MODULE else "approve"


def second_login_screenshot(module, ordinal, page):
    """The official prompt-login placeholder requires the second login page."""
    if module == "oidcc-prompt-login" and ordinal == 2:
        return page.screenshot(type="jpeg", quality=65)
    return None


class LoginPacer:
    """Respect the fixture's real quotas across modules and browser contexts."""

    def __init__(self, interval, clock=time.monotonic, sleep=time.sleep):
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval) or interval <= 0:
            raise ValueError("invalid configured login interval")
        self.interval, self.clock, self.sleep = interval, clock, sleep
        # Another plan may have just used this same deployment/IP budget.
        self.next_login = clock() + interval

    def wait(self):
        remaining = self.next_login - self.clock()
        if remaining > 0:
            self.sleep(remaining)
        self.next_login = self.clock() + self.interval


def upload_login_evidence(api, server, test_id, screenshot):
    """Fill actual official placeholders with a real browser screenshot."""
    response = api.get(f"{server}/api/log/{test_id}/images", timeout=30)
    response.raise_for_status()
    for document in response.json():
        placeholder = document.get("upload")
        if not placeholder:
            continue
        if not isinstance(placeholder, str) or not re.fullmatch(r"[A-Za-z0-9]{10}", placeholder):
            raise BrowserFailure("oidcc-prompt-login", "invalid-image-placeholder")
        if len(screenshot) > 500 * 1024:
            raise BrowserFailure("oidcc-prompt-login", "screenshot-exceeds-official-limit")
        image = "data:image/jpeg;base64," + base64.b64encode(screenshot).decode("ascii")
        uploaded = api.post(
            f"{server}/api/log/{test_id}/images/{placeholder}",
            data=image,
            headers={"Content-Type": "text/plain"}, timeout=30,
        )
        uploaded.raise_for_status()
        completed = uploaded.json()
        if not isinstance(completed, dict) or "upload" in completed or completed.get("testId") != test_id or completed.get("img") != image:
            raise BrowserFailure("oidcc-prompt-login", "image-placeholder-not-completed")


class LocalPlanScope:
    """Own only tests created after this isolated local plan starts."""

    def __init__(self, api, server):
        self.api = api
        self.server = server
        self.baseline = self.running_ids()

    def running_ids(self):
        response = self.api.get(self.server + "/api/runner/running", timeout=30)
        response.raise_for_status()
        ids = response.json()
        if not isinstance(ids, list) or not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9-]+", value) for value in ids):
            raise RuntimeError("unexpected official test identifiers")
        return set(ids)

    def test_ids(self):
        return sorted(self.running_ids() - self.baseline)

    def stop_pending(self):
        for test_id in self.test_ids():
            url = f"{self.server}/api/runner/{test_id}"
            response = self.api.get(f"{self.server}/api/info/{test_id}", timeout=30)
            if response.status_code == 404:
                continue
            response.raise_for_status()
            if response.json()["status"] not in {"FINISHED", "INTERRUPTED"}:
                response = self.api.delete(url, timeout=30)
                if response.status_code != 404:
                    response.raise_for_status()


def cleanup_plan(scope, log, failure_active):
    try:
        scope.stop_pending()
    except Exception:
        traceback.print_exc(file=log)
        if not failure_active:
            raise RuntimeError("local plan cleanup failed; private diagnostics were withheld") from None
        print("::error::Local plan cleanup also failed; the original browser failure is preserved", flush=True)


def drive_local_browser(process, scope):
    """Visit the official runner's front-channel URLs with the real WASM UI."""
    from playwright.sync_api import sync_playwright

    credentials = json.loads(Path(os.environ["COAUTH_CONFORMANCE_BROWSER_USER"]).read_text())
    pacer = LoginPacer(credentials["login_interval_seconds"])
    server, api = scope.server, scope.api
    allowed = {"https://localhost:8445", server}

    def origin(url):
        parsed = urlsplit(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        contexts = {}
        visited = set()
        login_screenshots = {}
        password_submissions = {}
        try:
            while process.poll() is None:
                for test_id in scope.test_ids():
                    response = api.get(f"{server}/api/runner/{test_id}", timeout=30)
                    if response.status_code in (404, 503):
                        continue
                    response.raise_for_status()
                    metadata = response.json()
                    module = metadata.get("name")
                    if module == "oidcc-prompt-login" and test_id in login_screenshots:
                        upload_login_evidence(api, server, test_id, login_screenshots[test_id])
                    for request in metadata.get("browser", {}).get("urlsWithMethod", []):
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
                        phase = "navigation"
                        submitted_password = False
                        submitted_decision = False
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
                                    raise BrowserFailure(module, "login-or-consent-timeout")
                                if page.locator("#login-error").is_visible():
                                    raise BrowserFailure(module, "login-ui-error")
                                if page.locator("#login-handle").is_visible():
                                    phase = "identifier-login"
                                    page.locator("#login-handle").fill(credentials["handle"])
                                    page.get_by_test_id("coauth-login-identifier-submit").click()
                                    page.locator("#login-handle").wait_for(state="hidden", timeout=30000)
                                elif page.locator("#login-password").is_visible():
                                    phase = "password-login"
                                    if submitted_password:
                                        raise BrowserFailure(module, "password-phase-did-not-advance")
                                    pacer.wait()
                                    ordinal = password_submissions.get(test_id, 0) + 1
                                    screenshot = second_login_screenshot(module, ordinal, page)
                                    if screenshot is not None:
                                        login_screenshots[test_id] = screenshot
                                    page.locator("#login-password").fill(credentials["password"])
                                    submitted_password = True
                                    password_submissions[test_id] = ordinal
                                    print("::notice::OIDF " + str(BrowserFailure(module, f"password-submit-{ordinal}")), flush=True)
                                    with page.expect_response(lambda reply: urlsplit(reply.url).path == "/_coauth/account/auth/login", timeout=30000) as login:
                                        page.get_by_test_id("coauth-login-submit").click()
                                    login_body = login.value.json()
                                    if login.value.status != 200 or login_body.get("status") != "success":
                                        # Never interpolate response text, credentials or redirect URLs.
                                        code = login_body.get("error")
                                        known = {"invalid_credentials", "rate_limited", "account_deactivated", "account_locked", "password_login_disabled"}
                                        raise BrowserFailure(module, "login-" + (code if code in known else "unexpected-response"))
                                    page.locator("#login-password").wait_for(state="hidden", timeout=30000)
                                elif page.get_by_test_id("coauth-continue-as-current").is_visible():
                                    phase = "continue-current-account"
                                    page.get_by_test_id("coauth-continue-as-current").click()
                                    page.get_by_test_id("coauth-continue-as-current").wait_for(state="hidden", timeout=30000)
                                elif page.get_by_test_id("coauth-oauth-approve").is_visible():
                                    phase = "authorization-decision"
                                    if submitted_decision:
                                        raise BrowserFailure(module, "consent-phase-did-not-advance")
                                    action = consent_action(module)
                                    submitted_decision = True
                                    with page.expect_response(lambda reply: urlsplit(reply.url).path.endswith("/decision") and reply.request.method == "POST", timeout=30000) as decision:
                                        page.get_by_test_id("coauth-oauth-" + action).click()
                                    if decision.value.status != 200:
                                        raise BrowserFailure(module, "consent-http-error")
                                    page.get_by_test_id("coauth-oauth-" + action).wait_for(state="hidden", timeout=30000)
                                page.wait_for_timeout(250)
                            response = api.post(f"{server}/api/runner/browser/{test_id}/visit", params={"url": url}, timeout=30)
                            if response.status_code != 404:
                                response.raise_for_status()
                            visited.add((test_id, url))
                        except BrowserFailure:
                            raise
                        except Exception as error:
                            raise BrowserFailure(module, phase + "-" + type(error).__name__) from error
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
        os.environ.get("PYTHON", "python3"), str(Path(__file__).with_name("official-runner-diagnostics.py")),
        str(source / "scripts/run-test-plan.py"),
        "--no-parallel", "--export-dir", str(results), plan, config_path.name,
    ]
    if config.get("_browser_driver") == "chromium":
        import requests

        server = os.environ["CONFORMANCE_SERVER"].rstrip("/")
        if server != "https://localhost:8446" or not os.environ.get("CONFORMANCE_DEV_MODE"):
            raise RuntimeError("the local browser driver requires the isolated local suite")
        # Raw runner output can contain redirect codes; it stays in the private
        # results tree and never becomes a public evidence artifact.
        with requests.Session() as api, (results / "runner-private.log").open("w") as log:
            api.verify = os.environ["CURL_CA_BUNDLE"]
            # Snapshot before starting the runner: an earlier failed profile's
            # pending browser requests must never drive this plan's credentials.
            scope = LocalPlanScope(api, server)
            process = subprocess.Popen(command, cwd=config_path.parent, stdout=log, stderr=subprocess.STDOUT)
            try:
                try:
                    drive_local_browser(process, scope)
                except Exception as error:
                    traceback.print_exc(file=log)
                    if isinstance(error, BrowserFailure):
                        raise RuntimeError(str(error)) from None
                    raise RuntimeError("local real-browser automation failed (" + type(error).__name__ + "); private URL diagnostics were withheld") from None
                returncode = process.wait()
                if returncode != 0:
                    log.flush()
                    diagnostics_path = Path(__file__).with_name("official-runner-diagnostics.py")
                    spec = importlib.util.spec_from_file_location("official_diagnostics", diagnostics_path)
                    diagnostics = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(diagnostics)
                    for diagnostic in diagnostics.public_failure_diagnostics(results / "runner-private.log"):
                        print("::notice::OIDF diagnostic: " + diagnostic, flush=True)
                    try:
                        if export_failed_plan_evidence(api, server, results, results / "runner-private.log", returncode):
                            print("::notice::Downloaded original official aborted-plan evidence; runner failure is retained", flush=True)
                    except Exception as error:
                        traceback.print_exc(file=log)
                        diagnostic = str(error) if isinstance(error, EvidenceExportFailure) else type(error).__name__
                        print("::notice::OIDF aborted-plan export: " + diagnostic, flush=True)
                    raise RuntimeError("the official conformance plan failed; inspect credential-free exported evidence")
            finally:
                failure_active = sys.exc_info()[0] is not None
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                cleanup_plan(scope, log, failure_active)
    else:
        subprocess.run(command, cwd=config_path.parent, check=True)
    if not list(results.glob("*.zip")):
        raise RuntimeError("the official runner produced no exported test result")


if __name__ == "__main__":
    main()
