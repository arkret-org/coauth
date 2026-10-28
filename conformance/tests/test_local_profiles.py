"""Local official profiles must match real registrations and private keys."""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import yaml


class LocalProfilesTests(unittest.TestCase):
    def test_prompt_login_evidence_captures_only_the_actual_second_login_page(self):
        runner = self.runner()

        class Page:
            content = b"first-login-page"
            calls = 0

            def screenshot(self, **options):
                self.calls += 1
                self.options = options
                return self.content

        page = Page()
        self.assertIsNone(runner.second_login_screenshot("oidcc-prompt-login", 1, page))
        self.assertEqual(page.calls, 0)
        page.content = b"real-second-login-page"
        self.assertEqual(runner.second_login_screenshot("oidcc-prompt-login", 2, page), page.content)
        self.assertEqual(page.calls, 1)
        self.assertEqual(page.options, {"type": "jpeg", "quality": 65})
        self.assertIsNone(runner.second_login_screenshot("oidcc-server", 2, page))
        self.assertEqual(page.calls, 1)

    def test_aborted_plan_download_preserves_the_original_signed_zip_bytes(self):
        runner = self.runner()
        original = io.BytesIO()
        with zipfile.ZipFile(original, "w") as bundle:
            bundle.writestr("test-log-fixture.json", '{"testInfo":{"result":null},"private":"PRIVATE_EXPORT_SENTINEL"}')
            bundle.writestr("test-log-fixture.sig", "unit-test-signature-fixture")

        class API:
            def get(self, url, timeout, allow_redirects):
                self.call = (url, timeout, allow_redirects)
                return type("Reply", (), {"status_code": 200, "headers": {"content-type": "application/zip"}, "content": original.getvalue()})()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "runner-private.log"
            log.write_text("2026-10-28 16:42:00 Created test plan, new id: A123456789012\n")
            api = API()
            self.assertTrue(runner.export_failed_plan_evidence(api, "https://localhost:8446", root, log, 1))
            self.assertEqual(api.call, ("https://localhost:8446/api/plan/export/A123456789012", 30, False))
            self.assertEqual((root / "failed-official-plan.zip").read_bytes(), original.getvalue())
            self.assertFalse(runner.export_failed_plan_evidence(None, "https://localhost:8446", root, log, 1))

    def test_aborted_plan_export_requires_one_unambiguous_owned_run_reference(self):
        runner = self.runner()
        valid = "2026-10-28 16:42:00 Created test plan, new id: A123456789012\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "runner-private.log"
            malformed = valid.replace("A123456789012", "../PRIVATE")
            for contents in ("", valid + valid, malformed, valid + malformed):
                log.write_text(contents)
                with self.assertRaisesRegex(runner.EvidenceExportFailure, "single-created-plan-reference-required"):
                    runner.export_failed_plan_evidence(None, "https://localhost:8446", root, log, 1)
            self.assertFalse(runner.export_failed_plan_evidence(None, "https://localhost:8446", root, log, 0))
            with self.assertRaisesRegex(runner.EvidenceExportFailure, "official-runner-exit-required"):
                runner.export_failed_plan_evidence(None, "https://localhost:8446", root, log, None)

    def test_aborted_plan_export_rejects_http_errors_and_unsigned_or_non_zip_content(self):
        runner = self.runner()
        unsigned = io.BytesIO()
        with zipfile.ZipFile(unsigned, "w") as bundle:
            bundle.writestr("test-log-fixture.json", "{}")
        cases = ((403, "application/zip", b"PRIVATE_SENTINEL"),
                 (200, "application/json", b"PRIVATE_SENTINEL"),
                 (200, "application/zip", b"PRIVATE_SENTINEL"),
                 (200, "application/zip", unsigned.getvalue().replace(b"{}", b"[]", 1)),
                 (200, "application/zip", unsigned.getvalue()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "runner-private.log"
            log.write_text("2026-10-28 16:42:00 Created test plan, new id: A123456789012\n")
            for status, content_type, body in cases:
                class API:
                    def get(self, url, timeout, allow_redirects):
                        return type("Reply", (), {"status_code": status, "headers": {"content-type": content_type}, "content": body})()
                with self.assertRaises(runner.EvidenceExportFailure) as caught:
                    runner.export_failed_plan_evidence(API(), "https://localhost:8446", root, log, 1)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
                if body == unsigned.getvalue():
                    self.assertEqual((root / "failed-official-plan.zip").read_bytes(), body)
                else:
                    self.assertFalse(list(root.glob("*.zip")))

    def runner(self):
        path = Path(__file__).resolve().parents[1] / "run-official-plan.py"
        spec = importlib.util.spec_from_file_location("official_plan", path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        return runner

    def test_official_denial_action_is_exact_and_diagnostics_are_sanitized(self):
        runner = self.runner()
        self.assertEqual(runner.consent_action("fapi2-security-profile-id2-user-rejects-authentication"), "deny")
        for name in ("oidcc-login", "other-user-rejects-authentication", None):
            self.assertEqual(runner.consent_action(name), "approve")
        self.assertEqual(str(runner.BrowserFailure("https://private/?code=SECRET", "login-ui-error")), "unknown-module: login-ui-error")

    def test_cleanup_preserves_original_failure_and_alone_fails_closed(self):
        runner = self.runner()

        class BrokenScope:
            def stop_pending(self):
                raise KeyError("PRIVATE_CLEANUP_SENTINEL")

        log, public = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(public):
            with self.assertRaisesRegex(ValueError, "original-browser-failure"):
                try:
                    raise ValueError("original-browser-failure")
                finally:
                    runner.cleanup_plan(BrokenScope(), log, True)
        self.assertNotIn("PRIVATE_CLEANUP_SENTINEL", public.getvalue())
        self.assertIn("PRIVATE_CLEANUP_SENTINEL", log.getvalue())
        with self.assertRaisesRegex(RuntimeError, "local plan cleanup failed"):
            runner.cleanup_plan(BrokenScope(), log, False)

    def test_official_image_placeholder_requires_real_bytes_and_completion(self):
        runner = self.runner()

        class Reply:
            def __init__(self, body):
                self.body = body

            def raise_for_status(self):
                pass

            def json(self):
                return self.body

        class API:
            incomplete = False

            def get(self, url, timeout):
                self.asserted_url = url
                return Reply([{"upload": "0123456789"}, {"img": "already-filled"}])

            def post(self, url, data, headers, timeout):
                self.upload = (url, data, headers)
                return Reply({"upload": "0123456789"} if self.incomplete else {"img": data, "testId": "test-id"})

        api = API()
        screenshot = b"test-only-browser-image-bytes"
        runner.upload_login_evidence(api, "https://localhost:8446", "test-id", screenshot)
        self.assertEqual(api.asserted_url, "https://localhost:8446/api/log/test-id/images")
        self.assertEqual(api.upload[0], "https://localhost:8446/api/log/test-id/images/0123456789")
        self.assertEqual(base64.b64decode(api.upload[1].split(",", 1)[1]), screenshot)
        self.assertEqual(api.upload[2], {"Content-Type": "text/plain"})
        api.incomplete = True
        with self.assertRaises(runner.BrowserFailure):
            runner.upload_login_evidence(api, "https://localhost:8446", "test-id", screenshot)
        with self.assertRaises(runner.BrowserFailure):
            runner.upload_login_evidence(api, "https://localhost:8446", "test-id", b"x" * (500 * 1024 + 1))

    @contextlib.contextmanager
    def fixture(self, login_limits=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "generated.yaml"
            initial = {"database": {}, "http": {}}
            if login_limits is not None:
                initial["rate_limiting"] = {"login": login_limits}
            generated.write_text(yaml.safe_dump(initial))
            subprocess.run([
                sys.executable, str(Path(__file__).resolve().parents[1] / "prepare-local-config.py"),
                str(generated), str(root),
            ], check=True, env={
                **os.environ, "DATABASE_URL": "postgresql://localhost/isolated_fixture",
                "COAUTH_CONFORMANCE_ASSETS": str(root / "frontend"),
                "COAUTH_CONFORMANCE_FULL_PLANS_JSON": "",
            })
            config = yaml.safe_load((root / "coauth.yaml").read_text())
            yield root, config

    def test_login_pacing_preserves_real_quotas_and_derives_the_slower_refill(self):
        with self.fixture() as (root, config):
            login = config["rate_limiting"]["login"]
            self.assertEqual(login["per_ip"], {"burst": 3, "per_second": 3 / 60})
            self.assertEqual(login["per_account"], {"burst": 1800, "per_second": 1800 / 3600})
            self.assertEqual(json.loads((root / "browser-user.json").read_text())["login_interval_seconds"], 21)
        custom = {"per_ip": {"burst": 3, "per_second": 0.1}, "per_account": {"burst": 100, "per_second": 0.02},
                  "lockout": {"consecutive_failures": 10, "lockout_seconds": 60, "failure_window_seconds": 300}}
        with self.fixture(custom) as (root, config):
            self.assertEqual(config["rate_limiting"]["login"], custom)
            self.assertEqual(json.loads((root / "browser-user.json").read_text())["login_interval_seconds"], 51)

    def test_login_pacer_spaces_contexts_and_starts_a_new_plan_conservatively(self):
        runner = self.runner()
        now, sleeps = [0.0], []

        def sleep(delay):
            sleeps.append(delay)
            now[0] += delay

        pacer = runner.LoginPacer(21, lambda: now[0], sleep)
        pacer.wait()
        self.assertEqual(now[0], 21)
        now[0] += 3
        pacer.wait()
        self.assertEqual(now[0], 42)
        next_plan = runner.LoginPacer(21, lambda: now[0], sleep)
        next_plan.wait()
        self.assertEqual(now[0], 63)
        self.assertEqual(sleeps, [21, 18, 21])
        for invalid in (0, -1, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                runner.LoginPacer(invalid, lambda: now[0], sleep)

    def test_login_hint_targets_the_registered_real_account(self):
        with self.fixture() as (root, _):
            user = json.loads((root / "browser-user.json").read_text())
            for name in ("basic-op", "fapi2-baseline"):
                profile = json.loads((root / "full-plans" / f"{name}.json").read_text())
                self.assertEqual(profile["server"]["login_hint"], user["handle"])

    def test_fapi_caller_only_supplies_selectable_variants(self):
        with self.fixture() as (root, _):
            profile = json.loads((root / "full-plans/fapi2-baseline.json").read_text())
            self.assertEqual(profile["_official_plan"], "fapi2-security-profile-id2-test-plan")
            self.assertEqual(profile["variant"], {
                "client_auth_type": "private_key_jwt", "fapi_profile": "plain_fapi",
                "sender_constrain": "dpop", "openid": "openid_connect", "authorization_request_type": "simple",
            })

    def test_client_secret_post_uses_an_independent_registered_client(self):
        with self.fixture() as (root, config):
            profile = json.loads((root / "full-plans/basic-op.json").read_text())
            post = profile["client_secret_post"]
            self.assertNotIn(post["client_id"], {profile["client"]["client_id"], profile["client2"]["client_id"]})
            clients = {client["client_id"]: client for client in config["clients"]}
            registration = clients[post["client_id"]]
            self.assertEqual(registration["client_auth_method"], "client_secret_post")
            self.assertEqual(registration["client_secret"], post["client_secret"])
            self.assertIn(f'https://localhost:8446/test/a/{profile["alias"]}/callback', registration["redirect_uris"])
            self.assertEqual(clients[profile["client"]["client_id"]]["client_auth_method"], "client_secret_basic")

    def test_local_plan_never_drives_or_cancels_previous_profile_ids(self):
        path = Path(__file__).resolve().parents[1] / "run-official-plan.py"
        spec = importlib.util.spec_from_file_location("official_plan", path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)

        class Reply:
            status_code = 200

            def __init__(self, body):
                self.body = body

            def raise_for_status(self):
                pass

            def json(self):
                return self.body

        class API:
            states = {"previous-waiting": "WAITING", "previous-finished": "FINISHED"}

            def __init__(self):
                self.states = dict(self.states)
                self.stopped = []
                self.read = []

            def get(self, url, timeout):
                if url.endswith("/running"):
                    return Reply(list(self.states))
                test_id = url.rsplit("/", 1)[1]
                self.read.append(test_id)
                if "/api/info/" not in url:
                    raise AssertionError("runner metadata has no status; use persisted official info")
                return Reply({"status": self.states[test_id]})

            def delete(self, url, timeout):
                test_id = url.rsplit("/", 1)[1]
                self.stopped.append(test_id)
                self.states[test_id] = "INTERRUPTED"
                return Reply({})

        api = API()
        scope = runner.LocalPlanScope(api, "https://localhost:8446")
        api.states.update({"current-waiting": "WAITING", "current-finished": "FINISHED"})
        self.assertEqual(scope.test_ids(), ["current-finished", "current-waiting"])
        scope.stop_pending()
        self.assertEqual(api.stopped, ["current-waiting"])
        self.assertEqual(api.states["previous-waiting"], "WAITING")
        self.assertNotIn("previous-waiting", api.read)
        api.states["../unexpected"] = "WAITING"
        with self.assertRaises(RuntimeError):
            scope.test_ids()

    def test_real_registrations_keys_and_unavailable_mtls(self):
        with self.fixture() as (root, config):
            clients = {client["client_id"]: client for client in config["clients"]}
            resources = config["http"]["listeners"][0]["resources"]
            self.assertIn({"name": "restapi"}, resources)
            self.assertIn({"name": "assets", "path": str(root / "frontend")}, resources)
            for name in ("basic-op", "fapi2-baseline"):
                profile = json.loads((root / "full-plans" / f"{name}.json").read_text())
                for slot in ("client", "client2"):
                    client = profile[slot]
                    registration = clients[client["client_id"]]
                    self.assertIn(f'https://localhost:8446/test/a/{profile["alias"]}/callback', registration["redirect_uris"])
                    if name == "basic-op":
                        self.assertEqual(client["client_secret"], registration["client_secret"])
                        continue
                    self.assertEqual(profile["resource"]["resourceUrl"], "https://localhost:8445/oauth/userinfo")
                    if slot == "client2":
                        self.assertIn(f'https://localhost:8446/test/a/{profile["alias"]}/callback?dummy1=lorem&dummy2=ipsum', registration["redirect_uris"])
                    key = client["jwks"]["keys"][0]
                    public = registration["jwks"]["keys"][0]
                    self.assertTrue({"d", "p", "q", "dp", "dq", "qi"}.isdisjoint(public))

                    def integer(field):
                        return int.from_bytes(base64.urlsafe_b64decode(key[field] + "=" * (-len(key[field]) % 4)), "big")

                    private = rsa.RSAPrivateNumbers(
                        integer("p"), integer("q"), integer("d"), integer("dp"), integer("dq"), integer("qi"),
                        rsa.RSAPublicNumbers(integer("e"), integer("n")),
                    ).private_key()
                    signature = private.sign(b"official-client-fixture", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
                    public_key = rsa.RSAPublicNumbers(
                        int.from_bytes(base64.urlsafe_b64decode(public["e"] + "=" * (-len(public["e"]) % 4)), "big"),
                        int.from_bytes(base64.urlsafe_b64decode(public["n"] + "=" * (-len(public["n"]) % 4)), "big"),
                    ).public_key()
                    public_key.verify(signature, b"official-client-fixture", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
            mtls = json.loads((root / "full-plans/mtls-baseline.json").read_text())
            self.assertIn("RFC8705", mtls["_unavailable"])
            self.assertNotIn("_official_plan", mtls)


if __name__ == "__main__":
    unittest.main()
