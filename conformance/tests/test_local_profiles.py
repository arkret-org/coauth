"""Local official profiles must match real registrations and private keys."""

import base64
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import yaml


class LocalProfilesTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "generated.yaml"
            generated.write_text(yaml.safe_dump({"database": {}, "http": {}}))
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

    def test_login_hint_targets_the_registered_real_account(self):
        with self.fixture() as (root, _):
            user = json.loads((root / "browser-user.json").read_text())
            for name in ("basic-op", "fapi2-baseline"):
                profile = json.loads((root / "full-plans" / f"{name}.json").read_text())
                self.assertEqual(profile["server"]["login_hint"], user["handle"])

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
