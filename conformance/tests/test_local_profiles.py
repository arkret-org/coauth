"""Local official profiles must match real registrations and private keys."""

import base64
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
    def test_real_registrations_keys_and_unavailable_mtls(self):
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
