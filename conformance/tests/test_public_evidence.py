"""Credential boundaries must preserve both success and failure evidence."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


path = Path(__file__).resolve().parents[1] / "publish-evidence.py"
spec = importlib.util.spec_from_file_location("publish_evidence", path)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class PublicEvidenceTests(unittest.TestCase):
    def test_module_outcomes_preserved_without_configuration_or_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "public"
            output.mkdir()
            archive = root / "official.zip"
            sentinel = "PRIVATE_FIXTURE_SENTINEL"
            with zipfile.ZipFile(archive, "w") as bundle:
                for result in ("PASSED", "FAILED"):
                    bundle.writestr(f"test-log-{result}.json", json.dumps({
                        "testInfo": {"testName": "oidcc-discovery-endpoint-verification",
                                     "status": "FINISHED", "result": result,
                                     "config": {"client": {"client_secret": sentinel}}},
                        "results": [{"src": "CheckHttps", "result": "SUCCESS", "input": sentinel},
                                    {"src": "CheckIssuer", "result": "FAILURE", "msg": sentinel}],
                    }))
                bundle.writestr("test-log-PASSED.sig", "unchanged signature")
            original = archive.read_bytes()
            evidence.export_modules(root, output, "1" * 40)
            report = (output / "modules.json").read_text()
            self.assertNotIn(sentinel, report)
            self.assertNotIn("client_secret", report)
            self.assertEqual(original, archive.read_bytes())
            self.assertEqual({"PASSED", "FAILED"}, {module["result"] for module in json.loads(report)["modules"]})
            self.assertTrue(all(module["counts"]["FAILURE"] == 1 for module in json.loads(report)["modules"]))

    def test_junit_counts_preserved_without_properties_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "public"
            output.mkdir()
            sentinel = "PRIVATE_FIXTURE_SENTINEL"
            (root / "TEST-net.openid.conformance.condition.client.CheckDiscEndpointAllEndpointsAreHttps_UnitTest.xml").write_text(
                '<testsuite name="EndpointValidation" tests="2" failures="1" errors="0" skipped="0">'
                f'<properties><property name="client_secret" value="{sentinel}"/></properties>'
                '<testcase name="acceptHttps" classname="EndpointValidation"/>'
                f'<testcase name="rejectHttp" classname="EndpointValidation"><failure message="{sentinel}"/></testcase>'
                f'<system-out>{sentinel}</system-out></testsuite>')
            evidence.export_junit(root, output)
            self.assertNotIn(sentinel, (output / "endpoint-validation.junit.xml").read_text())
            self.assertEqual(1, json.loads((output / "junit.json").read_text())["suites"][0]["failures"])


if __name__ == "__main__":
    unittest.main()
