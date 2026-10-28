"""Official HTTP failures stay actionable without publishing response/configuration text."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "runner_diagnostics", Path(__file__).resolve().parents[1] / "official-runner-diagnostics.py",
)
DIAGNOSTICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTICS)


class RunnerDiagnosticsTests(unittest.TestCase):
    def test_official_failure_templates_preserve_status_and_hide_values(self):
        class Reply:
            status_code = 400

            def __init__(self, body):
                self.body = body

            def json(self):
                return self.body

        cases = (
            ("No plan with name: PRIVATE_SENTINEL", "unknown-plan"),
            ("Invalid alias value 'PRIVATE_SENTINEL'. alias can only contain alphanumeric characters, _ and -.", "invalid-alias"),
            ("Unknown variant parameter(s) [PRIVATE_SENTINEL] for plan 'x'. Known parameters: []", "unknown-variant"),
            ("Variant 'PRIVATE_SENTINEL' has been set by user, but test plan already sets this variant for module 'x'", "fixed-variant"),
            ("No test modules in plan 'PRIVATE_SENTINEL' are applicable for specified variant", "no-applicable-modules"),
            ("PRIVATE_SENTINEL", "unclassified-response"),
        )
        for error, category in cases:
            value = DIAGNOSTICS.plan_diagnostic(Reply({"error": error, "config": "PRIVATE_SENTINEL"}))
            self.assertEqual(value, {"phase": "plan-create", "http_status": 400, "category": category})
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(value))
        self.assertEqual(DIAGNOSTICS.plan_diagnostic(Reply(None))["category"], "unclassified-response")

    def test_official_timestamp_prefix_and_safe_exception_field_survive_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner-private.log"
            path.write_text("2026-10-28 16:01:27 " + DIAGNOSTICS.PREFIX + json.dumps({
                "phase": "module-create", "http_status": 400, "category": "unclassified-response",
            }) + "\nKeyError: 'test_name'\nKeyError: 'PRIVATE_SENTINEL'\nException: PRIVATE_SENTINEL\n")
            public = list(DIAGNOSTICS.public_failure_diagnostics(path))
            self.assertEqual(public, [
                "official-module-create: HTTP 400; unclassified-response",
                "official-runner-exception: KeyError; field=test_name",
                "official-runner-exception: KeyError",
                "official-runner-exception: Exception",
            ])
            self.assertNotIn("PRIVATE_SENTINEL", str(public))

    def test_plan_creation_is_an_http_observation_not_a_protocol_result(self):
        class Reply:
            status_code = 201

            def json(self):
                raise AssertionError("Accepted response payload must not be inspected or published")

        self.assertEqual(DIAGNOSTICS.plan_diagnostic(Reply()), {
            "phase": "plan-create", "http_status": 201, "category": "accepted",
        })

    def test_module_diagnostic_accepts_only_fixed_family_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner-private.log"
            values = [{"phase": "module-create", "http_status": 400, "category": "unclassified-response", "module": name}
                      for name in ("fapi2-security-profile-id2-happy-flow", "PRIVATE_SENTINEL", "https://private/?code=secret", [])]
            path.write_text("\n".join(DIAGNOSTICS.PREFIX + json.dumps(value) for value in values))
            self.assertEqual(list(DIAGNOSTICS.public_failure_diagnostics(path)), [
                "official-module-create [fapi2-security-profile-id2-happy-flow]: HTTP 400; unclassified-response",
            ])

    def test_public_log_reader_rejects_raw_values_and_malformed_diagnostics(self):
        values = [
            {"http_status": 400, "category": "fixed-variant"},
            {"http_status": 400, "category": "PRIVATE_SENTINEL"},
            {"http_status": 400, "category": []},
            {"http_status": 400, "category": "fixed-variant", "config": "PRIVATE_SENTINEL"},
            {"http_status": True, "category": "fixed-variant"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner-private.log"
            path.write_text("PRIVATE_SENTINEL\n" + "\n".join(
                DIAGNOSTICS.PREFIX + json.dumps(value) for value in values
            ) + "\n" + DIAGNOSTICS.PREFIX + "not-json")
            self.assertEqual(list(DIAGNOSTICS.public_failure_diagnostics(path)), [
                "official-plan-create: HTTP 400; fixed-variant",
            ])


if __name__ == "__main__":
    unittest.main()
