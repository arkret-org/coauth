"""Export conformance outcomes without configuration, HTTP payloads or credentials."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", value):
        raise ValueError("invalid evidence identifier")
    return value


def export_modules(archives, output, source_ref):
    if not re.fullmatch(r"[a-f0-9]{40}", source_ref):
        raise ValueError("invalid pinned suite source")
    modules = []
    for archive in sorted(archives.rglob("*.zip")):
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if not name.startswith("test-log-") or not name.endswith(".json"):
                    continue
                document = json.loads(bundle.read(name))
                info = document["testInfo"]
                result = info["result"]
                status = info["status"]
                if result not in {"PASSED", "FAILED", "WARNING", "UNKNOWN", "SKIPPED"}:
                    raise ValueError("unknown official module outcome")
                if status not in {"CREATED", "CONFIGURED", "RUNNING", "WAITING", "FINISHED", "INTERRUPTED", "UNKNOWN"}:
                    raise ValueError("unknown official module status")
                conditions = []
                for row in document["results"]:
                    if row.get("result") not in {"SUCCESS", "FAILURE", "WARNING"}:
                        continue
                    conditions.append({
                        "condition": identifier(row["src"]),
                        "result": row["result"],
                    })
                counts = Counter(condition["result"] for condition in conditions)
                modules.append({
                    "test_name": identifier(info["testName"]),
                    "status": status,
                    "result": result,
                    "conditions": conditions,
                    "counts": {key: counts[key] for key in ("SUCCESS", "FAILURE", "WARNING")},
                    "original_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                })
    (output / "modules.json").write_text(json.dumps({
        "scope": "Official modules executed; full certification is not inferred from Discovery",
        "suite_source": source_ref,
        "local_suite_repair": "literal metadata member lookup",
        "modules": modules,
    }, indent=2) + "\n")


def export_junit(reports, output):
    suites = []
    pattern = "TEST-net.openid.conformance.condition.client.CheckDiscEndpointAllEndpointsAreHttps_UnitTest.xml"
    for path in sorted(reports.glob(pattern)):
        source = ET.parse(path).getroot()
        counts = {key: int(source.attrib.get(key, "0")) for key in ("tests", "failures", "errors", "skipped")}
        if any(count < 0 for count in counts.values()):
            raise ValueError("invalid JUnit outcome count")
        destination = ET.Element("testsuite", name=identifier(source.attrib["name"]),
                                 **{key: str(value) for key, value in counts.items()})
        for case in source.findall("testcase"):
            clean = ET.SubElement(destination, "testcase", name=identifier(case.attrib["name"]),
                                  classname=identifier(case.attrib["classname"]))
            for outcome in ("failure", "error", "skipped"):
                if case.find(outcome) is not None:
                    ET.SubElement(clean, outcome)
        ET.ElementTree(destination).write(output / "endpoint-validation.junit.xml", encoding="utf-8", xml_declaration=True)
        suites.append({"name": destination.attrib["name"], **counts})
    (output / "junit.json").write_text(json.dumps({"suites": suites}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archives", type=Path)
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-ref", default=os.environ.get("COAUTH_CONFORMANCE_REF"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.archives is not None:
        if args.source_ref is None:
            parser.error("archive evidence requires the exact suite source ref")
        export_modules(args.archives, args.output, args.source_ref)
    export_junit(args.junit, args.output)


if __name__ == "__main__":
    main()
