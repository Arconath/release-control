#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-license-policy.py"


class LicensePolicyTests(unittest.TestCase):
    def run_check(self, value: dict) -> tuple[subprocess.CompletedProcess[str], dict | None]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sbom = root / "sbom.json"
            output = root / "licenses.json"
            sbom.write_text(json.dumps(value), encoding="utf-8")
            result = subprocess.run(
                ["python3", str(SCRIPT), "--sbom", str(sbom), "--output", str(output)],
                capture_output=True,
                text=True,
                check=False,
            )
            report = json.loads(output.read_text(encoding="utf-8")) if result.returncode == 0 else None
            return result, report

    def test_report_binds_each_package_to_exact_declared_license(self) -> None:
        result, report = self.run_check(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "example",
                        "licenseConcluded": "MIT",
                        "licenseDeclared": "Apache-2.0",
                        "licenseInfoFromFiles": ["GPL-3.0-only"],
                    },
                    {"name": "dependency", "licenseDeclared": "BSD-2-Clause"},
                ],
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        assert report is not None
        self.assertEqual(
            report["packages"],
            [
                {"name": "example", "licenses": ["Apache-2.0"]},
                {"name": "dependency", "licenses": ["BSD-2-Clause"]},
            ],
        )

    def test_missing_or_unasserted_declared_license_fails_closed(self) -> None:
        for package in (
            {"name": "missing"},
            {"name": "unknown", "licenseDeclared": "NOASSERTION"},
            {"name": "none", "licenseDeclared": "NONE"},
        ):
            with self.subTest(package=package):
                result, _ = self.run_check({"spdxVersion": "SPDX-2.3", "packages": [package]})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("licenseDeclared", result.stderr)

    def test_empty_sbom_fails_closed(self) -> None:
        result, _ = self.run_check({"spdxVersion": "SPDX-2.3", "packages": []})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("at least one package", result.stderr)

    def test_noncanonical_spdx_version_fails_closed(self) -> None:
        result, _ = self.run_check(
            {
                "spdxVersion": "SPDX-2.3-preview",
                "packages": [
                    {
                        "name": "example",
                        "licenseDeclared": "Apache-2.0",
                    }
                ],
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("spdxVersion", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
