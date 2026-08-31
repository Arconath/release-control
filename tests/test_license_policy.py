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
    def run_check(self, value: dict) -> subprocess.CompletedProcess[str]:
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
            if result.returncode == 0:
                self.assertTrue(output.is_file())
                self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["package_count"], 1)
            return result

    def test_license_report_is_generated_for_asserted_spdx_license(self) -> None:
        result = self.run_check(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "example",
                        "licenseConcluded": "Apache-2.0",
                        "licenseDeclared": "Apache-2.0",
                    }
                ],
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_noassertion_license_fails_closed(self) -> None:
        for package in (
            {"name": "missing"},
            {"name": "unknown", "licenseConcluded": "NOASSERTION", "licenseDeclared": "NONE"},
        ):
            with self.subTest(package=package):
                result = self.run_check({"spdxVersion": "SPDX-2.3", "packages": [package]})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("without an asserted license", result.stderr)

    def test_empty_sbom_fails_closed(self) -> None:
        result = self.run_check({"spdxVersion": "SPDX-2.3", "packages": []})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("at least one package", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
