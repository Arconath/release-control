#!/usr/bin/env python3
"""Fail closed when an SPDX SBOM does not provide usable license evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(f"license policy: {message}")


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot load SBOM {path}: {exc}")
    if not isinstance(value, dict):
        fail("SBOM must be a JSON object")
    return value


def license_values(package: dict[str, Any], context: str) -> list[str]:
    values: list[str] = []
    for field in ("licenseConcluded", "licenseDeclared"):
        value = package.get(field)
        if value is not None:
            if not isinstance(value, str):
                fail(f"{context}.{field} must be a string")
            values.append(value)
    from_files = package.get("licenseInfoFromFiles", [])
    if not isinstance(from_files, list) or any(not isinstance(value, str) for value in from_files):
        fail(f"{context}.licenseInfoFromFiles must be an array of strings")
    values.extend(from_files)
    usable = sorted(
        {
            value.strip()
            for value in values
            if value.strip() and value.strip() not in {"NOASSERTION", "NONE"}
        }
    )
    return usable


def build_report(sbom: dict[str, Any]) -> dict[str, Any]:
    spdx_version = sbom.get("spdxVersion")
    if not isinstance(spdx_version, str) or not spdx_version.startswith("SPDX-"):
        fail("spdxVersion is missing or is not an SPDX document")
    packages = sbom.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("SBOM must contain at least one package")
    report_packages: list[dict[str, Any]] = []
    missing: list[str] = []
    for index, package in enumerate(packages):
        context = f"packages[{index}]"
        if not isinstance(package, dict):
            fail(f"{context} must be an object")
        name = package.get("name")
        if not isinstance(name, str) or not name.strip() or "\n" in name or "\r" in name:
            fail(f"{context}.name must be a non-empty single-line string")
        licenses = license_values(package, context)
        report_packages.append({"name": name, "licenses": licenses})
        if not licenses:
            missing.append(name)
    if missing:
        fail("packages without an asserted license: " + ", ".join(sorted(set(missing))))
    return {
        "schema_version": 1,
        "spdx_version": spdx_version,
        "package_count": len(report_packages),
        "packages": report_packages,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(load(args.sbom))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(f"license policy: PASS ({report['package_count']} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
