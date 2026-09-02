#!/usr/bin/env python3
"""Fail closed when an SPDX SBOM does not provide exact declared licenses."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn


def fail(message: str) -> NoReturn:
    raise SystemExit(f"license policy: {message}")


def load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"SBOM must be a regular non-symlink file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot load SBOM {path}: {exc}")
    if not isinstance(value, dict):
        fail("SBOM must be a JSON object")
    return value


UNASSERTED_LICENSES = {"NOASSERTION", "NONE"}


def declared_license(package: dict[str, Any], context: str) -> str:
    value = package.get("licenseDeclared")
    if not isinstance(value, str):
        fail(f"{context}.licenseDeclared must be a string")
    if not value or value.strip() != value or value in UNASSERTED_LICENSES:
        fail(f"{context}.licenseDeclared must be an asserted SPDX value")
    if "\n" in value or "\r" in value:
        fail(f"{context}.licenseDeclared must be a single-line string")
    return value


def build_report(sbom: dict[str, Any]) -> dict[str, Any]:
    spdx_version = sbom.get("spdxVersion")
    if not isinstance(spdx_version, str) or not re.fullmatch(
        r"SPDX-[0-9]+\.[0-9]+", spdx_version
    ):
        fail("spdxVersion is missing or is not an SPDX document")
    packages = sbom.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("SBOM must contain at least one package")
    report_packages: list[dict[str, Any]] = []
    for index, package in enumerate(packages):
        context = f"packages[{index}]"
        if not isinstance(package, dict):
            fail(f"{context} must be an object")
        name = package.get("name")
        if not isinstance(name, str) or not name.strip() or "\n" in name or "\r" in name:
            fail(f"{context}.name must be a non-empty single-line string")
        # Preserve the SBOM's declared-license value exactly. Other SPDX
        # fields describe different facts and must not be merged into it.
        report_packages.append({"name": name, "licenses": [declared_license(package, context)]})
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
    if args.output.is_symlink() or (args.output.exists() and not args.output.is_file()):
        fail(f"output must be a regular non-symlink file: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(
        (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    print(f"license policy: PASS ({report['package_count']} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
