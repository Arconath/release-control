#!/usr/bin/env python3
"""Validate a candidate tree as inert data using only trusted-base code."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType


def _load_trusted_release_control(trusted_root: Path) -> ModuleType:
    if trusted_root.is_symlink() or not trusted_root.is_dir():
        raise ValueError("trusted validator root must be a regular directory")
    trusted_root = trusted_root.resolve()
    this_file = Path(__file__)
    if this_file.is_symlink() or this_file.resolve() != trusted_root / "scripts" / "verify_candidate.py":
        raise ValueError("trusted validator must execute from the trusted checkout")
    module_path = trusted_root / "scripts" / "release_control.py"
    if module_path.is_symlink() or not module_path.is_file():
        raise ValueError("trusted release-control validator is missing")
    spec = importlib.util.spec_from_file_location(
        "trusted_release_control", module_path
    )
    if spec is None or spec.loader is None:
        raise ValueError("trusted release-control validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    return environment


def _require_git_sha(expected: str, context: str) -> str:
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise ValueError(f"invalid {context} expected SHA")
    return expected


def _git_revision(root: Path, expected: str, context: str) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{context} must be a regular directory")
    expected_sha = _require_git_sha(expected, context)
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        raise ValueError(f"{context} Git revision could not be verified") from None
    if result.returncode:
        raise ValueError(f"{context} Git revision could not be verified")
    try:
        actual_sha = result.stdout.decode("ascii").strip()
    except (AttributeError, UnicodeError):
        raise ValueError(f"{context} Git revision is not valid ASCII") from None
    if actual_sha != expected_sha:
        raise ValueError(f"{context} Git revision differs from the expected SHA")
    return actual_sha


def _validate_candidate_validation_workflow(
    release_control: ModuleType, candidate_root: Path
) -> dict[str, int]:
    """Require the candidate to preserve the trusted-base validation split."""

    path = candidate_root / ".github" / "workflows" / "validate.yml"
    if path.is_symlink() or not path.is_file():
        release_control.die(
            "candidate validation workflow must be a regular non-symlink file"
        )
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        release_control.die(f"cannot read candidate validation workflow: {exc}")

    required_fragments = (
        "pull_request_target:",
        "github.event.pull_request.base.sha",
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.repo.full_name == 'Arconath/release-control'",
        "path: trusted",
        "path: candidate",
        "EXPECTED_TRUSTED_SHA",
        "EXPECTED_CANDIDATE_SHA",
        "python3 trusted/scripts/verify_candidate.py",
        "--trusted-root trusted",
        "--candidate-root candidate",
        '--trusted-sha "$EXPECTED_TRUSTED_SHA"',
        '--candidate-sha "$EXPECTED_CANDIDATE_SHA"',
    )
    missing = [fragment for fragment in required_fragments if fragment not in text]
    if missing:
        release_control.die(
            "candidate validation workflow is missing trusted split markers: "
            + ", ".join(missing)
        )
    if re.search(r"(?m)^\s+pull_request:\s*(?:#.*)?$", text):
        release_control.die(
            "candidate validation workflow must not execute from pull_request"
        )
    forbidden_fragments = (
        "./scripts/verify.sh",
        "candidate/scripts/verify.sh",
        "python3 candidate/",
        "bash candidate/",
        "sh candidate/",
        "node candidate/",
        "go run candidate/",
    )
    present = [fragment for fragment in forbidden_fragments if fragment in text]
    if present:
        release_control.die(
            "candidate validation workflow contains candidate execution paths: "
            + ", ".join(present)
        )
    return {"required_markers": len(required_fragments)}


def validate_candidate(
    release_control: ModuleType,
    trusted_root: Path,
    candidate_root: Path,
    trusted_sha: str,
    candidate_sha: str,
) -> dict[str, object]:
    trusted_revision = _git_revision(
        trusted_root, trusted_sha, "trusted validator checkout"
    )
    candidate_revision = _git_revision(candidate_root, candidate_sha, "candidate checkout")
    if trusted_root.resolve() == candidate_root.resolve():
        release_control.die("trusted and candidate checkouts must be separate")

    # This snapshot is an integrity/symlink check only.  It never imports or
    # executes anything from the candidate tree.
    release_control.source_tree_snapshot(candidate_root)
    validation_workflow = _validate_candidate_validation_workflow(
        release_control, candidate_root
    )
    contract_details = release_control.validate_contract_inventory(
        candidate_root / "contracts"
    )
    policy_details = release_control.validate_policy_set(
        candidate_root / "policies" / "products"
    )
    workflow_details = release_control.validate_workflow_policy(
        candidate_root / ".github" / "workflows"
    )
    readiness = release_control.merge_readiness(
        candidate_root / ".github" / "CODEOWNERS",
        candidate_root / "policies" / "release-signers",
        candidate_root / "bootstrap" / "repository-settings.json",
        candidate_root / "policies" / "products",
        candidate_root / "contracts",
        candidate_root / ".github" / "workflows",
    )
    if not readiness["merge_ready"]:
        release_control.die(
            "trusted candidate validation is blocked: "
            + ",".join(readiness["blocking_reasons"])
        )
    return {
        "status": "ready",
        "trusted_sha": trusted_revision,
        "candidate_sha": candidate_revision,
        "contracts": contract_details,
        "policies": policy_details,
        "workflows": workflow_details,
        "validation_workflow": validation_workflow,
        "readiness": {
            "checked_in_contract_ready": readiness["checked_in_contract_ready"],
            "merge_ready": readiness["merge_ready"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a candidate checkout using trusted-base code only"
    )
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--trusted-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    args = parser.parse_args()
    try:
        # Verify both checkout identities before importing any checkout code.
        # The trusted module is loaded only after the base SHA is known to be
        # the exact value supplied by the trusted workflow.
        _git_revision(args.trusted_root, args.trusted_sha, "trusted validator checkout")
        _git_revision(args.candidate_root, args.candidate_sha, "candidate checkout")
        release_control = _load_trusted_release_control(args.trusted_root)
        result = validate_candidate(
            release_control,
            args.trusted_root,
            args.candidate_root,
            args.trusted_sha,
            args.candidate_sha,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except ValueError as exc:
        print(f"trusted candidate validator: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"trusted candidate validator: operating-system error: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
