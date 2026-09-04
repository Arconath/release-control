#!/usr/bin/env python3
"""Strict release identity and digest contracts for Arconath release-control."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import urlparse


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENT = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,127}$")
POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
INTENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
SOURCE_REPO = re.compile(r"^Arconath/[a-z0-9][a-z0-9-]{1,99}$")
REGISTRY_HOST = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?$"
)
ARTIFACT_REPO = re.compile(
    r"^(?=.{8,255}$)[a-z0-9.-]+(?::[1-9][0-9]{0,4})?(?:/[a-z0-9][a-z0-9._-]{0,127})+$"
)
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
NONZERO_SHA256 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
LEDGER = re.compile(r"^[a-z0-9][a-z0-9._/-]{2,127}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
ZERO_DIGEST = "sha256:" + "0" * 64
NAMESPACE = "arconath-release-intent"
MACHINE_EVIDENCE_NAMESPACE = "arconath-machine-evidence"
AUTOMATED_POLICY_ID = "arconath-automated-release"
AUTOMATED_CONTROL_REPOSITORY = "Arconath/.github"
AUTOMATED_CONTROL_WORKFLOW = ".github/workflows/release-control.yml"
AUTOMATED_CONTROL_REF = "refs/heads/main"
AUTOMATED_RUNNER_GROUP = "arconath-jit"
AUTOMATED_SIGNER_IDENTITY = "arconath-release-bot"
AUTOMATED_BACKUP_MODE = "local-only-no-off-host-dr"
AUTOMATED_ALLOWED_ROUTES = [
    "releasepassport.com",
    "foundiqo.com",
    "loklyo.com",
    "boringkit.com",
    "abra.arconath.com",
    "aeliqo.com",
    "spatial.arconath.com",
    "labs.arconath.com",
    "peoplepassport.arconath.com",
    "agentdeck.arconath.com",
    "syviora.com",
]
AUTOMATED_RUNNER_LABELS = [
    "self-hosted",
    "linux",
    "x64",
    "arconath-jit",
    "rootless-buildkit",
]
AUTOMATED_REQUIRED_CHECKS = [
    "contracts and workflow policy",
    "release-control machine attestation",
]
AUTOMATED_REQUIRED_EVIDENCE = [
    "provenance",
    "sbom",
    "artifact_signature",
    "machine_attestation_signature",
    "canary",
    "rollback",
    "backup_guard",
    "production_domain_guard",
]


class ContractError(ValueError):
    """A fail-closed contract validation error."""


def die(message: str) -> None:
    raise ContractError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def load_json_bytes(data: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeError, ValueError) as exc:
        die(f"cannot load JSON {context}: {exc}")
    if not isinstance(value, dict):
        die(f"JSON document must be an object: {context}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        die(f"cannot load JSON {path}: {exc}")
    return load_json_bytes(data, str(path))


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def require_canonical(path: Path, value: Any) -> None:
    if path.read_bytes() != canonical_bytes(value):
        die(f"document is not canonical JSON: {path}")


def strict_keys(value: dict[str, Any], required: set[str], context: str) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    unknown = sorted(actual - required)
    if missing:
        die(f"{context} missing fields: {', '.join(missing)}")
    if unknown:
        die(f"{context} unknown fields: {', '.join(unknown)}")


def require_string(value: Any, pattern: re.Pattern[str], context: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        die(f"invalid {context}: {value!r}")
    return value


def validate_registry_host(value: Any, context: str = "registry_host") -> str:
    host = require_string(value, REGISTRY_HOST, context)
    if ":" in host and int(host.rsplit(":", 1)[1]) > 65535:
        die(f"invalid {context} port")
    if host != "ghcr.io":
        die(f"{context} must be canonical GHCR")
    return host


def validate_artifact_repository(value: Any, context: str) -> str:
    repository = require_string(value, ARTIFACT_REPO, context)
    host, *segments = repository.split("/")
    validate_registry_host(host, f"{context} registry host")
    if not segments or any(segment in {".", ".."} for segment in segments):
        die(f"invalid {context} path")
    if not repository.startswith("ghcr.io/arconath/"):
        die(f"{context} must use the canonical GHCR organization")
    return repository


def relative_path(value: Any, context: str, allow_dot: bool = False) -> str:
    if not isinstance(value, str) or not value:
        die(f"invalid {context}: {value!r}")
    if allow_dot and value == ".":
        return value
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        die(f"{context} must be a normalized relative path: {value!r}")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
        die(f"{context} contains unsupported characters: {value!r}")
    return value


def parse_time(value: Any, context: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        die(f"{context} must be UTC RFC3339 with Z suffix")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        die(f"invalid {context}: {exc}")
    if parsed.microsecond:
        die(f"{context} must not contain fractional seconds")
    return parsed


def validate_policy(value: dict[str, Any], *, require_enabled: bool = True) -> dict[str, Any]:
    required = {
        "schema_version",
        "policy_id",
        "enabled",
        "source_repository",
        "registry_host",
        "artifact_repository",
        "max_intent_age_seconds",
        "build",
        "verification_commands",
    }
    strict_keys(value, required, "policy")
    if value["schema_version"] != 1:
        die("unsupported policy schema_version")
    require_string(value["policy_id"], POLICY_ID, "policy_id")
    if not isinstance(value["enabled"], bool):
        die("policy enabled must be boolean")
    if require_enabled and not value["enabled"]:
        die("policy is disabled")
    require_string(value["source_repository"], SOURCE_REPO, "source_repository")
    registry_host = validate_registry_host(value["registry_host"])
    validate_artifact_repository(value["artifact_repository"], "artifact_repository")
    if not value["artifact_repository"].startswith(f"{registry_host}/"):
        die("artifact_repository must be hosted by registry_host")
    age = value["max_intent_age_seconds"]
    if isinstance(age, bool) or not isinstance(age, int) or not 300 <= age <= 604800:
        die("max_intent_age_seconds must be between 300 and 604800")
    build = value["build"]
    if not isinstance(build, dict):
        die("build must be an object")
    strict_keys(build, {"context", "dockerfile", "platform"}, "build")
    relative_path(build["context"], "build.context", allow_dot=True)
    relative_path(build["dockerfile"], "build.dockerfile")
    if build["platform"] not in {"linux/amd64", "linux/arm64"}:
        die("unsupported build.platform")
    commands = value["verification_commands"]
    if not isinstance(commands, list) or not commands:
        die("verification_commands must be a non-empty array")
    for index, command in enumerate(commands):
        if not isinstance(command, list) or not command:
            die(f"verification_commands[{index}] must be a non-empty argv array")
        if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in command):
            die(f"verification_commands[{index}] contains an invalid argument")
    return value


def _require_sha256(value: Any, context: str, *, nonzero: bool = True) -> str:
    pattern = NONZERO_SHA256 if nonzero else SHA256
    return require_string(value, pattern, context)


def _require_digest(value: Any, context: str, *, nonzero: bool = True) -> str:
    digest = require_string(value, DIGEST, context)
    if nonzero and digest == ZERO_DIGEST:
        die(f"{context} must not be the zero digest")
    return digest


def _is_finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and (not isinstance(value, float) or math.isfinite(value))
    )


def _safe_evidence_path(root: Path, value: Any, context: str) -> Path:
    relative = relative_path(value, context)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        die(f"evidence root cannot be inspected: {exc}")
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        die("evidence root must be a regular directory")
    current = root
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            die(f"{context} cannot be inspected: {exc}")
        if stat.S_ISLNK(metadata.st_mode):
            die(f"{context} must not use symlinks")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            die(f"{context} parent must be a directory")
    if not stat.S_ISREG(metadata.st_mode):
        die(f"{context} must be a regular file")
    return current


def _read_evidence_file(root: Path, value: Any, context: str) -> tuple[Path, bytes]:
    path = _safe_evidence_path(root, value, context)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            return path, stream.read()
    except OSError as exc:
        die(f"{context} cannot be read: {exc}")
    raise AssertionError("unreachable")


def verify_machine_evidence_signature(
    payload: bytes, signature: Path, allowed_signers: Path, identity: str
) -> None:
    try:
        allowed_stat = allowed_signers.lstat()
        signature_stat = signature.lstat()
    except OSError as exc:
        die(f"machine evidence signature input cannot be inspected: {exc}")
    if (
        stat.S_ISLNK(allowed_stat.st_mode)
        or not stat.S_ISREG(allowed_stat.st_mode)
        or stat.S_ISLNK(signature_stat.st_mode)
        or not stat.S_ISREG(signature_stat.st_mode)
    ):
        die("machine evidence signature inputs must be regular files")
    command = [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        str(allowed_signers),
        "-I",
        identity,
        "-n",
        MACHINE_EVIDENCE_NAMESPACE,
        "-s",
        str(signature),
    ]
    try:
        result = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        die("ssh-keygen is required to verify machine evidence signatures")
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        die(f"machine evidence signature verification failed: {detail}")


def git_checkout_identity(root: Path, expected_sha: str, expected_tree: str, context: str) -> tuple[str, str]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        die(f"{context} cannot be inspected: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        die(f"{context} must be a regular directory")
    require_string(expected_sha, SHA, f"{context} expected commit")
    require_string(expected_tree, SHA, f"{context} expected tree")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    values = []
    for revision in ("HEAD^{commit}", "HEAD^{tree}"):
        try:
            result = subprocess.run(
                [
                    "git",
                    "--no-optional-locks",
                    "-C",
                    str(root),
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "rev-parse",
                    "--verify",
                    revision,
                ],
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=30,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            die(f"{context} Git identity could not be verified")
        if result.returncode:
            die(f"{context} Git identity could not be verified")
        try:
            values.append(result.stdout.decode("ascii").strip())
        except UnicodeError:
            die(f"{context} Git identity is not valid ASCII")
    if values != [expected_sha, expected_tree]:
        die(f"{context} commit or tree differs from the attestation")
    return values[0], values[1]


def git_checkout_repository(root: Path, expected_repository: str, context: str) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        result = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-C",
                str(root),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "remote",
                "get-url",
                "origin",
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        die(f"{context} repository identity could not be verified")
    if result.returncode:
        die(f"{context} repository has no origin remote")
    try:
        remote = result.stdout.decode("ascii").strip()
    except UnicodeError:
        die(f"{context} repository remote is not valid ASCII")
    if remote.startswith("git@github.com:"):
        repository = remote.split(":", 1)[1]
    else:
        parsed = urlparse(remote)
        if parsed.hostname != "github.com" or not parsed.path:
            die(f"{context} repository remote is not the canonical GitHub host")
        repository = parsed.path.lstrip("/")
    if repository.endswith(".git"):
        repository = repository[:-4]
    if repository != expected_repository:
        die(f"{context} origin repository does not match the attestation")


def verify_registry_digest(repository: str, digest: str, authfile: Path) -> None:
    repository = validate_artifact_repository(repository, "registry repository")
    digest = _require_digest(digest, "registry digest")
    try:
        metadata = authfile.lstat()
    except OSError as exc:
        die(f"registry auth file cannot be inspected: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        die("registry auth file must be a regular file")
    try:
        result = subprocess.run(
            [
                "skopeo",
                "inspect",
                "--authfile",
                str(authfile),
                "--format",
                "{{.Digest}}",
                f"docker://{repository}@{digest}",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        die("skopeo is required to verify the published artifact digest")
    if result.returncode:
        die("registry digest lookup failed")
    try:
        actual = result.stdout.decode("ascii").strip()
    except UnicodeError:
        die("registry digest lookup returned non-ASCII output")
    if not DIGEST.fullmatch(actual) or actual != digest:
        die("registry digest does not match the machine attestation")


def machine_attestation_audit_digest(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "audit"}
    payload["evidence"] = {
        name: item
        for name, item in payload["evidence"].items()
        if name != "machine_attestation_signature"
    }
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _machine_attestation_binding(value: dict[str, Any]) -> dict[str, Any]:
    payload = {key: item for key, item in value.items() if key != "evidence"}
    payload["evidence"] = {
        name: item
        for name, item in value["evidence"].items()
        if name != "machine_attestation_signature"
    }
    return payload


def _expected_signed_evidence_payload(
    name: str, value: dict[str, Any], artifact_digest: str
) -> dict[str, Any] | None:
    target = value["target"]
    canary = value["canary"]
    rollback = value["rollback"]
    if name == "machine_attestation_signature":
        return _machine_attestation_binding(value)
    if name in {"provenance", "sbom", "artifact_signature"}:
        payload = {
            "artifact_digest": artifact_digest,
            "kind": f"{name}-binding",
            "policy_id": value["policy_id"],
            "release_control": {
                "repository": value["release_control"]["repository"],
                "commit_sha": value["release_control"]["commit_sha"],
                "tree_sha": value["release_control"]["tree_sha"],
            },
            "source": {
                "repository": value["source"]["repository"],
                "commit_sha": value["source"]["commit_sha"],
                "tree_sha": value["source"]["tree_sha"],
            },
        }
        if name == "artifact_signature":
            payload["verification"] = {
                "identity": "https://github.com/Arconath/.github/.github/workflows/release-control.yml@refs/heads/main",
                "issuer": "https://token.actions.githubusercontent.com",
                "method": "sigstore-cosign-keyless",
            }
        return payload
    if name == "canary":
        health = {key: item for key, item in canary["health"].items() if key != "evidence_sha256"}
        return {
            "abort_thresholds": canary["abort_thresholds"],
            "artifact_digest": artifact_digest,
            "environment": target["environment"],
            "health": health,
            "kind": "canary-observation",
            "observability": canary["observability"],
            "observed": canary["observed"],
            "policy_id": value["policy_id"],
        }
    if name == "rollback":
        return {
            "artifact_digest": artifact_digest,
            "automatic": rollback["automatic"],
            "kind": "rollback-test",
            "policy_id": value["policy_id"],
            "restore_digest": rollback["restore_digest"],
            "strategy": rollback["strategy"],
            "tested": rollback["tested"],
        }
    if name == "backup_guard":
        return {
            "artifact_digest": artifact_digest,
            "external_backup": False,
            "kind": "backup-guard",
            "mode": target["backup_mode"],
            "policy_id": value["policy_id"],
        }
    if name == "production_domain_guard":
        return {
            "allowlisted": True,
            "artifact_digest": artifact_digest,
            "kind": "production-domain-guard",
            "policy_id": value["policy_id"],
            "routes": target["routes"],
        }
    return None


def verify_machine_attestation_evidence(
    value: dict[str, Any], evidence_root: Path, allowed_machine_signers: Path
) -> None:
    evidence = value["evidence"]
    artifact_digest = value["artifact"]["digest"]
    seen_payloads: dict[str, bytes] = {}
    for name in AUTOMATED_REQUIRED_EVIDENCE:
        item = evidence[name]
        _, payload = _read_evidence_file(
            evidence_root, item["path"], f"machine attestation evidence {name}.path"
        )
        signature_path, _ = _read_evidence_file(
            evidence_root,
            item["signature_path"],
            f"machine attestation evidence {name}.signature_path",
        )
        actual_sha256 = hashlib.sha256(payload).hexdigest()
        if actual_sha256 != item["sha256"]:
            die(f"machine attestation evidence {name} bytes do not match sha256")
        verify_machine_evidence_signature(
            payload,
            signature_path,
            allowed_machine_signers,
            item["signer_identity"],
        )
        expected_payload = _expected_signed_evidence_payload(name, value, artifact_digest)
        if expected_payload is not None:
            parsed = load_json_bytes(payload, f"machine attestation evidence {name} payload")
            if canonical_bytes(parsed) != canonical_bytes(expected_payload):
                die(f"machine attestation evidence {name} payload is not bound to the release")
        seen_payloads[name] = payload



def validate_automated_release_policy(value: dict[str, Any]) -> dict[str, Any]:
    """Validate the permanent machine-only release policy.

    The policy is deliberately separate from product image policies.  It is
    consumed by the private ``Arconath/.github`` control plane, while this
    public repository remains a read-only contract and evidence surface.
    """

    strict_keys(
        value,
        {
            "schema_version",
            "policy_id",
            "authorization_mode",
            "human_signers_required",
            "human_reviewers_required",
            "manual_override",
            "control_plane",
            "allowed_routes",
            "required_checks",
            "required_evidence",
            "rollout",
        },
        "automated release policy",
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        die("unsupported automated release policy schema_version")
    if value["policy_id"] != AUTOMATED_POLICY_ID:
        die("automated release policy_id is not canonical")
    if value["authorization_mode"] != "machine-only":
        die("automated release policy must use machine-only authorization")
    if value["human_signers_required"] is not False:
        die("automated release policy must not require human signers")
    if value["human_reviewers_required"] is not False:
        die("automated release policy must not require human reviewers")
    if value["manual_override"] is not False:
        die("automated release policy must disable manual override")

    control_plane = value["control_plane"]
    if not isinstance(control_plane, dict):
        die("automated release control_plane must be an object")
    strict_keys(
        control_plane,
        {
            "repository",
            "workflow_path",
            "ref",
            "runner_group",
            "runner_labels",
            "machine_signer_identity",
            "public_control_repository",
            "public_runner_allowed",
        },
        "automated release control_plane",
    )
    if control_plane["repository"] != AUTOMATED_CONTROL_REPOSITORY:
        die("automated release control plane must be Arconath/.github")
    if control_plane["workflow_path"] != AUTOMATED_CONTROL_WORKFLOW:
        die("automated release workflow path is not canonical")
    if control_plane["ref"] != AUTOMATED_CONTROL_REF:
        die("automated release workflow must use protected main")
    if control_plane["runner_group"] != AUTOMATED_RUNNER_GROUP:
        die("automated release runner group is not canonical")
    if control_plane["runner_labels"] != AUTOMATED_RUNNER_LABELS:
        die("automated release runner labels are not canonical")
    if control_plane["machine_signer_identity"] != AUTOMATED_SIGNER_IDENTITY:
        die("automated release machine signer identity is not canonical")
    if control_plane["public_control_repository"] != "Arconath/release-control":
        die("public release-control repository binding is not canonical")
    if control_plane["public_runner_allowed"] is not False:
        die("public release-control must not use the private runner group")
    if value["allowed_routes"] != AUTOMATED_ALLOWED_ROUTES:
        die("automated release routes are not the canonical product route allowlist")

    required_checks = value["required_checks"]
    if (
        not isinstance(required_checks, list)
        or not required_checks
        or any(not isinstance(item, str) or not item.strip() for item in required_checks)
        or len(required_checks) != len(set(required_checks))
    ):
        die("automated release required_checks must be a unique non-empty list")
    if required_checks != AUTOMATED_REQUIRED_CHECKS:
        die("automated release required_checks are not canonical")

    required_evidence = value["required_evidence"]
    if not isinstance(required_evidence, dict):
        die("automated release required_evidence must be an object")
    strict_keys(
        required_evidence,
        set(AUTOMATED_REQUIRED_EVIDENCE),
        "automated release required_evidence",
    )
    if any(required_evidence.get(name) is not True for name in required_evidence):
        die("automated release evidence requirements cannot be disabled")

    rollout = value["rollout"]
    if not isinstance(rollout, dict):
        die("automated release rollout must be an object")
    strict_keys(
        rollout,
        {
            "environments",
            "canary_required",
            "automatic_rollback_required",
            "external_backup_guard",
            "production_domain_guard",
            "backup_mode",
            "canary_abort_thresholds",
            "max_promotions_per_attestation",
            "cooldown_seconds",
            "max_attestation_age_seconds",
        },
        "automated release rollout",
    )
    if rollout["environments"] != ["production"]:
        die("automated release environments are not canonical")
    for name in (
        "canary_required",
        "automatic_rollback_required",
        "external_backup_guard",
        "production_domain_guard",
    ):
        if rollout[name] is not True:
            die(f"automated release rollout must require {name}")
    if rollout["backup_mode"] != AUTOMATED_BACKUP_MODE:
        die("automated release backup mode must make no off-host DR claim")
    thresholds = rollout["canary_abort_thresholds"]
    if not isinstance(thresholds, dict):
        die("automated release canary_abort_thresholds must be an object")
    strict_keys(
        thresholds,
        {"error_rate_percent_max", "p95_latency_ms_max", "restart_count_max"},
        "automated release canary_abort_thresholds",
    )
    if thresholds != {
        "error_rate_percent_max": 5.0,
        "p95_latency_ms_max": 2000,
        "restart_count_max": 3,
    }:
        die("automated release canary abort thresholds are not canonical")
    if (
        type(rollout["max_promotions_per_attestation"]) is not int
        or rollout["max_promotions_per_attestation"] != 1
    ):
        die("automated release attestations must allow exactly one promotion")
    cooldown = rollout["cooldown_seconds"]
    if isinstance(cooldown, bool) or not isinstance(cooldown, int) or not 60 <= cooldown <= 3600:
        die("automated release cooldown_seconds must be between 60 and 3600")
    max_age = rollout["max_attestation_age_seconds"]
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 60 <= max_age <= 900:
        die("automated release max_attestation_age_seconds must be between 60 and 900")
    return value


def validate_automated_release_settings(value: dict[str, Any]) -> dict[str, Any]:
    """Validate the checked-in ruleset contract for machine-only releases."""

    governance = value.get("release_governance")
    if not isinstance(governance, dict):
        die("repository settings are missing release_governance")
    strict_keys(
        governance,
        {
            "authorization_mode",
            "human_reviewers_required",
            "human_signers_required",
            "manual_override",
            "policy_id",
            "required_checks",
        },
        "release_governance",
    )
    if governance != {
        "authorization_mode": "machine-only",
        "human_reviewers_required": False,
        "human_signers_required": False,
        "manual_override": False,
        "policy_id": AUTOMATED_POLICY_ID,
        "required_checks": AUTOMATED_REQUIRED_CHECKS,
    }:
        die("repository release_governance is not the canonical machine-only contract")

    protection = value.get("main_protection")
    if not isinstance(protection, dict):
        die("repository settings are missing main_protection")
    expected_protection = {
        "allow_deletions": False,
        "allow_force_pushes": False,
        "dismiss_stale_reviews": True,
        "enforce_admins": True,
        "linear_history": True,
        "required_approvals": 0,
        "required_checks": ["contracts and workflow policy"],
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "require_signed_commits": True,
        "strict_checks": True,
    }
    if protection != expected_protection:
        die("main source governance protections are not canonical")

    environments = value.get("environments")
    if not isinstance(environments, dict) or set(environments) != {"publication", "promotion"}:
        die("repository settings must declare publication and promotion environments")
    for name, environment in environments.items():
        if not isinstance(environment, dict):
            die(f"{name} environment must be an object")
        if environment.get("protected_branches_only") is not True:
            die(f"{name} environment must remain restricted to protected branches")
        if environment.get("required_reviewers") != 0:
            die(f"{name} environment must not require human reviewers")
        if environment.get("can_admins_bypass") is not False:
            die(f"{name} environment must disable administrator bypass")
        expected_secrets = (
            ["ARCONATH_REGISTRY_USERNAME", "ARCONATH_REGISTRY_PASSWORD"]
            if name == "publication"
            else []
        )
        if environment.get("required_secrets") != expected_secrets:
            die(f"{name} environment credential compartment is not canonical")
    return value


def validate_machine_release_attestation(
    value: dict[str, Any],
    policy: dict[str, Any],
    *,
    now: dt.datetime,
    evidence_root: Path | None = None,
    allowed_machine_signers: Path | None = None,
) -> dict[str, Any]:
    """Validate an attestation emitted by the private control-plane workflow."""

    validate_automated_release_policy(policy)
    strict_keys(
        value,
        {
            "schema_version",
            "policy_id",
            "attestation_id",
            "issued_at",
            "expires_at",
            "release_control",
            "source",
            "artifact",
            "target",
            "checks",
            "runner",
            "evidence",
            "canary",
            "rollback",
            "audit",
            "replay_protection",
            "authorization",
        },
        "machine release attestation",
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        die("unsupported machine release attestation schema_version")
    require_string(value["policy_id"], POLICY_ID, "machine attestation policy_id")
    if value["policy_id"] != policy["policy_id"]:
        die("machine attestation policy_id does not match policy")
    require_string(value["attestation_id"], INTENT_ID, "machine attestation_id")
    issued = parse_time(value["issued_at"], "machine attestation issued_at")
    expires = parse_time(value["expires_at"], "machine attestation expires_at")
    if expires <= issued:
        die("machine attestation expires_at must be after issued_at")
    if now < issued - dt.timedelta(minutes=5):
        die("machine attestation issued_at is in the future")
    if now >= expires:
        die("machine release attestation is expired")
    max_age = policy["rollout"]["max_attestation_age_seconds"]
    if (expires - issued).total_seconds() > max_age:
        die("machine attestation lifetime exceeds policy")

    release_control = value["release_control"]
    if not isinstance(release_control, dict):
        die("machine attestation release_control must be an object")
    strict_keys(
        release_control,
        {"repository", "commit_sha", "tree_sha", "workflow"},
        "machine attestation release_control",
    )
    if release_control["repository"] != "Arconath/release-control":
        die("machine attestation release-control repository is not canonical")
    release_control_sha = require_string(
        release_control["commit_sha"], SHA, "machine attestation release-control commit"
    )
    require_string(release_control["tree_sha"], SHA, "machine attestation release-control tree")
    workflow = release_control["workflow"]
    if not isinstance(workflow, dict):
        die("machine attestation control-plane workflow must be an object")
    strict_keys(
        workflow,
        {
            "repository",
            "path",
            "ref",
            "commit_sha",
            "tree_sha",
            "run_id",
            "runner_group",
            "public_runner_allowed",
        },
        "machine attestation control-plane workflow",
    )
    if workflow["repository"] != AUTOMATED_CONTROL_REPOSITORY:
        die("machine attestation workflow repository is not canonical")
    if workflow["path"] != AUTOMATED_CONTROL_WORKFLOW:
        die("machine attestation workflow path is not canonical")
    if workflow["ref"] != AUTOMATED_CONTROL_REF:
        die("machine attestation workflow ref is not canonical")
    require_string(workflow["commit_sha"], SHA, "machine attestation workflow commit")
    require_string(workflow["tree_sha"], SHA, "machine attestation workflow tree")
    require_string(workflow["run_id"], RUN_ID, "machine attestation workflow run_id")
    if workflow["runner_group"] != AUTOMATED_RUNNER_GROUP:
        die("machine attestation workflow runner group is not canonical")
    if workflow["public_runner_allowed"] is not False:
        die("machine attestation workflow cannot run public control code on private runner")

    source = value["source"]
    if not isinstance(source, dict):
        die("machine attestation source must be an object")
    strict_keys(source, {"repository", "commit_sha", "tree_sha"}, "machine attestation source")
    require_string(source["repository"], SOURCE_REPO, "machine attestation source.repository")
    require_string(source["commit_sha"], SHA, "machine attestation source.commit_sha")
    require_string(source["tree_sha"], SHA, "machine attestation source.tree_sha")

    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        die("machine attestation artifact must be an object")
    strict_keys(artifact, {"repository", "digest"}, "machine attestation artifact")
    artifact_repository = validate_artifact_repository(
        artifact["repository"], "machine attestation artifact.repository"
    )
    artifact_digest = _require_digest(
        artifact["digest"], "machine attestation artifact.digest"
    )
    if not artifact_repository.startswith("ghcr.io/arconath/"):
        die("machine attestation artifact must use the canonical registry namespace")

    target = value["target"]
    if not isinstance(target, dict):
        die("machine attestation target must be an object")
    strict_keys(
        target,
        {
            "environment",
            "routes",
            "external_backup_guard",
            "production_domain_guard",
            "backup_mode",
            "guard_evidence",
        },
        "machine attestation target",
    )
    if target["environment"] not in policy["rollout"]["environments"]:
        die("machine attestation target environment is not allowed")
    routes = target["routes"]
    if (
        not isinstance(routes, list)
        or not routes
        or len(routes) != len(set(routes))
        or any(
            not isinstance(route, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", route)
            for route in routes
        )
    ):
        die("machine attestation target routes must be unique canonical hostnames")
    if not set(routes).issubset(set(policy["allowed_routes"])):
        die("machine attestation target contains a route outside the canonical allowlist")
    if target["external_backup_guard"] is not True:
        die("machine attestation external backup guard is not satisfied")
    if target["production_domain_guard"] is not True:
        die("machine attestation production domain guard is not satisfied")
    if target["backup_mode"] != AUTOMATED_BACKUP_MODE:
        die("machine attestation backup mode must make no off-host DR claim")
    if target["guard_evidence"] != {
        "backup": "backup_guard",
        "production_domain": "production_domain_guard",
    }:
        die("machine attestation guard evidence references are not canonical")

    checks = value["checks"]
    if not isinstance(checks, dict):
        die("machine attestation checks must be an object")
    strict_keys(
        checks,
        {"required_contexts", "results", "all_completed", "no_skips", "queried_at"},
        "machine attestation checks",
    )
    required_checks = policy["required_checks"]
    if checks["required_contexts"] != required_checks:
        die("machine attestation required CI contexts do not match policy")
    if checks["all_completed"] is not True or checks["no_skips"] is not True:
        die("machine attestation CI checks must all be completed without skips")
    queried_at = parse_time(checks["queried_at"], "machine attestation checks.queried_at")
    if queried_at > now + dt.timedelta(minutes=5):
        die("machine attestation checks.queried_at is in the future")
    if issued - queried_at > dt.timedelta(seconds=max_age):
        die("machine attestation CI checks are older than the attestation policy window")
    results = checks["results"]
    if not isinstance(results, list) or len(results) != len(required_checks):
        die("machine attestation must contain one result for every required CI context")
    seen_contexts: set[str] = set()
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            die(f"machine attestation CI result {index} must be an object")
        strict_keys(
            result,
            {"context", "status", "conclusion", "head_sha", "run_id"},
            f"machine attestation CI result {index}",
        )
        context = result["context"]
        if context not in required_checks or context in seen_contexts:
            die("machine attestation CI contexts must be unique and policy-bound")
        seen_contexts.add(context)
        if result["status"] != "completed" or result["conclusion"] != "success":
            die(f"machine attestation CI context is not completed successfully: {context}")
        if result["head_sha"] != release_control_sha:
            die(f"machine attestation CI context head does not match release-control: {context}")
        if result["run_id"] != workflow["run_id"]:
            die(f"machine attestation CI context run does not match control-plane workflow: {context}")
    if seen_contexts != set(required_checks):
        die("machine attestation is missing a required CI context")

    runner = value["runner"]
    if not isinstance(runner, dict):
        die("machine attestation runner must be an object")
    strict_keys(runner, {"group", "labels", "ephemeral", "attestation_sha256"}, "machine attestation runner")
    if runner["group"] != AUTOMATED_RUNNER_GROUP or runner["labels"] != AUTOMATED_RUNNER_LABELS:
        die("machine attestation runner identity is not canonical")
    if runner["ephemeral"] is not True:
        die("machine attestation runner must be ephemeral")
    _require_sha256(runner["attestation_sha256"], "machine attestation runner attestation")

    evidence = value["evidence"]
    if not isinstance(evidence, dict):
        die("machine attestation evidence must be an object")
    evidence_names = set(AUTOMATED_REQUIRED_EVIDENCE)
    strict_keys(evidence, evidence_names, "machine attestation evidence")
    for name in evidence_names:
        item = evidence[name]
        if not isinstance(item, dict):
            die(f"machine attestation evidence {name} must be an object")
        strict_keys(
            item,
            {"path", "signature_path", "signer_identity", "sha256", "artifact_digest", "verified"},
            f"machine attestation evidence {name}",
        )
        relative_path(item["path"], f"machine attestation evidence {name}.path")
        relative_path(item["signature_path"], f"machine attestation evidence {name}.signature_path")
        if item["path"] == item["signature_path"]:
            die(f"machine attestation evidence {name} payload and signature paths must differ")
        if item["signer_identity"] != AUTOMATED_SIGNER_IDENTITY:
            die(f"machine attestation evidence {name} signer is not canonical")
        _require_sha256(item["sha256"], f"machine attestation evidence {name}.sha256")
        if item["artifact_digest"] != artifact_digest:
            die(f"machine attestation evidence {name} digest does not match artifact")
        if item["verified"] is not True:
            die(f"machine attestation evidence {name} is not verified")

    evidence_paths = [
        evidence[name][field]
        for name in evidence_names
        for field in ("path", "signature_path")
    ]
    if len(evidence_paths) != len(set(evidence_paths)):
        die("machine attestation evidence paths must be unique")

    canary = value["canary"]
    if not isinstance(canary, dict):
        die("machine attestation canary must be an object")
    strict_keys(canary, {"required", "health", "observability", "abort_thresholds", "observed"}, "machine attestation canary")
    if canary["required"] is not True:
        die("machine attestation canary is required")
    health = canary["health"]
    if not isinstance(health, dict):
        die("machine attestation canary health must be an object")
    strict_keys(health, {"status", "evidence_sha256"}, "machine attestation canary health")
    if health["status"] != "pass":
        die("machine attestation canary health did not pass")
    _require_sha256(health["evidence_sha256"], "machine attestation canary health evidence")
    observability = canary["observability"]
    if not isinstance(observability, dict):
        die("machine attestation canary observability must be an object")
    strict_keys(observability, {"metrics", "logs", "traces"}, "machine attestation canary observability")
    if any(observability[name] != "pass" for name in ("metrics", "logs", "traces")):
        die("machine attestation canary observability did not pass")
    thresholds = canary["abort_thresholds"]
    observed = canary["observed"]
    if not isinstance(thresholds, dict) or not isinstance(observed, dict):
        die("machine attestation canary thresholds and observations must be objects")
    strict_keys(
        thresholds,
        {"error_rate_percent_max", "p95_latency_ms_max", "restart_count_max"},
        "machine attestation canary abort_thresholds",
    )
    strict_keys(
        observed,
        {"error_rate_percent", "p95_latency_ms", "restart_count"},
        "machine attestation canary observed",
    )
    if canonical_bytes(thresholds) != canonical_bytes(policy["rollout"]["canary_abort_thresholds"]):
        die("machine attestation canary abort thresholds do not match policy")
    if (
        not _is_finite_number(thresholds["error_rate_percent_max"])
        or thresholds["error_rate_percent_max"] <= 0
        or thresholds["error_rate_percent_max"] > 100
        or not _is_finite_number(thresholds["p95_latency_ms_max"])
        or thresholds["p95_latency_ms_max"] <= 0
        or isinstance(thresholds["restart_count_max"], bool)
        or not isinstance(thresholds["restart_count_max"], int)
        or thresholds["restart_count_max"] < 0
    ):
        die("machine attestation canary abort thresholds are invalid")
    if (
        not _is_finite_number(observed["error_rate_percent"])
        or not 0 <= observed["error_rate_percent"] <= 100
        or not _is_finite_number(observed["p95_latency_ms"])
        or observed["p95_latency_ms"] < 0
        or isinstance(observed["restart_count"], bool)
        or not isinstance(observed["restart_count"], int)
        or observed["restart_count"] < 0
    ):
        die("machine attestation canary observations are invalid")
    if observed["error_rate_percent"] > thresholds["error_rate_percent_max"]:
        die("machine attestation canary error rate exceeded abort threshold")
    if observed["p95_latency_ms"] > thresholds["p95_latency_ms_max"]:
        die("machine attestation canary latency exceeded abort threshold")
    if observed["restart_count"] > thresholds["restart_count_max"]:
        die("machine attestation canary restarts exceeded abort threshold")

    rollback = value["rollback"]
    if not isinstance(rollback, dict):
        die("machine attestation rollback must be an object")
    strict_keys(
        rollback,
        {"automatic", "strategy", "restore_digest", "tested", "evidence_sha256"},
        "machine attestation rollback",
    )
    if rollback["automatic"] is not True or rollback["strategy"] != "gitops-revert":
        die("machine attestation rollback must be automatic GitOps revert")
    restore_digest = _require_digest(rollback["restore_digest"], "machine attestation rollback.restore_digest")
    if restore_digest == artifact_digest:
        die("machine attestation rollback restore digest must differ from release")
    if rollback["tested"] is not True:
        die("machine attestation rollback must have a passing test")
    _require_sha256(rollback["evidence_sha256"], "machine attestation rollback evidence")

    if canary["health"]["evidence_sha256"] != evidence["canary"]["sha256"]:
        die("machine attestation canary evidence is not bound to the evidence record")
    if rollback["evidence_sha256"] != evidence["rollback"]["sha256"]:
        die("machine attestation rollback evidence is not bound to the evidence record")
    if evidence["backup_guard"]["artifact_digest"] != artifact_digest:
        die("machine attestation backup evidence is not bound to the artifact")
    if evidence["production_domain_guard"]["artifact_digest"] != artifact_digest:
        die("machine attestation domain evidence is not bound to the artifact")

    audit = value["audit"]
    if not isinstance(audit, dict):
        die("machine attestation audit must be an object")
    strict_keys(audit, {"immutable", "append_only", "ledger", "entry_sha256", "sequence"}, "machine attestation audit")
    if audit["immutable"] is not True or audit["append_only"] is not True:
        die("machine attestation audit must be immutable and append-only")
    require_string(audit["ledger"], LEDGER, "machine attestation audit ledger")
    _require_sha256(audit["entry_sha256"], "machine attestation audit entry")
    if isinstance(audit["sequence"], bool) or not isinstance(audit["sequence"], int) or audit["sequence"] < 1:
        die("machine attestation audit sequence must be positive")

    replay = value["replay_protection"]
    if not isinstance(replay, dict):
        die("machine attestation replay_protection must be an object")
    strict_keys(
        replay,
        {"single_use", "nonce", "max_promotions", "cooldown_seconds", "consumed"},
        "machine attestation replay_protection",
    )
    if (
        replay["single_use"] is not True
        or type(replay["max_promotions"]) is not int
        or replay["max_promotions"] != 1
    ):
        die("machine attestation replay protection must be single-use")
    require_string(replay["nonce"], NONCE, "machine attestation replay nonce")
    if replay["cooldown_seconds"] != policy["rollout"]["cooldown_seconds"]:
        die("machine attestation cooldown does not match policy")
    if replay["consumed"] is not False:
        die("machine attestation has already been consumed")

    authorization = value["authorization"]
    if not isinstance(authorization, dict):
        die("machine attestation authorization must be an object")
    strict_keys(
        authorization,
        {"mode", "human_signers", "human_reviewers", "manual_override"},
        "machine attestation authorization",
    )
    if (
        authorization["mode"] != "machine-only"
        or type(authorization["human_signers"]) is not int
        or authorization["human_signers"] != 0
        or type(authorization["human_reviewers"]) is not int
        or authorization["human_reviewers"] != 0
        or authorization["manual_override"] is not False
    ):
        die("machine attestation authorization is not machine-only")
    if audit["entry_sha256"] != machine_attestation_audit_digest(value):
        die("machine attestation audit entry does not bind the complete attestation")
    if (evidence_root is None) != (allowed_machine_signers is None):
        die("evidence root and machine signer file must be supplied together")
    if evidence_root is not None and allowed_machine_signers is not None:
        verify_machine_attestation_evidence(value, evidence_root, allowed_machine_signers)
    return value


def consume_machine_attestation(
    value: dict[str, Any],
    policy: dict[str, Any],
    ledger_path: Path,
    *,
    now: dt.datetime,
    clock: Callable[[], dt.datetime] | None = None,
) -> dict[str, Any]:
    """Atomically consume a single attestation in an append-only local ledger."""

    parent = ledger_path.parent
    if clock is None:
        clock = lambda: dt.datetime.now(dt.timezone.utc)
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        die(f"machine replay ledger parent cannot be inspected: {exc}")
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        die("machine replay ledger parent must be a regular directory")
    try:
        existing = ledger_path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        die(f"machine replay ledger cannot be inspected: {exc}")
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
    ):
        die("machine replay ledger must be a regular file")

    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(ledger_path, flags, 0o600)
        with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0)
            raw_entries = handle.read()
            entries: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            seen_nonces: set[str] = set()
            for line_number, line in enumerate(raw_entries.splitlines(), 1):
                if not line.strip():
                    die(f"machine replay ledger contains a blank line at {line_number}")
                entry = load_json_bytes(
                    line.encode("utf-8"), f"machine replay ledger line {line_number}"
                )
                if canonical_bytes(entry).decode("utf-8") != line + "\n":
                    die(f"machine replay ledger line {line_number} is not canonical JSON")
                strict_keys(
                    entry,
                    {
                        "attestation_id",
                        "nonce",
                        "artifact_digest",
                        "consumed_at",
                        "expires_at",
                        "sequence",
                        "audit_entry_sha256",
                    },
                    f"machine replay ledger line {line_number}",
                )
                require_string(entry["attestation_id"], INTENT_ID, "replay ledger attestation_id")
                require_string(entry["nonce"], NONCE, "replay ledger nonce")
                _require_digest(entry["artifact_digest"], "replay ledger artifact_digest")
                parse_time(entry["consumed_at"], "replay ledger consumed_at")
                parse_time(entry["expires_at"], "replay ledger expires_at")
                if (
                    type(entry["sequence"]) is not int
                    or entry["sequence"] != line_number
                ):
                    die("machine replay ledger sequence is not contiguous")
                _require_sha256(entry["audit_entry_sha256"], "replay ledger audit_entry_sha256")
                if entry["attestation_id"] in seen_ids or entry["nonce"] in seen_nonces:
                    die("machine replay ledger contains a duplicate attestation or nonce")
                seen_ids.add(entry["attestation_id"])
                seen_nonces.add(entry["nonce"])
                entries.append(entry)

            attestation_id = value["attestation_id"]
            nonce = value["replay_protection"]["nonce"]
            if attestation_id in seen_ids or nonce in seen_nonces:
                die("machine release attestation has already been consumed")
            expected_sequence = len(entries) + 1
            # External evidence and registry checks happen before this lock is
            # acquired.  Re-read the trusted UTC clock while holding the lock
            # so a lease cannot be consumed after expiry or cooldown.
            try:
                fresh_now = clock()
            except Exception as exc:
                die(f"machine replay ledger clock could not be read: {exc}")
            if not isinstance(fresh_now, dt.datetime) or fresh_now.tzinfo is None:
                die("machine replay ledger clock must return timezone-aware UTC")
            fresh_now = fresh_now.astimezone(dt.timezone.utc)
            if fresh_now >= parse_time(value["expires_at"], "machine attestation expires_at"):
                die("machine release attestation expired before ledger consumption")
            if value["audit"]["sequence"] != expected_sequence:
                die("machine attestation audit sequence does not match replay ledger")
            if entries:
                last_consumed = parse_time(entries[-1]["consumed_at"], "replay ledger consumed_at")
                if fresh_now - last_consumed < dt.timedelta(
                    seconds=policy["rollout"]["cooldown_seconds"]
                ):
                    die("machine release cooldown has not elapsed")
            entry = {
                "artifact_digest": value["artifact"]["digest"],
                "attestation_id": attestation_id,
                "audit_entry_sha256": value["audit"]["entry_sha256"],
                "consumed_at": fresh_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": value["expires_at"],
                "nonce": nonce,
                "sequence": expected_sequence,
            }
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_bytes(entry).decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
            return entry
    except OSError as exc:
        die(f"machine replay ledger could not be consumed: {exc}")


def admit_machine_release(
    value: dict[str, Any],
    policy: dict[str, Any],
    *,
    now: dt.datetime,
    evidence_root: Path,
    allowed_machine_signers: Path,
    release_control_root: Path,
    source_root: Path,
    control_plane_root: Path,
    registry_authfile: Path,
    replay_ledger: Path,
    clock: Callable[[], dt.datetime] | None = None,
) -> dict[str, Any]:
    """Validate all trusted observations, then consume the attestation once."""

    validate_machine_release_attestation(
        value,
        policy,
        now=now,
        evidence_root=evidence_root,
        allowed_machine_signers=allowed_machine_signers,
    )
    git_checkout_repository(
        release_control_root,
        value["release_control"]["repository"],
        "release-control checkout",
    )
    git_checkout_identity(
        release_control_root,
        value["release_control"]["commit_sha"],
        value["release_control"]["tree_sha"],
        "release-control checkout",
    )
    git_checkout_repository(source_root, value["source"]["repository"], "source checkout")
    git_checkout_identity(
        source_root,
        value["source"]["commit_sha"],
        value["source"]["tree_sha"],
        "source checkout",
    )
    git_checkout_repository(
        control_plane_root,
        value["release_control"]["workflow"]["repository"],
        "private control-plane checkout",
    )
    git_checkout_identity(
        control_plane_root,
        value["release_control"]["workflow"]["commit_sha"],
        value["release_control"]["workflow"]["tree_sha"],
        "private control-plane checkout",
    )
    verify_registry_digest(
        value["artifact"]["repository"], value["artifact"]["digest"], registry_authfile
    )
    return consume_machine_attestation(value, policy, replay_ledger, now=now, clock=clock)


def load_policy(policy_dir: Path, policy_id: str, *, require_enabled: bool = True) -> dict[str, Any]:
    require_string(policy_id, POLICY_ID, "policy_id")
    path = policy_dir / f"{policy_id}.json"
    if not path.is_file():
        die(f"policy does not exist: {policy_id}")
    policy = load_json(path)
    require_canonical(path, policy)
    validate_policy(policy, require_enabled=require_enabled)
    if policy["policy_id"] != policy_id:
        die("policy filename and policy_id differ")
    return policy


def validate_intent_value(
    value: dict[str, Any], policy: dict[str, Any], *, now: dt.datetime
) -> dict[str, Any]:
    strict_keys(
        value,
        {
            "schema_version",
            "intent_id",
            "policy_id",
            "signer_identity",
            "issued_at",
            "expires_at",
            "source",
            "artifact",
            "rollback",
        },
        "intent",
    )
    if value["schema_version"] != 1:
        die("unsupported intent schema_version")
    require_string(value["intent_id"], INTENT_ID, "intent_id")
    require_string(value["policy_id"], POLICY_ID, "policy_id")
    require_string(value["signer_identity"], IDENT, "signer_identity")
    if value["policy_id"] != policy["policy_id"]:
        die("intent policy_id does not match policy")
    issued = parse_time(value["issued_at"], "issued_at")
    expires = parse_time(value["expires_at"], "expires_at")
    if expires <= issued:
        die("expires_at must be after issued_at")
    if now < issued - dt.timedelta(minutes=5):
        die("intent issued_at is in the future")
    if now >= expires:
        die("release intent is expired")
    if (expires - issued).total_seconds() > policy["max_intent_age_seconds"]:
        die("release intent lifetime exceeds policy")

    source = value["source"]
    if not isinstance(source, dict):
        die("source must be an object")
    strict_keys(source, {"repository", "commit_sha", "tree_sha"}, "source")
    require_string(source["repository"], SOURCE_REPO, "source.repository")
    require_string(source["commit_sha"], SHA, "source.commit_sha")
    require_string(source["tree_sha"], SHA, "source.tree_sha")
    if source["repository"] != policy["source_repository"]:
        die("source repository is not allowed by policy")

    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        die("artifact must be an object")
    strict_keys(artifact, {"repository", "version"}, "artifact")
    validate_artifact_repository(artifact["repository"], "artifact.repository")
    require_string(artifact["version"], VERSION, "artifact.version")
    if artifact["repository"] != policy["artifact_repository"]:
        die("artifact repository is not allowed by policy")

    rollback = value["rollback"]
    if not isinstance(rollback, dict):
        die("rollback must be an object")
    strict_keys(rollback, {"previous_digest", "reason"}, "rollback")
    require_string(rollback["previous_digest"], DIGEST, "rollback.previous_digest")
    reason = rollback["reason"]
    if not isinstance(reason, str) or not 8 <= len(reason) <= 512:
        die("rollback.reason must contain 8 to 512 characters")
    return value


def verify_ssh_signature(intent: Path, signature: Path, allowed: Path, identity: str) -> None:
    if not signature.is_file():
        die(f"missing detached signature: {signature}")
    if not allowed.is_file():
        die(f"missing allowed signers file: {allowed}")
    command = [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        str(allowed),
        "-I",
        identity,
        "-n",
        NAMESPACE,
        "-s",
        str(signature),
    ]
    try:
        result = subprocess.run(command, input=intent.read_bytes(), capture_output=True, check=False)
    except FileNotFoundError:
        die("ssh-keygen is required to verify release intent signatures")
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        die(f"release intent signature verification failed: {detail}")


def validate_intent(
    intent_path: Path,
    signature: Path,
    allowed: Path,
    policy_dir: Path,
    now: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    intent = load_json(intent_path)
    require_canonical(intent_path, intent)
    policy_id = intent.get("policy_id")
    if not isinstance(policy_id, str):
        die("intent missing policy_id")
    policy = load_policy(policy_dir, policy_id)
    validate_intent_value(intent, policy, now=now)
    verify_ssh_signature(intent_path, signature, allowed, intent["signer_identity"])
    return intent, policy


def inspect_oci_archive(path: Path) -> tuple[str, str]:
    archive_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = [member for member in archive.getmembers() if member.name == "index.json"]
            if len(members) != 1 or not members[0].isfile():
                die("OCI archive must contain exactly one regular index.json")
            handle = archive.extractfile(members[0])
            if handle is None:
                die("cannot read OCI archive index.json")
            index = json.loads(handle.read())
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        die(f"invalid OCI archive: {exc}")
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or len(manifests) != 1:
        die("OCI archive must contain exactly one top-level manifest")
    digest = manifests[0].get("digest") if isinstance(manifests[0], dict) else None
    require_string(digest, DIGEST, "OCI manifest digest")
    return digest, archive_hash


def build_evidence(intent: dict[str, Any], archive: Path) -> dict[str, Any]:
    digest, archive_hash = inspect_oci_archive(archive)
    return {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "source": intent["source"],
        "artifact": {"repository": intent["artifact"]["repository"], "digest": digest},
        "oci_archive_sha256": archive_hash,
    }


def validate_build_evidence(value: dict[str, Any], intent: dict[str, Any]) -> None:
    strict_keys(
        value,
        {"schema_version", "intent_id", "source", "artifact", "oci_archive_sha256"},
        "build evidence",
    )
    if value["schema_version"] != 1 or value["intent_id"] != intent["intent_id"]:
        die("build evidence identity does not match intent")
    if value["source"] != intent["source"]:
        die("build evidence source does not match intent")
    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        die("build evidence artifact must be an object")
    strict_keys(artifact, {"repository", "digest"}, "build evidence artifact")
    if artifact["repository"] != intent["artifact"]["repository"]:
        die("build evidence artifact repository does not match intent")
    require_string(artifact["digest"], DIGEST, "build evidence artifact digest")
    if not isinstance(value["oci_archive_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["oci_archive_sha256"]
    ):
        die("invalid OCI archive SHA-256")


def verify_published(
    intent: dict[str, Any], evidence: dict[str, Any], archive: Path, published_digest: str
) -> dict[str, Any]:
    validate_build_evidence(evidence, intent)
    require_string(published_digest, DIGEST, "published digest")
    archive_digest, archive_hash = inspect_oci_archive(archive)
    if archive_hash != evidence["oci_archive_sha256"]:
        die("transported OCI archive SHA-256 differs from build evidence")
    if archive_digest != evidence["artifact"]["digest"]:
        die("transported OCI manifest digest differs from build evidence")
    if published_digest != archive_digest:
        die("published digest differs from the built OCI manifest digest")
    return {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "source": intent["source"],
        "artifact": {
            "repository": intent["artifact"]["repository"],
            "digest": published_digest,
            "reference": f"{intent['artifact']['repository']}@{published_digest}",
            "version": intent["artifact"]["version"],
        },
        "oci_archive_sha256": archive_hash,
    }


def release_manifests(
    intent: dict[str, Any], record: dict[str, Any], expected_digest: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    strict_keys(
        record,
        {"schema_version", "intent_id", "source", "artifact", "oci_archive_sha256"},
        "release record",
    )
    if record["schema_version"] != 1:
        die("unsupported release record schema_version")
    if record.get("intent_id") != intent["intent_id"] or record.get("source") != intent["source"]:
        die("release record identity does not match intent")
    artifact = record.get("artifact")
    if not isinstance(artifact, dict):
        die("release record artifact missing")
    strict_keys(artifact, {"repository", "digest", "reference", "version"}, "release record artifact")
    digest = require_string(artifact.get("digest"), DIGEST, "release record digest")
    if expected_digest is not None and digest != require_string(
        expected_digest, DIGEST, "expected published digest"
    ):
        die("release record digest does not match publish job output")
    if artifact.get("repository") != intent["artifact"]["repository"]:
        die("release record artifact repository does not match intent")
    if artifact.get("reference") != f"{artifact['repository']}@{digest}":
        die("release record artifact reference is not digest exact")
    if artifact.get("version") != intent["artifact"]["version"]:
        die("release record version does not match intent")
    if not isinstance(record["oci_archive_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", record["oci_archive_sha256"]
    ):
        die("invalid release record OCI archive SHA-256")
    previous = intent["rollback"]["previous_digest"]
    if digest == previous:
        die("rollback digest must differ from the released digest")
    promotion = {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "source": intent["source"],
        "artifact": {
            "repository": artifact["repository"],
            "digest": digest,
            "reference": f"{artifact['repository']}@{digest}",
            "version": intent["artifact"]["version"],
        },
        "rollback_digest": previous,
    }
    rollback = {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "artifact_repository": artifact["repository"],
        "replace_digest": digest,
        "restore_digest": previous,
        "reason": intent["rollback"]["reason"],
    }
    return promotion, rollback


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def utc_now(value: str | None) -> dt.datetime:
    if value:
        return parse_time(value, "now")
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def emit_outputs(path: Path, intent: dict[str, Any], policy: dict[str, Any]) -> None:
    outputs = {
        "intent-id": intent["intent_id"],
        "policy-id": policy["policy_id"],
        "source-repository": intent["source"]["repository"],
        "source-name": intent["source"]["repository"].split("/", 1)[1],
        "source-sha": intent["source"]["commit_sha"],
        "source-tree": intent["source"]["tree_sha"],
        "artifact-repository": intent["artifact"]["repository"],
        "registry-host": policy["registry_host"],
        "context": policy["build"]["context"],
        "dockerfile": policy["build"]["dockerfile"],
        "platform": policy["build"]["platform"],
    }
    with path.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            if "\n" in value or "\r" in value:
                die(f"unsafe workflow output: {key}")
            handle.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    canonical = sub.add_parser("canonicalize")
    canonical.add_argument("--input", type=Path, required=True)
    canonical.add_argument("--output", type=Path, required=True)

    policy_parser = sub.add_parser("validate-policy")
    policy_parser.add_argument("--policy", type=Path, required=True)
    policy_parser.add_argument("--allow-disabled", action="store_true")

    automated_policy_parser = sub.add_parser(
        "validate-automated-policy",
        help="validate the permanent machine-only release policy",
    )
    automated_policy_parser.add_argument("--policy", type=Path, required=True)

    settings_parser = sub.add_parser(
        "validate-automated-settings",
        help="validate the checked-in machine-only repository settings contract",
    )
    settings_parser.add_argument("--settings", type=Path, required=True)

    machine_attestation_parser = sub.add_parser(
        "validate-machine-attestation",
        help="validate a private control-plane machine release attestation",
    )
    machine_attestation_parser.add_argument("--attestation", type=Path, required=True)
    machine_attestation_parser.add_argument("--policy", type=Path, required=True)
    machine_attestation_parser.add_argument("--now")

    admission_parser = sub.add_parser(
        "admit-machine-release",
        help="verify and atomically consume a machine release attestation",
    )
    admission_parser.add_argument("--attestation", type=Path, required=True)
    admission_parser.add_argument("--policy", type=Path, required=True)
    admission_parser.add_argument("--evidence-root", type=Path, required=True)
    admission_parser.add_argument("--allowed-machine-signers", type=Path, required=True)
    admission_parser.add_argument("--release-control-root", type=Path, required=True)
    admission_parser.add_argument("--source-root", type=Path, required=True)
    admission_parser.add_argument("--control-plane-root", type=Path, required=True)
    admission_parser.add_argument("--registry-authfile", type=Path, required=True)
    admission_parser.add_argument("--replay-ledger", type=Path, required=True)
    admission_parser.add_argument("--now")

    intent_parser = sub.add_parser("validate-intent")
    intent_parser.add_argument("--intent", type=Path, required=True)
    intent_parser.add_argument("--signature", type=Path, required=True)
    intent_parser.add_argument("--allowed-signers", type=Path, required=True)
    intent_parser.add_argument("--policy-dir", type=Path, required=True)
    intent_parser.add_argument("--now")
    intent_parser.add_argument("--github-output", type=Path)

    evidence_parser = sub.add_parser("build-evidence")
    evidence_parser.add_argument("--intent", type=Path, required=True)
    evidence_parser.add_argument("--archive", type=Path, required=True)
    evidence_parser.add_argument("--output", type=Path, required=True)

    verify_parser = sub.add_parser("verify-published")
    verify_parser.add_argument("--intent", type=Path, required=True)
    verify_parser.add_argument("--evidence", type=Path, required=True)
    verify_parser.add_argument("--archive", type=Path, required=True)
    verify_parser.add_argument("--published-digest", required=True)
    verify_parser.add_argument("--output", type=Path, required=True)

    manifest_parser = sub.add_parser("emit-manifests")
    manifest_parser.add_argument("--intent", type=Path, required=True)
    manifest_parser.add_argument("--release-record", type=Path, required=True)
    manifest_parser.add_argument("--promotion", type=Path, required=True)
    manifest_parser.add_argument("--rollback", type=Path, required=True)
    manifest_parser.add_argument("--expected-digest", required=True)

    command_parser = sub.add_parser("run-policy")
    command_parser.add_argument("--policy", type=Path, required=True)
    command_parser.add_argument("--source", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "canonicalize":
            write_json(args.output, load_json(args.input))
        elif args.command == "validate-policy":
            value = load_json(args.policy)
            require_canonical(args.policy, value)
            validate_policy(value, require_enabled=not args.allow_disabled)
        elif args.command == "validate-automated-policy":
            policy = load_json(args.policy)
            require_canonical(args.policy, policy)
            validate_automated_release_policy(policy)
        elif args.command == "validate-automated-settings":
            settings = load_json(args.settings)
            validate_automated_release_settings(settings)
        elif args.command == "validate-machine-attestation":
            policy = load_json(args.policy)
            require_canonical(args.policy, policy)
            attestation = load_json(args.attestation)
            require_canonical(args.attestation, attestation)
            validate_machine_release_attestation(
                attestation,
                policy,
                now=utc_now(args.now),
            )
        elif args.command == "admit-machine-release":
            policy = load_json(args.policy)
            require_canonical(args.policy, policy)
            attestation = load_json(args.attestation)
            require_canonical(args.attestation, attestation)
            result = admit_machine_release(
                attestation,
                policy,
                now=utc_now(args.now),
                evidence_root=args.evidence_root,
                allowed_machine_signers=args.allowed_machine_signers,
                release_control_root=args.release_control_root,
                source_root=args.source_root,
                control_plane_root=args.control_plane_root,
                registry_authfile=args.registry_authfile,
                replay_ledger=args.replay_ledger,
            )
            print(json.dumps({"status": "admitted", "ledger_entry": result}, sort_keys=True))
        elif args.command == "validate-intent":
            intent, policy = validate_intent(
                args.intent,
                args.signature,
                args.allowed_signers,
                args.policy_dir,
                utc_now(args.now),
            )
            if args.github_output:
                emit_outputs(args.github_output, intent, policy)
        elif args.command == "build-evidence":
            write_json(args.output, build_evidence(load_json(args.intent), args.archive))
        elif args.command == "verify-published":
            write_json(
                args.output,
                verify_published(
                    load_json(args.intent),
                    load_json(args.evidence),
                    args.archive,
                    args.published_digest,
                ),
            )
        elif args.command == "emit-manifests":
            promotion, rollback = release_manifests(
                load_json(args.intent), load_json(args.release_record), args.expected_digest
            )
            write_json(args.promotion, promotion)
            write_json(args.rollback, rollback)
        elif args.command == "run-policy":
            policy = load_json(args.policy)
            require_canonical(args.policy, policy)
            validate_policy(policy)
            source = args.source.resolve(strict=True)
            for command in policy["verification_commands"]:
                result = subprocess.run(command, cwd=source, check=False)
                if result.returncode:
                    die(f"verification command failed ({result.returncode}): {command!r}")
        return 0
    except ContractError as exc:
        print(f"release-control: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
