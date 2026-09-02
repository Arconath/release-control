#!/usr/bin/env python3
"""Strict release identity and digest contracts for Arconath release-control."""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
NONZERO_DIGEST = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IDENT = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,127}$")
POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
PRODUCT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
INTENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
SOURCE_REPO = re.compile(r"^Arconath/[a-z0-9][a-z0-9-]{1,99}$")
REGISTRY_HOST = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?$"
)
CANONICAL_REGISTRY_HOST = "registry.arconath.internal"
CANONICAL_ARTIFACT_PREFIX = f"{CANONICAL_REGISTRY_HOST}/arconath/"
ARTIFACT_REPO = re.compile(
    r"^(?=.{8,255}$)[a-z0-9.-]+(?::[1-9][0-9]{0,4})?(?:/[a-z0-9][a-z0-9._-]{0,127})+$"
)
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
AGE_RECIPIENT = re.compile(r"^age1[a-z0-9]{20,200}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
SIGNER_KEY_TYPE = re.compile(r"^(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+:-]+$")
SIGNER_KEY_BLOB = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
BUILD_ARG_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
CODEOWNER = re.compile(r"^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
WORKLOAD = re.compile(r"^[A-Za-z][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RELEASE_CODEOWNER_PATTERNS = (
    "*",
    "/.github/CODEOWNERS",
    "/.github/workflows/",
    "/bootstrap/",
    "/contracts/",
    "/policies/",
    "/scripts/",
    "/tests/",
)
IMMUTABLE_IMAGE = re.compile(
    r"^[a-z0-9](?:[a-z0-9./_-]{0,254})(?::[a-z0-9][a-z0-9._-]{0,127})?@sha256:(?!0{64}$)[0-9a-f]{64}$"
)
ZERO_DIGEST = "sha256:" + "0" * 64
NAMESPACE = "arconath-release-intent"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
NONZERO_HEX_SHA256 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")

# This is the protected release-control snapshot of platform/portfolio.yaml.
# A product source may enter the release boundary only through one of these
# exact canonical repositories.  Historical checkout names and product labels
# are intentionally absent; loklyo and spatial are the two canonical repository
# names retained by the portfolio plan.
CANONICAL_PRODUCTS: dict[str, tuple[str, str]] = {
    "release-passport": ("Arconath/releasepassport", "harden_existing"),
    "foundiqo": ("Arconath/foundiqo", "harden_existing"),
    "opportunity-radar": ("Arconath/loklyo", "experiment_only"),
    "boringkit": ("Arconath/boringkit", "harden_existing"),
    "abra": ("Arconath/abra", "maintenance_only"),
    "aeliqo": ("Arconath/aeliqo", "experiment_only"),
    "spatial-studio": ("Arconath/spatial", "experiment_only"),
    "efficient-ai-compute": ("Arconath/efficient-ai-compute", "benchmark_only"),
    "people-passport": ("Arconath/people-passport", "build_minimal"),
    "agentdeck": ("Arconath/agentdeck", "harden_existing"),
    "syviora": ("Arconath/syviora", "harden_existing"),
}

# Protected snapshot of each OCI image binding in platform-apps.  This is
# deliberately closed-world: adding an image or changing a workload requires a
# reviewed release-control policy change before a signed release can propose a
# GitOps update.  Non-OCI deliverables (Aeliqo's OpenWrt package and AgentDeck's
# mobile bundle) remain outside this image workflow and are documented blockers.
CANONICAL_PRODUCT_ARTIFACTS: dict[str, dict[str, dict[str, Any]]] = {
    "release-passport": {
        "releasepassport-web": {
            "repository": "registry.arconath.internal/arconath/releasepassport/web",
            "desired_state_path": "apps/releasepassport/desired-state.yaml",
            "workloads": ["Deployment/releasepassport-web"],
        },
        "releasepassport-api": {
            "repository": "registry.arconath.internal/arconath/releasepassport/api",
            "desired_state_path": "apps/releasepassport/desired-state.yaml",
            "workloads": ["Deployment/releasepassport-api"],
        },
        "releasepassport-worker": {
            "repository": "registry.arconath.internal/arconath/releasepassport/worker",
            "desired_state_path": "apps/releasepassport/desired-state.yaml",
            "workloads": ["Deployment/releasepassport-worker"],
        },
    },
    "foundiqo": {
        "foundiqo-web": {
            "repository": "registry.arconath.internal/arconath/foundiqo-web",
            "desired_state_path": "apps/foundiqo/desired-state.yaml",
            "workloads": ["Deployment/foundiqo-web"],
        },
        "foundiqo-web-bff": {
            "repository": "registry.arconath.internal/arconath/foundiqo-web-bff",
            "desired_state_path": "apps/foundiqo/desired-state.yaml",
            "workloads": ["Deployment/foundiqo-web-bff"],
        },
        "foundiqo-mobile-bff": {
            "repository": "registry.arconath.internal/arconath/foundiqo-mobile-bff",
            "desired_state_path": "apps/foundiqo/desired-state.yaml",
            "workloads": ["Deployment/foundiqo-mobile-bff"],
        },
        "foundiqo-worker": {
            "repository": "registry.arconath.internal/arconath/foundiqo-worker",
            "desired_state_path": "apps/foundiqo/desired-state.yaml",
            "workloads": ["Deployment/foundiqo-worker"],
        },
    },
    "opportunity-radar": {
        "loklyo-web": {
            "repository": "registry.arconath.internal/arconath/loklyo-web",
            "desired_state_path": "apps/loklyo/desired-state.yaml",
            "workloads": ["Deployment/loklyo-opportunity-web"],
        },
        "loklyo-api": {
            "repository": "registry.arconath.internal/arconath/loklyo-api",
            "desired_state_path": "apps/loklyo/desired-state.yaml",
            "workloads": [
                "Deployment/loklyo-opportunity-api",
                "Job/loklyo-opportunity-migration",
            ],
        },
        "loklyo-worker": {
            "repository": "registry.arconath.internal/arconath/loklyo-worker",
            "desired_state_path": "apps/loklyo/desired-state.yaml",
            "workloads": ["Deployment/loklyo-opportunity-worker"],
        },
    },
    "boringkit": {
        "boringkit-web": {
            "repository": "registry.arconath.internal/arconath/boringkit-web",
            "desired_state_path": "apps/boringkit/desired-state.yaml",
            "workloads": ["Deployment/boringkit-web"],
        },
        "boringkit-api": {
            "repository": "registry.arconath.internal/arconath/boringkit-api",
            "desired_state_path": "apps/boringkit/desired-state.yaml",
            "workloads": ["Deployment/boringkit-api"],
        },
        "boringkit-worker": {
            "repository": "registry.arconath.internal/arconath/boringkit-worker",
            "desired_state_path": "apps/boringkit/desired-state.yaml",
            "workloads": [
                "Deployment/boringkit-worker-api",
                "Deployment/boringkit-worker-image",
                "Deployment/boringkit-worker-docs",
                "Deployment/boringkit-worker-video",
            ],
        },
    },
    "abra": {
        "abra": {
            "repository": "registry.arconath.internal/arconath/abra",
            "desired_state_path": "apps/abra/desired-state.yaml",
            "workloads": [
                "Deployment/abra-api",
                "Deployment/abra-worker",
                "Job/abra-migrate",
            ],
        },
    },
    "aeliqo": {
        "aeliqo-web": {
            "repository": "registry.arconath.internal/arconath/aeliqo-web",
            "desired_state_path": "apps/aeliqo/desired-state.yaml",
            "workloads": ["Deployment/aeliqo-web"],
        },
        "aeliqo-web-bff": {
            "repository": "registry.arconath.internal/arconath/aeliqo-web-bff",
            "desired_state_path": "apps/aeliqo/desired-state.yaml",
            "workloads": ["Deployment/aeliqo-web-bff"],
        },
        "aeliqo-mobile-bff": {
            "repository": "registry.arconath.internal/arconath/aeliqo-mobile-bff",
            "desired_state_path": "apps/aeliqo/desired-state.yaml",
            "workloads": ["Deployment/aeliqo-mobile-bff"],
        },
        "aeliqo-agent-gateway": {
            "repository": "registry.arconath.internal/arconath/aeliqo-agent-gateway",
            "desired_state_path": "apps/aeliqo/desired-state.yaml",
            "workloads": ["Deployment/aeliqo-agent-gateway"],
        },
    },
    "spatial-studio": {
        "spatial-control-api": {
            "repository": "registry.arconath.internal/arconath/spatial-control-api",
            "desired_state_path": "apps/spatial-studio/desired-state.yaml",
            "workloads": ["Deployment/spatial-control-api"],
        },
        "spatial-worker": {
            "repository": "registry.arconath.internal/arconath/spatial-worker",
            "desired_state_path": "apps/spatial-studio/desired-state.yaml",
            "workloads": ["Deployment/spatial-worker"],
        },
    },
    "efficient-ai-compute": {
        "efficient-ai-compute": {
            "repository": "registry.arconath.internal/arconath/efficient-ai-compute",
            "desired_state_path": "apps/efficient-ai-compute/desired-state.yaml",
            "workloads": ["Deployment/efficient-ai-compute"],
        },
    },
    "people-passport": {
        "people-passport": {
            "repository": "registry.arconath.internal/arconath/people-passport",
            "desired_state_path": "apps/people-passport/desired-state.yaml",
            "workloads": ["Deployment/people-passport"],
        },
    },
    "agentdeck": {
        "agentdeck-bridge": {
            "repository": "registry.arconath.internal/arconath/agentdeck-bridge",
            "desired_state_path": "apps/agentdeck/desired-state.yaml",
            "workloads": ["Deployment/agentdeck-bridge"],
        },
        "agentdeck-push-gateway": {
            "repository": "registry.arconath.internal/arconath/agentdeck-push-gateway",
            "desired_state_path": "apps/agentdeck/desired-state.yaml",
            "workloads": ["ComposeService/push-gateway"],
        },
    },
    "syviora": {
        "syviora-web": {
            "repository": "registry.arconath.internal/arconath/syviora-web",
            "desired_state_path": "apps/syviora/desired-state.yaml",
            "workloads": ["Deployment/syviora-web"],
        },
        "syviora-api": {
            "repository": "registry.arconath.internal/arconath/syviora-api",
            "desired_state_path": "apps/syviora/desired-state.yaml",
            "workloads": ["Deployment/syviora-web-bff"],
        },
        "syviora-worker": {
            "repository": "registry.arconath.internal/arconath/syviora-worker",
            "desired_state_path": "apps/syviora/desired-state.yaml",
            "workloads": ["Deployment/syviora-worker"],
        },
    },
}
PLATFORM_POLICY_IDS = frozenset(
    {
        "platform-keycloak",
        "platform-observability",
        "platform-pgadmin",
        "platform-registry-jwks",
        "platform-traefik",
    }
)
PLATFORM_POLICY_SOURCE = "Arconath/platform-components"
BLOCKED_BUILD_AUTHORIZATIONS = frozenset({"no_product_engineering", "archived"})
HANDOFF_FILES = {
    "source": "product.tar.age",
    "candidate": "candidate.oci.tar.age",
}
HANDOFF_PLAINTEXT_FILES = {
    "source": "product.tar",
    "candidate": "candidate.oci.tar",
}
EVIDENCE_FILE_NAMES = {
    "build_evidence": "build-evidence.json",
    "lock": "evidence-lock.json",
    "sbom": "sbom.spdx.json",
    "licenses": "licenses.json",
    "provenance": "provenance.intoto.json",
    "vulnerabilities": "vulnerabilities.json",
    "artifact_signature": "artifact.sigstore.json",
    "build_evidence_attestation": "build-evidence.attestation.sigstore.json",
    "license_attestation": "license.attestation.sigstore.json",
    "sbom_attestation": "sbom.attestation.sigstore.json",
    "provenance_attestation": "provenance.attestation.sigstore.json",
    "vulnerability_attestation": "vulnerability.attestation.sigstore.json",
}
RELEASE_EVIDENCE_KEYS = (
    "lock",
    "sbom",
    "licenses",
    "provenance",
    "vulnerabilities",
    "artifact_signature",
    "build_evidence_attestation",
    "license_attestation",
    "sbom_attestation",
    "provenance_attestation",
    "vulnerability_attestation",
)
REQUIRED_REPOSITORY_VARIABLES = {
    "ARCONATH_REGISTRY_HOST": CANONICAL_REGISTRY_HOST,
    "CANDIDATE_HANDOFF_AGE_RECIPIENT": "set-after-candidate-handoff-key-is-created",
    "SOURCE_HANDOFF_AGE_RECIPIENT": "set-after-source-handoff-key-is-created",
    "SOURCE_READER_APP_ID": "set-after-source-reader-app-is-created",
}
REQUIRED_REPOSITORY_SECRETS = ("SOURCE_READER_PRIVATE_KEY",)
REQUIRED_ENVIRONMENT_SECRETS = {
    "source-handoff": ["SOURCE_HANDOFF_AGE_IDENTITY"],
    "publication": [
        "ARCONATH_REGISTRY_USERNAME",
        "ARCONATH_REGISTRY_PASSWORD",
        "CANDIDATE_HANDOFF_AGE_IDENTITY",
    ],
    "promotion": [],
}
EXPECTED_CONTRACT_FILES = frozenset(
    {
        "artifact-lock-proposal.schema.json",
        "build-evidence.schema.json",
        "evidence-lock.schema.json",
        "license-evidence.schema.json",
        "product-policy.schema.json",
        "promotion-manifest.schema.json",
        "provenance.schema.json",
        "release-intent.schema.json",
        "release-record.schema.json",
        "rollback-manifest.schema.json",
        "source-handoff.schema.json",
    }
)
CANONICAL_RUNNER_GROUP = "arconath-jit"
CANONICAL_RUNNER_LABELS = (
    "self-hosted",
    "linux",
    "x64",
    "arconath-jit",
    "rootless-buildkit",
)
CONTRACT_SCHEMA_ID_PREFIX = "https://release-control.arconath.com/contracts/"


class ContractError(ValueError):
    """A fail-closed contract validation error."""


def die(message: str) -> None:
    raise ContractError(message)


def require_directory(path: Path, context: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        die(f"{context} must be a regular non-symlink directory: {path}")
    return path


def load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        die(f"cannot load JSON {path}: regular non-symlink file required")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        die(f"cannot load JSON {path}: {exc}")
    if not isinstance(value, dict):
        die(f"JSON document must be an object: {path}")
    return value


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def require_canonical(path: Path, value: Any) -> None:
    if path.is_symlink() or not path.is_file():
        die(f"document must be a regular non-symlink file: {path}")
    try:
        actual = path.read_bytes()
    except OSError as exc:
        die(f"cannot read document {path}: {exc}")
    if actual != canonical_bytes(value):
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


def require_integer_at_least(value: Any, minimum: int, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        die(f"{context} must be an integer of at least {minimum}")
    return value


def require_nonzero_digest(value: Any, context: str) -> str:
    return require_string(value, NONZERO_DIGEST, context)


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        die(f"evidence file must be a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        die(f"cannot read file {path}: {exc}")
    return digest.hexdigest()


def source_tree_snapshot(source: Path) -> dict[str, tuple[Any, ...]]:
    """Capture a fail-closed identity snapshot of a product source tree."""

    require_directory(source, "product validation source")
    try:
        root_mode = stat.S_IMODE(source.lstat().st_mode)
    except OSError as exc:
        die(f"cannot inspect product validation source: {exc}")
    snapshot: dict[str, tuple[Any, ...]] = {".": ("directory", root_mode)}

    def onerror(exc: OSError) -> None:
        die(f"cannot inspect product validation source: {exc}")

    for current, directories, files in os.walk(
        source, topdown=True, followlinks=False, onerror=onerror
    ):
        entries = sorted(directories) + sorted(files)
        for name in entries:
            path = Path(current) / name
            relative = path.relative_to(source).as_posix()
            try:
                metadata = path.lstat()
            except OSError as exc:
                die(f"cannot inspect product validation source: {exc}")
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                die(f"product validation source contains an unsupported symlink: {relative}")
            if stat.S_ISDIR(mode):
                snapshot[relative] = ("directory", stat.S_IMODE(mode))
            elif stat.S_ISREG(mode):
                snapshot[relative] = ("file", stat.S_IMODE(mode), sha256_file(path))
            else:
                die(f"product validation source contains an unsupported file type: {relative}")
    return snapshot


VALIDATION_ENV_KEYS = frozenset(
    {"CI", "LANG", "LC_ALL", "PATH", "SHELL", "TERM", "TZ", "USER", "LOGNAME"}
)


def validation_environment(root: Path) -> dict[str, str]:
    """Provide product verification only non-credentialed, disposable state."""

    environment = {
        key: value
        for key, value in os.environ.items()
        if key in VALIDATION_ENV_KEYS
    }
    environment["PATH"] = environment.get("PATH") or "/usr/local/bin:/usr/bin:/bin"
    for name in ("home", "tmp", "cache", "config", "data"):
        (root / name).mkdir()
    environment.update(
        {
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "TMP": str(root / "tmp"),
            "TEMP": str(root / "tmp"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def run_policy(policy: dict[str, Any], source: Path) -> None:
    """Run approved product checks from a disposable copy with no secrets."""

    validate_policy(policy)
    require_directory(source, "product validation source")
    before = source_tree_snapshot(source)
    try:
        with tempfile.TemporaryDirectory(prefix="release-control-validation-") as temporary:
            temporary_root = Path(temporary)
            validation_source = temporary_root / "source"
            shutil.copytree(source, validation_source, symlinks=False)
            environment = validation_environment(temporary_root)
            for command in policy["verification_commands"]:
                try:
                    result = subprocess.run(
                        command,
                        cwd=validation_source,
                        env=environment,
                        check=False,
                    )
                except (FileNotFoundError, OSError) as exc:
                    die(f"verification command could not be executed: {command!r}: {exc}")
                if result.returncode:
                    die(f"verification command failed ({result.returncode}): {command!r}")
                if source_tree_snapshot(source) != before:
                    die("product validation mutated the source; validation must be read-only")
    except OSError as exc:
        die(f"cannot create disposable product validation workspace: {exc}")


def require_json_object(path: Path, context: str) -> dict[str, Any]:
    """Load an evidence JSON object without trusting its formatting."""

    if not path.is_file() or path.is_symlink():
        die(f"{context} must be a regular non-symlink file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        die(f"{context} is not valid JSON: {exc}")
    if not isinstance(value, dict) or not value:
        die(f"{context} must be a non-empty JSON object")
    return value


def evidence_file(path: Path, key: str, *, require_json: bool = True) -> dict[str, str]:
    """Return a canonical filename/hash entry for a generated evidence file."""

    expected_name = EVIDENCE_FILE_NAMES.get(key)
    if expected_name is None:
        die(f"unsupported evidence key: {key}")
    if path.name != expected_name:
        die(f"{key} evidence must be named {expected_name}")
    if require_json:
        require_json_object(path, f"{key} evidence")
    digest = sha256_file(path)
    return {"filename": expected_name, "sha256": digest}


def validate_file_hash(value: Any, key: str, *, expected_name: str | None = None) -> dict[str, str]:
    if not isinstance(value, dict):
        die(f"{key} evidence reference must be an object")
    strict_keys(value, {"filename", "sha256"}, f"{key} evidence reference")
    filename = value["filename"]
    if expected_name is None:
        expected_name = EVIDENCE_FILE_NAMES.get(key)
    if filename != expected_name:
        die(f"{key} evidence filename is not canonical")
    require_string(filename, re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$"), f"{key} evidence filename")
    require_string(value["sha256"], NONZERO_HEX_SHA256, f"{key} evidence SHA-256")
    return {"filename": filename, "sha256": value["sha256"]}


def validate_registry_host(value: Any, context: str = "registry_host") -> str:
    host = require_string(value, REGISTRY_HOST, context)
    if ":" in host and int(host.rsplit(":", 1)[1]) > 65535:
        die(f"invalid {context} port")
    return host


def validate_artifact_repository(value: Any, context: str) -> str:
    repository = require_string(value, ARTIFACT_REPO, context)
    host, *segments = repository.split("/")
    validate_registry_host(host, f"{context} registry host")
    if not segments or any(segment in {".", ".."} for segment in segments):
        die(f"invalid {context} path")
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
    actual = set(value)
    missing = sorted(required - actual)
    unknown = sorted(actual - (required | {"artifact_lock", "product_id"}))
    if missing:
        die(f"policy missing fields: {', '.join(missing)}")
    if unknown:
        die(f"policy unknown fields: {', '.join(unknown)}")
    if value["schema_version"] != 1:
        die("unsupported policy schema_version")
    require_string(value["policy_id"], POLICY_ID, "policy_id")
    if not isinstance(value["enabled"], bool):
        die("policy enabled must be boolean")
    if require_enabled and not value["enabled"]:
        die("policy is disabled")
    source_repository = require_string(value["source_repository"], SOURCE_REPO, "source_repository")
    product_id = value.get("product_id")
    expected_binding: dict[str, Any] | None = None
    if product_id is not None:
        product_id = require_string(product_id, PRODUCT_ID, "product_id")
        product = CANONICAL_PRODUCTS.get(product_id)
        if product is None:
            die("policy product_id is not in the canonical 11-product plan")
        expected_repository, build_authorization = product
        if source_repository != expected_repository:
            die("policy source_repository does not match canonical product_id")
        if build_authorization in BLOCKED_BUILD_AUTHORIZATIONS:
            die("canonical product build authorization does not permit release")
        if value["policy_id"] in PLATFORM_POLICY_IDS:
            die("platform policies cannot declare a canonical product_id")
        artifacts = CANONICAL_PRODUCT_ARTIFACTS[product_id]
        expected_binding = artifacts.get(value["policy_id"])
        if expected_binding is None:
            die("policy_id is not an authorized canonical product artifact")
        artifact_lock = value.get("artifact_lock")
        if not isinstance(artifact_lock, dict):
            die("canonical product policy requires an artifact_lock binding")
        strict_keys(
            artifact_lock,
            {"desired_state_path", "key", "proposal_only", "repository", "workloads"},
            "artifact_lock",
        )
        if artifact_lock["repository"] != "Arconath/platform-apps":
            die("artifact-lock binding repository must be Arconath/platform-apps")
        if artifact_lock["key"] != value["policy_id"]:
            die("artifact-lock binding key must match policy_id")
        if artifact_lock["proposal_only"] is not True:
            die("artifact-lock binding must be proposal-only")
        desired_state_path = relative_path(
            artifact_lock["desired_state_path"], "artifact_lock.desired_state_path"
        )
        if desired_state_path != expected_binding["desired_state_path"]:
            die("artifact-lock binding desired-state path is not canonical")
        workloads = artifact_lock["workloads"]
        if (
            not isinstance(workloads, list)
            or not workloads
            or len(workloads) != len(set(workloads))
            or any(not isinstance(item, str) or not WORKLOAD.fullmatch(item) for item in workloads)
        ):
            die("artifact-lock binding workloads must be unique workload identities")
        if workloads != expected_binding["workloads"]:
            die("artifact-lock binding workloads do not match canonical product binding")
    elif value["enabled"] and value["policy_id"] not in PLATFORM_POLICY_IDS:
        die("enabled product policies must declare a canonical product_id")
    elif "artifact_lock" in value:
        die("non-product policies cannot declare an artifact_lock binding")
    if value["policy_id"] in PLATFORM_POLICY_IDS and source_repository != PLATFORM_POLICY_SOURCE:
        die("platform policy source_repository is not canonical")
    registry_host = validate_registry_host(value["registry_host"])
    validate_artifact_repository(value["artifact_repository"], "artifact_repository")
    if registry_host != CANONICAL_REGISTRY_HOST:
        die(
            "registry_host must be the canonical internal Distribution host: "
            f"{CANONICAL_REGISTRY_HOST}"
        )
    if not value["artifact_repository"].startswith(f"{registry_host}/"):
        die("artifact_repository must be hosted by registry_host")
    if not value["artifact_repository"].startswith(CANONICAL_ARTIFACT_PREFIX):
        die("artifact_repository must use the canonical arconath/ namespace")
    if expected_binding is not None and value["artifact_repository"] != expected_binding["repository"]:
        die("artifact_repository does not match canonical product artifact")
    age = value["max_intent_age_seconds"]
    if isinstance(age, bool) or not isinstance(age, int) or not 300 <= age <= 604800:
        die("max_intent_age_seconds must be between 300 and 604800")
    build = value["build"]
    if not isinstance(build, dict):
        die("build must be an object")
    allowed_build_keys = {
        "context",
        "dockerfile",
        "platform",
        "build_args",
        "identity_args",
    }
    unknown_build_keys = sorted(set(build) - allowed_build_keys)
    if unknown_build_keys:
        die(f"build unknown fields: {', '.join(unknown_build_keys)}")
    missing_build_keys = sorted({"context", "dockerfile", "platform"} - set(build))
    if missing_build_keys:
        die(f"build missing fields: {', '.join(missing_build_keys)}")
    relative_path(build["context"], "build.context", allow_dot=True)
    relative_path(build["dockerfile"], "build.dockerfile")
    if build["platform"] not in {"linux/amd64", "linux/arm64"}:
        die("unsupported build.platform")
    build_args = build.get("build_args", {})
    if not isinstance(build_args, dict) or not build_args:
        if "build_args" in build:
            die("build.build_args must be a non-empty object when present")
    else:
        if len(build_args) > 32:
            die("build.build_args contains too many entries")
        for arg_name, arg_value in build_args.items():
            if not isinstance(arg_name, str) or not BUILD_ARG_NAME.fullmatch(arg_name):
                die(f"invalid build argument name: {arg_name!r}")
            if (
                not isinstance(arg_value, str)
                or not arg_value
                or "\r" in arg_value
                or "\n" in arg_value
            ):
                die(f"invalid build argument value for {arg_name}")
            if len(arg_value) > 512:
                die(f"build argument value for {arg_name} must be at most 512 characters")
            if arg_name in {"VCS_REF", "SOURCE_REVISION"}:
                die(f"{arg_name} is reserved and is injected from the signed source SHA")
            if arg_name in {"BASE_IMAGE", "BUILDER_IMAGE"} and not IMMUTABLE_IMAGE.fullmatch(arg_value):
                die(f"{arg_name} must be a lowercase image reference pinned by sha256 digest")
    identity_args = build.get("identity_args", {})
    if not isinstance(identity_args, dict):
        die("build.identity_args must be an object")
    if "identity_args" in build and not identity_args:
        die("build.identity_args must be a non-empty object when present")
    unknown_identity = sorted(set(identity_args) - {"created", "revision", "version"})
    if unknown_identity:
        die(f"build.identity_args unknown fields: {', '.join(unknown_identity)}")
    identity_names: list[str] = []
    for identity_kind, names in identity_args.items():
        if (
            not isinstance(names, list)
            or not names
            or len(names) > 8
            or any(not isinstance(name, str) or not BUILD_ARG_NAME.fullmatch(name) for name in names)
        ):
            die(f"build.identity_args.{identity_kind} must contain valid build argument names")
        identity_names.extend(names)
    if len(identity_names) != len(set(identity_names)):
        die("build.identity_args contains duplicate build argument names")
    universal_identity_names = {"SOURCE_REVISION", "VCS_REF"}
    if set(identity_names) & universal_identity_names:
        die("build.identity_args cannot repeat universal source identity arguments")
    if set(identity_names) & set(build_args):
        die("static build_args cannot override signed identity build arguments")
    commands = value["verification_commands"]
    if not isinstance(commands, list) or not commands:
        die("verification_commands must be a non-empty array")
    for index, command in enumerate(commands):
        if not isinstance(command, list) or not command:
            die(f"verification_commands[{index}] must be a non-empty argv array")
        if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in command):
            die(f"verification_commands[{index}] contains an invalid argument")
    return value


def validate_policy_set(policy_dir: Path) -> dict[str, int]:
    """Require one closed-world OCI policy inventory for all 11 products."""

    require_directory(policy_dir, "policy directory")
    expected = {
        policy_id
        for artifacts in CANONICAL_PRODUCT_ARTIFACTS.values()
        for policy_id in artifacts
    }
    actual: set[str] = set()
    artifact_repositories: set[str] = set()
    validated_files = 0
    for path in sorted(policy_dir.iterdir()):
        if not path.name.endswith((".json", ".json.disabled")):
            continue
        validated_files += 1
        value = load_json(path)
        require_canonical(path, value)
        validate_policy(value, require_enabled=False)
        product_id = value.get("product_id")
        if product_id is None:
            continue
        policy_id = value["policy_id"]
        expected_filename = f"{policy_id}.json" + ("" if value["enabled"] else ".disabled")
        if path.name != expected_filename:
            die(f"product policy filename and activation state differ: {path.name}")
        if policy_id in actual:
            die(f"duplicate canonical product policy: {policy_id}")
        repository = value["artifact_repository"]
        if repository in artifact_repositories:
            die(f"duplicate canonical product artifact repository: {repository}")
        actual.add(policy_id)
        artifact_repositories.add(repository)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        die(f"canonical product policies missing: {', '.join(missing)}")
    if unexpected:
        die(f"unexpected canonical product policies: {', '.join(unexpected)}")
    return {
        "validated_policy_files": validated_files,
        "canonical_product_policies": len(actual),
    }


def _validate_schema_structure(value: Any, location: str) -> None:
    """Check the strict structural subset shared by every local JSON schema."""

    if isinstance(value, dict):
        if "properties" in value and value.get("type") != "object":
            die(f"{location}: schema properties must have object type")
        if "required" in value:
            required = value.get("required")
            properties = value.get("properties")
            if value.get("type") != "object" or not isinstance(required, list) or not required:
                die(f"{location}: schema required must be a non-empty object property list")
            if not isinstance(properties, dict):
                die(f"{location}: schema required needs local properties")
            if any(not isinstance(item, str) or not item for item in required):
                die(f"{location}: schema required contains an invalid property name")
            if len(required) != len(set(required)):
                die(f"{location}: schema required contains duplicate property names")
            if not set(required).issubset(properties):
                die(f"{location}: schema required keys must be declared locally")
        for key, child in value.items():
            _validate_schema_structure(child, f"{location}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_schema_structure(child, f"{location}/{index}")


def validate_contract_inventory(contract_dir: Path) -> dict[str, int]:
    """Validate the exact, closed-world inventory of release contract schemas."""

    require_directory(contract_dir, "contract schema directory")
    entries = list(contract_dir.iterdir())
    actual = {entry.name for entry in entries}
    missing = sorted(EXPECTED_CONTRACT_FILES - actual)
    unexpected = sorted(actual - EXPECTED_CONTRACT_FILES)
    if missing:
        die(f"contract schemas missing: {', '.join(missing)}")
    if unexpected:
        die(f"unexpected contract schema files: {', '.join(unexpected)}")
    for filename in sorted(EXPECTED_CONTRACT_FILES):
        path = contract_dir / filename
        value = load_json(path)
        if value.get("type") != "object":
            die(f"{filename}: root schema must have object type")
        if value.get("additionalProperties") is not False:
            die(f"{filename}: root schema must close additional properties")
        required = value.get("required")
        if not isinstance(required, list) or not required:
            die(f"{filename}: root schema must declare required properties")
        schema_id = value.get("$id")
        if not isinstance(schema_id, str) or not schema_id.startswith(CONTRACT_SCHEMA_ID_PREFIX):
            die(f"{filename}: schema $id is not in the canonical namespace")
        _validate_schema_structure(value, filename)
    return {"schema_files": len(EXPECTED_CONTRACT_FILES)}


def _workflow_runner_body(lines: list[str], line_index: int, indent: int, inline: str) -> str:
    if inline.strip():
        return inline.strip()
    body: list[str] = []
    for line in lines[line_index + 1 :]:
        if line.strip():
            line_indent = len(line) - len(line.lstrip(" "))
            if line_indent <= indent:
                break
        body.append(line.strip())
    return " ".join(body)


def validate_workflow_policy(workflow_dir: Path) -> dict[str, int]:
    """Validate pinned actions, explicit permissions, and the private runner fleet."""

    require_directory(workflow_dir, "workflow directory")
    paths = sorted(
        path
        for path in workflow_dir.iterdir()
        if path.name.endswith((".yml", ".yaml"))
    )
    if not paths:
        die("workflow directory contains no YAML workflows")

    external_actions = 0
    runner_blocks = 0
    permission_blocks = 0
    for path in paths:
        if path.is_symlink() or not path.is_file():
            die(f"workflow must be a regular non-symlink file: {path}")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            die(f"cannot read workflow {path}: {exc}")
        if not any(re.fullmatch(r"permissions:\s*(?:#.*)?", line) for line in lines):
            die(f"workflow is missing top-level permissions: {path.name}")
        for line_number, line in enumerate(lines, 1):
            permissions_match = re.match(r"^ *permissions:\s*(.*?)(?:\s+#.*)?$", line)
            if permissions_match:
                permission_blocks += 1
                if permissions_match.group(1).strip() in {"read-all", "write-all"}:
                    die(f"workflow uses broad permissions at {path}:{line_number}")
            if re.search(r"\b(?:ubuntu|macos|windows)-(?:latest|[0-9][A-Za-z0-9._-]*)\b", line):
                die(f"workflow contains a GitHub-hosted runner at {path}:{line_number}")
            uses_match = re.match(r"\s*uses:\s*([^\s#]+)", line)
            if uses_match:
                reference = uses_match.group(1)
                if reference.startswith("./"):
                    continue
                if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference):
                    die(f"workflow action is not pinned to a commit at {path}:{line_number}")
                external_actions += 1
            runs_on_match = re.match(
                r"^(?P<indent> *)runs-on:\s*(?P<inline>.*?)(?:\s+#.*)?$", line
            )
            if not runs_on_match:
                continue
            runner_blocks += 1
            indent = len(runs_on_match.group("indent"))
            body = _workflow_runner_body(
                lines,
                line_number - 1,
                indent,
                runs_on_match.group("inline"),
            )
            if not re.search(
                rf"(?:^|\s)group:\s*{re.escape(CANONICAL_RUNNER_GROUP)}(?:\s|$)",
                body,
            ):
                die(f"workflow runner group is not canonical at {path}:{line_number}")
            labels_match = re.search(r"labels:\s*\[([^\]]+)\]", body)
            if not labels_match:
                die(f"workflow runner labels are not explicit at {path}:{line_number}")
            labels = [item.strip().strip("'\"") for item in labels_match.group(1).split(",")]
            if len(labels) != len(set(labels)) or set(labels) != set(CANONICAL_RUNNER_LABELS):
                die(f"workflow runner labels are not canonical at {path}:{line_number}")
    if runner_blocks == 0:
        die("workflow inventory contains no runner declarations")
    return {
        "workflow_files": len(paths),
        "runner_blocks": runner_blocks,
        "external_actions": external_actions,
        "permission_blocks": permission_blocks,
    }


def merge_readiness(
    codeowners: Path,
    allowed_signers: Path,
    settings_path: Path,
    policy_dir: Path,
    contract_dir: Path,
    workflow_dir: Path,
) -> dict[str, Any]:
    """Report local merge gates without pretending to inspect live GitHub."""

    checks: list[dict[str, Any]] = []
    blockers: list[str] = []

    try:
        governance = validate_governance(
            codeowners,
            allowed_signers,
            settings_path,
            require_ready=False,
        )
    except ContractError as exc:
        checks.append(
            {
                "name": "governance",
                "status": "blocked",
                "error": str(exc),
            }
        )
        blockers.append("GOVERNANCE_CONTRACT_INVALID")
    else:
        governance_blockers = list(governance["blocking_reasons"])
        checks.append(
            {
                "name": "governance",
                "status": "pass" if not governance_blockers else "blocked",
                "details": governance,
            }
        )
        blockers.extend(governance_blockers)

    gates: tuple[tuple[str, str, Any], ...] = (
        (
            "contracts",
            "CONTRACT_SCHEMA_INVENTORY_INVALID",
            lambda: validate_contract_inventory(contract_dir),
        ),
        (
            "policies",
            "POLICY_SET_INVALID",
            lambda: validate_policy_set(policy_dir),
        ),
        (
            "workflows",
            "WORKFLOW_POLICY_INVALID",
            lambda: validate_workflow_policy(workflow_dir),
        ),
    )
    for name, error_code, validator in gates:
        try:
            details = validator()
        except ContractError as exc:
            checks.append({"name": name, "status": "blocked", "error": str(exc)})
            blockers.append(error_code)
        else:
            checks.append({"name": name, "status": "pass", "details": details})

    unique_blockers = sorted(set(blockers))
    return {
        "schema_version": 1,
        "status": "ready" if not unique_blockers else "blocked",
        "merge_ready": not unique_blockers,
        "checked_in_contract_ready": not unique_blockers,
        "blocking_reasons": unique_blockers,
        "live_github_configuration": "unverified",
        "external_blockers": [
            "GITHUB_CONFIGURATION_UNVERIFIED",
            "ARCONATH_REGISTRY_HOST_UNVERIFIED",
            "ARCONATH_REGISTRY_CREDENTIALS_UNVERIFIED",
            "SOURCE_HANDOFF_CONFIGURATION_UNVERIFIED",
            "CANDIDATE_HANDOFF_CONFIGURATION_UNVERIFIED",
            "SOURCE_READER_CONFIGURATION_UNVERIFIED",
        ],
        "external_prerequisites": {
            "status": "unverified",
            "repository_variables": sorted(REQUIRED_REPOSITORY_VARIABLES),
            "repository_secrets": list(REQUIRED_REPOSITORY_SECRETS),
            "environment_secrets": {
                name: values for name, values in REQUIRED_ENVIRONMENT_SECRETS.items()
            },
            "action": (
                "Configure the listed GitHub variables, repository secret, and "
                "protected-environment secrets; keep their values out of the "
                "repository, then verify live GitHub configuration separately."
            ),
        },
        "checks": checks,
    }


def load_policy(policy_dir: Path, policy_id: str, *, require_enabled: bool = True) -> dict[str, Any]:
    require_string(policy_id, POLICY_ID, "policy_id")
    require_directory(policy_dir, "policy directory")
    path = policy_dir / f"{policy_id}.json"
    if path.is_symlink() or not path.is_file():
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
            "signer_identities",
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
    signer_identities = value["signer_identities"]
    if (
        not isinstance(signer_identities, list)
        or len(signer_identities) != 2
        or any(not isinstance(identity, str) or not IDENT.fullmatch(identity) for identity in signer_identities)
        or len(set(signer_identities)) != 2
    ):
        die("intent must name exactly two distinct signer identities")
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


def verify_ssh_signatures(
    intent: Path,
    signatures: Sequence[Path],
    allowed: Path,
    identities: Sequence[str],
) -> None:
    if intent.is_symlink() or not intent.is_file():
        die(f"release intent must be a regular non-symlink file: {intent}")
    if len(signatures) != 2 or len(identities) != 2 or len(set(identities)) != 2:
        die("release intent requires exactly two distinct detached signatures")
    expected_names = [f"{intent.name}.sig.1", f"{intent.name}.sig.2"]
    for index, signature in enumerate(signatures):
        if signature.name != expected_names[index]:
            die(f"detached signature {index + 1} must be named {expected_names[index]}")
        if signature.is_symlink() or not signature.is_file():
            die(f"missing detached signature: {signature}")
    if allowed.is_symlink() or not allowed.is_file():
        die(f"missing allowed signers file: {allowed}")
    require_two_operator_keys(allowed)
    for identity, signature in zip(identities, signatures):
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
            die(f"release intent signature verification failed for {identity}: {detail}")


def operator_key_inventory(allowed: Path) -> tuple[set[str], set[tuple[str, str]]]:
    """Parse named public keys without exposing key material in diagnostics.

    GitHub branch protection supplies the second human review for the change
    that adds an intent. This local inventory prevents a future repository
    configuration from silently reducing the cryptographic operator set to a
    single key.
    """

    if allowed.is_symlink() or not allowed.is_file():
        die(f"allowed signers file must be a regular non-symlink file: {allowed}")
    try:
        lines = allowed.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        die(f"cannot read allowed signers file: {exc}")

    operator_keys: set[tuple[str, str]] = set()
    operator_identities: set[str] = set()
    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        key_index = next(
            (index for index, field in enumerate(fields) if SIGNER_KEY_TYPE.fullmatch(field)),
            None,
        )
        if key_index is None or key_index == 0 or key_index + 1 >= len(fields):
            die(f"allowed signers line {line_number} is not a named public key")
        principals = fields[0].split(",")
        if not principals or any(not IDENT.fullmatch(principal) for principal in principals):
            die(f"allowed signers line {line_number} has an invalid operator identity")
        key_blob = fields[key_index + 1]
        if not SIGNER_KEY_BLOB.fullmatch(key_blob):
            die(f"allowed signers line {line_number} has an invalid public key encoding")
        operator_identities.update(principals)
        operator_keys.add((fields[key_index], key_blob))

    return operator_identities, operator_keys


def require_two_operator_keys(allowed: Path) -> None:
    """Require two distinct named operator keys before any release can verify."""

    operator_identities, operator_keys = operator_key_inventory(allowed)
    if len(operator_keys) < 2 or len(operator_identities) < 2:
        die("at least two distinct named operator keys are required")


def codeowner_rule_inventory(codeowners: Path) -> dict[str, set[str]]:
    if codeowners.is_symlink() or not codeowners.is_file():
        die(f"CODEOWNERS must be a regular non-symlink file: {codeowners}")
    try:
        lines = codeowners.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        die(f"cannot read CODEOWNERS: {exc}")
    rules: dict[str, set[str]] = {}
    for line_number, line in enumerate(lines, 1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        fields = content.split()
        pattern = fields[0]
        if pattern in rules:
            die(f"CODEOWNERS contains duplicate rule {pattern!r} on line {line_number}")
        rules[pattern] = {
            owner.casefold() for owner in fields[1:] if CODEOWNER.fullmatch(owner)
        }
    return rules


def named_codeowners(codeowners: Path) -> set[str]:
    return set().union(*codeowner_rule_inventory(codeowners).values())


def validate_runtime_configuration_contract(settings: dict[str, Any]) -> dict[str, Any]:
    """Validate checked-in names for credentials kept in GitHub settings."""

    variables = settings.get("required_repository_variables")
    if not isinstance(variables, dict):
        die("repository settings are missing required_repository_variables")
    strict_keys(
        variables,
        set(REQUIRED_REPOSITORY_VARIABLES),
        "required_repository_variables",
    )
    for name, expected in REQUIRED_REPOSITORY_VARIABLES.items():
        if variables.get(name) != expected:
            die(
                "required_repository_variables."
                f"{name} must remain the reviewed canonical marker"
            )

    environments = settings.get("environments")
    if not isinstance(environments, dict):
        die("repository settings are missing environments")
    if set(environments) != set(REQUIRED_ENVIRONMENT_SECRETS):
        die("repository settings environments must be the canonical release environments")
    for name, required_secrets in REQUIRED_ENVIRONMENT_SECRETS.items():
        environment = environments.get(name)
        if not isinstance(environment, dict):
            die(f"repository settings are missing {name} environment")
        if environment.get("required_secrets") != required_secrets:
            die(f"{name} environment required_secrets are not canonical")

    return {
        "status": "unverified",
        "repository_variables": sorted(REQUIRED_REPOSITORY_VARIABLES),
        "repository_secrets": list(REQUIRED_REPOSITORY_SECRETS),
        "environment_secrets": {
            name: values for name, values in REQUIRED_ENVIRONMENT_SECRETS.items()
        },
        "action": (
            "Configure the listed GitHub variables, repository secret, and "
            "protected-environment secrets; their live values are never stored "
            "in this repository."
        ),
    }


def validate_governance(
    codeowners: Path,
    allowed_signers: Path,
    settings_path: Path,
    *,
    require_ready: bool = True,
) -> dict[str, Any]:
    """Validate two-person source governance and report explicit readiness.

    The optional diagnostic mode is intentionally not a live GitHub check.  Its
    output therefore separates checked-in contract readiness from the external
    branch-protection and environment configuration that GitHub must enforce.
    """

    settings = load_json(settings_path)
    governance = settings.get("release_governance")
    if not isinstance(governance, dict):
        die("repository settings are missing release_governance")
    strict_keys(
        governance,
        {
            "enforce_on_release",
            "minimum_distinct_release_signers",
            "minimum_environment_reviewers",
            "minimum_named_codeowners",
            "required_codeowner_patterns",
        },
        "release_governance",
    )
    if governance["enforce_on_release"] is not True:
        die("release governance must be enforced on every release")
    minimum_codeowners = governance["minimum_named_codeowners"]
    minimum_signers = governance["minimum_distinct_release_signers"]
    minimum_reviewers = governance["minimum_environment_reviewers"]
    required_codeowner_patterns = governance["required_codeowner_patterns"]
    minimum_codeowners = require_integer_at_least(
        minimum_codeowners, 2, "release_governance.minimum_named_codeowners"
    )
    minimum_signers = require_integer_at_least(
        minimum_signers, 2, "release_governance.minimum_distinct_release_signers"
    )
    minimum_reviewers = require_integer_at_least(
        minimum_reviewers, 2, "release_governance.minimum_environment_reviewers"
    )
    if required_codeowner_patterns != list(RELEASE_CODEOWNER_PATTERNS):
        die("release_governance.required_codeowner_patterns is not canonical")

    runtime_prerequisites = validate_runtime_configuration_contract(settings)

    protection = settings.get("main_protection")
    if not isinstance(protection, dict):
        die("repository settings are missing main_protection")
    required_approvals = require_integer_at_least(
        protection.get("required_approvals"),
        minimum_codeowners,
        "main_protection.required_approvals",
    )
    if required_approvals < minimum_codeowners:
        die("main protection does not require enough approvals")
    for key in (
        "dismiss_stale_reviews",
        "enforce_admins",
        "require_code_owner_review",
        "require_last_push_approval",
        "require_signed_commits",
        "strict_checks",
        "linear_history",
    ):
        if protection.get(key) is not True:
            die(f"main protection must enable {key}")
    for key in ("allow_force_pushes", "allow_deletions"):
        if protection.get(key) is not False:
            die(f"main protection must disable {key}")
    if protection.get("required_checks") != ["contracts and workflow policy"]:
        die("main protection must require the contracts and workflow policy check")

    environments = settings.get("environments")
    if not isinstance(environments, dict):
        die("repository settings are missing environments")
    for environment_name in ("source-handoff", "publication", "promotion"):
        environment = environments.get(environment_name)
        if not isinstance(environment, dict):
            die(f"repository settings are missing {environment_name} environment")
        if environment.get("protected_branches_only") is not True:
            die(f"{environment_name} environment must be restricted to protected branches")
        required_reviewers = require_integer_at_least(
            environment.get("required_reviewers"),
            minimum_reviewers,
            f"{environment_name}.required_reviewers",
        )
        if required_reviewers < minimum_reviewers:
            die(f"{environment_name} environment does not require enough reviewers")
        if environment.get("prevent_self_review") is not True:
            die(f"{environment_name} environment must prevent self review")

    codeowner_rules = codeowner_rule_inventory(codeowners)
    owners = set().union(*codeowner_rules.values())
    missing_codeowner_rules = sorted(
        set(RELEASE_CODEOWNER_PATTERNS) - set(codeowner_rules)
    )
    protected_rules_ready = sum(
        len(codeowner_rules.get(pattern, set())) >= minimum_codeowners
        for pattern in RELEASE_CODEOWNER_PATTERNS
    )
    signer_identities, signer_keys = operator_key_inventory(allowed_signers)
    underprotected_rules = sorted(
        pattern
        for pattern, rule_owners in codeowner_rules.items()
        if len(rule_owners) < minimum_codeowners
    )
    checked_in_contract_ready = (
        len(owners) >= minimum_codeowners
        and protected_rules_ready == len(RELEASE_CODEOWNER_PATTERNS)
        and not underprotected_rules
        and len(signer_identities) >= minimum_signers
        and len(signer_keys) >= minimum_signers
    )
    blocking_reasons: list[str] = []
    if len(owners) < minimum_codeowners:
        blocking_reasons.append("CODEOWNERS_INCOMPLETE")
    if missing_codeowner_rules:
        blocking_reasons.append("CODEOWNER_RULES_MISSING")
    if protected_rules_ready != len(RELEASE_CODEOWNER_PATTERNS):
        blocking_reasons.append("CODEOWNER_RULES_UNDERPROTECTED")
    if underprotected_rules:
        blocking_reasons.append("CODEOWNERS_HAS_UNDERPROTECTED_RULES")
    if len(signer_identities) < minimum_signers:
        blocking_reasons.append("RELEASE_SIGNER_IDENTITIES_INCOMPLETE")
    if len(signer_keys) < minimum_signers:
        blocking_reasons.append("RELEASE_SIGNER_KEYS_INCOMPLETE")
    readiness = {
        "named_codeowners": len(owners),
        "protected_codeowner_rules_ready": protected_rules_ready,
        "release_signer_identities": len(signer_identities),
        "release_signer_keys": len(signer_keys),
        "minimum_named_codeowners": minimum_codeowners,
        "protected_codeowner_rules_required": len(RELEASE_CODEOWNER_PATTERNS),
        "minimum_release_signer_identities": minimum_signers,
        "minimum_release_signer_keys": minimum_signers,
        "minimum_environment_reviewers": minimum_reviewers,
        "required_codeowner_patterns": list(RELEASE_CODEOWNER_PATTERNS),
        "missing_codeowner_rules": missing_codeowner_rules,
        "underprotected_codeowner_rules": underprotected_rules,
        "blocking_reasons": blocking_reasons,
        "checked_in_contract_ready": checked_in_contract_ready,
        "status": "ready" if checked_in_contract_ready else "blocked",
        "merge_ready": checked_in_contract_ready,
        "live_github_configuration": "unverified",
        "runtime_prerequisites": runtime_prerequisites,
    }
    if require_ready and len(owners) < minimum_codeowners:
        die("at least two distinct named CODEOWNER accounts are required")
    if require_ready and protected_rules_ready != len(RELEASE_CODEOWNER_PATTERNS):
        die("every protected CODEOWNERS rule requires two distinct named accounts")
    if require_ready:
        if underprotected_rules:
            die(
                "every CODEOWNERS rule requires two distinct named accounts: "
                + ", ".join(underprotected_rules)
            )
    if require_ready and (
        len(signer_identities) < minimum_signers or len(signer_keys) < minimum_signers
    ):
        die("at least two distinct named operator keys are required")
    return readiness


def validate_intent(
    intent_path: Path,
    signatures: Sequence[Path],
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
    verify_ssh_signatures(intent_path, signatures, allowed, intent["signer_identities"])
    return intent, policy


def inspect_oci_archive(path: Path) -> tuple[str, str]:
    """Return a verified OCI manifest digest and exact archive hash.

    The digest recorded in ``index.json`` is untrusted input.  Verify the
    referenced manifest blob and every config/layer descriptor before using
    that digest as release identity.
    """

    if not path.is_file() or path.is_symlink():
        die(f"OCI archive must be a regular non-symlink file: {path}")
    archive_hash = sha256_file(path)
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                member_path = PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or member.name != member_path.as_posix()
                    or any(part in {"", ".", ".."} for part in member_path.parts)
                ):
                    die(f"OCI archive contains an unsafe path: {member.name!r}")
                if member.name in members:
                    die(f"OCI archive contains a duplicate path: {member.name}")
                if not (member.isfile() or member.isdir()):
                    die(f"OCI archive contains an unsupported entry type: {member.name}")
                members[member.name] = member

            def regular_member(name: str, context: str) -> tarfile.TarInfo:
                member = members.get(name)
                if member is None or not member.isfile():
                    die(f"{context} is missing or is not a regular file: {name}")
                return member

            def read_member(name: str, context: str, *, max_bytes: int) -> bytes:
                member = regular_member(name, context)
                if member.size > max_bytes:
                    die(f"{context} exceeds the safe size limit")
                handle = archive.extractfile(member)
                if handle is None:
                    die(f"cannot read {context}: {name}")
                data = handle.read(max_bytes + 1)
                if len(data) != member.size:
                    die(f"{context} size differs from its tar metadata")
                return data

            def read_json_member(name: str, context: str) -> dict[str, Any]:
                try:
                    value = json.loads(read_member(name, context, max_bytes=8 * 1024 * 1024))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    die(f"{context} is not valid JSON: {exc}")
                if not isinstance(value, dict):
                    die(f"{context} must be a JSON object")
                return value

            def verify_descriptor(
                descriptor: Any,
                context: str,
                *,
                load_bytes: bool = False,
            ) -> tuple[str, bytes | None]:
                if not isinstance(descriptor, dict):
                    die(f"{context} must be an object")
                digest = require_nonzero_digest(descriptor.get("digest"), f"{context} digest")
                size = descriptor.get("size")
                if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                    die(f"{context} size must be a non-negative integer")
                media_type = descriptor.get("mediaType")
                if not isinstance(media_type, str) or not media_type.startswith("application/"):
                    die(f"{context} mediaType is invalid")
                blob_name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
                member = regular_member(blob_name, "referenced OCI blob")
                if member.size != size:
                    die(f"{context} size differs from the referenced OCI blob")
                handle = archive.extractfile(member)
                if handle is None:
                    die(f"cannot read referenced OCI blob: {blob_name}")
                calculated = hashlib.sha256()
                content = bytearray() if load_bytes else None
                count = 0
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    count += len(chunk)
                    calculated.update(chunk)
                    if content is not None:
                        if count > 8 * 1024 * 1024:
                            die(f"{context} exceeds the safe JSON size limit")
                        content.extend(chunk)
                if count != size:
                    die(f"{context} size differs while reading the referenced OCI blob")
                if calculated.hexdigest() != digest.removeprefix("sha256:"):
                    die(f"OCI blob digest mismatch for {context}")
                return digest, bytes(content) if content is not None else None

            layout = read_json_member("oci-layout", "OCI layout descriptor")
            if layout != {"imageLayoutVersion": "1.0.0"}:
                die("OCI layout descriptor is not version 1.0.0")
            index = read_json_member("index.json", "OCI index")
            if index.get("schemaVersion") != 2:
                die("OCI index schemaVersion must be 2")
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                die("OCI archive must contain exactly one top-level manifest")
            top_descriptor = manifests[0]
            if not isinstance(top_descriptor, dict) or top_descriptor.get("mediaType") != (
                "application/vnd.oci.image.manifest.v1+json"
            ):
                die("OCI top-level descriptor must reference one OCI image manifest")
            digest, manifest_bytes = verify_descriptor(
                top_descriptor,
                "OCI image manifest descriptor",
                load_bytes=True,
            )
            assert manifest_bytes is not None
            try:
                manifest = json.loads(manifest_bytes)
            except (UnicodeError, json.JSONDecodeError) as exc:
                die(f"OCI image manifest is not valid JSON: {exc}")
            if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
                die("OCI image manifest schemaVersion must be 2")
            if manifest.get("mediaType") not in {
                None,
                "application/vnd.oci.image.manifest.v1+json",
            }:
                die("OCI image manifest mediaType is not canonical")
            verify_descriptor(manifest.get("config"), "OCI image config descriptor")
            layers = manifest.get("layers")
            if not isinstance(layers, list):
                die("OCI image manifest layers must be an array")
            for index_number, layer in enumerate(layers):
                verify_descriptor(layer, f"OCI image layer descriptor {index_number}")
    except (OSError, tarfile.TarError) as exc:
        die(f"invalid OCI archive: {exc}")
    return digest, archive_hash


def build_evidence(
    intent: dict[str, Any], archive: Path, release_control_sha: str
) -> dict[str, Any]:
    digest, archive_hash = inspect_oci_archive(archive)
    control_sha = require_string(
        release_control_sha, GIT_SHA, "release-control SHA"
    )
    return {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "release_control_sha": control_sha,
        "source": intent["source"],
        "artifact": {"repository": intent["artifact"]["repository"], "digest": digest},
        "oci_archive_sha256": archive_hash,
    }


def provenance_evidence(
    intent: dict[str, Any], archive: Path, release_control_sha: str
) -> dict[str, Any]:
    """Create the canonical SLSA v1 predicate that Cosign will wrap once."""

    digest, _ = inspect_oci_archive(archive)
    control_sha = require_string(
        release_control_sha, GIT_SHA, "release-control SHA"
    )
    source = _handoff_source(intent)
    artifact_repository = validate_artifact_repository(
        intent.get("artifact", {}).get("repository"), "artifact.repository"
    )
    version = require_string(intent.get("artifact", {}).get("version"), VERSION, "artifact.version")
    return {
        "buildDefinition": {
            "buildType": "https://arconath.com/release-control/build/v1",
            "externalParameters": {
                "source": source,
                "artifact": {
                    "repository": artifact_repository,
                    "version": version,
                    "digest": digest,
                },
            },
            "internalParameters": {"release_control_sha": control_sha},
            "resolvedDependencies": [
                {
                    "uri": f"git+https://github.com/{source['repository']}",
                    "digest": {
                        "gitCommit": source["commit_sha"],
                        "gitTree": source["tree_sha"],
                    },
                }
            ],
        },
        "runDetails": {
            "builder": {
                "id": "https://github.com/Arconath/release-control/.github/workflows/release.yml@refs/heads/main",
            },
            "metadata": {
                "invocationId": f"{intent['intent_id']}@{control_sha}",
            },
        },
    }


def verify_attestation_payload(
    envelope_path: Path,
    predicate_path: Path,
    predicate_type: str,
    artifact_repository: str,
    artifact_digest: str,
) -> None:
    """Bind Cosign's verified DSSE output to the exact local evidence file."""

    envelope = load_json(envelope_path)
    strict_keys(
        envelope,
        {"payloadType", "payload", "signatures"},
        "verified attestation envelope",
    )
    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        die("verified attestation payloadType is not in-toto JSON")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        die("verified attestation signature is missing")
    for index, signature in enumerate(signatures):
        if not isinstance(signature, dict):
            die(f"verified attestation signature {index} must be an object")
        unknown = sorted(set(signature) - {"keyid", "sig"})
        if unknown:
            die(
                f"verified attestation signature {index} unknown fields: "
                f"{', '.join(unknown)}"
            )
        if "keyid" in signature and not isinstance(signature["keyid"], str):
            die(f"verified attestation signature {index} keyid must be a string")
        encoded_signature = signature.get("sig")
        if not isinstance(encoded_signature, str) or not encoded_signature:
            die(f"verified attestation signature {index} is missing")
        try:
            base64.b64decode(encoded_signature, validate=True)
        except (ValueError, binascii.Error) as exc:
            die(f"verified attestation signature {index} is invalid: {exc}")
    payload = envelope.get("payload")
    if not isinstance(payload, str) or not payload:
        die("verified attestation payload is missing")
    try:
        statement_bytes = base64.b64decode(payload, validate=True)
        statement = json.loads(statement_bytes)
    except (ValueError, binascii.Error, UnicodeError, json.JSONDecodeError) as exc:
        die(f"verified attestation payload is invalid: {exc}")
    if not isinstance(statement, dict):
        die("verified attestation statement must be an object")
    strict_keys(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        "verified attestation statement",
    )
    if statement["_type"] not in {
        "https://in-toto.io/Statement/v0.1",
        "https://in-toto.io/Statement/v1",
    }:
        die("verified attestation statement type is not in-toto")
    if statement["predicateType"] != predicate_type:
        die("verified attestation predicate type does not match")
    repository = validate_artifact_repository(
        artifact_repository, "verified attestation artifact repository"
    )
    digest = require_nonzero_digest(
        artifact_digest, "verified attestation artifact digest"
    )
    subject = statement["subject"]
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        die("verified attestation must contain exactly one subject")
    strict_keys(subject[0], {"name", "digest"}, "verified attestation subject")
    if subject[0]["name"] != repository:
        die("verified attestation subject repository does not match")
    subject_digest = subject[0]["digest"]
    if not isinstance(subject_digest, dict):
        die("verified attestation subject digest must be an object")
    strict_keys(subject_digest, {"sha256"}, "verified attestation subject digest")
    if subject_digest["sha256"] != digest.removeprefix("sha256:"):
        die("verified attestation subject digest does not match")
    predicate = require_json_object(predicate_path, "attestation predicate")
    if statement["predicate"] != predicate:
        die("verified attestation predicate does not match the local evidence")


def validate_provenance_value(
    value: dict[str, Any],
    intent: dict[str, Any],
    artifact_digest: str,
    release_control_sha: str,
) -> None:
    strict_keys(
        value,
        {"buildDefinition", "runDetails"},
        "provenance predicate",
    )
    digest = require_nonzero_digest(artifact_digest, "provenance artifact digest")
    build_definition = value["buildDefinition"]
    if not isinstance(build_definition, dict):
        die("provenance buildDefinition must be an object")
    strict_keys(
        build_definition,
        {"buildType", "externalParameters", "internalParameters", "resolvedDependencies"},
        "provenance buildDefinition",
    )
    if build_definition["buildType"] != "https://arconath.com/release-control/build/v1":
        die("provenance build type is not canonical")
    external_parameters = build_definition["externalParameters"]
    if not isinstance(external_parameters, dict):
        die("provenance externalParameters must be an object")
    strict_keys(external_parameters, {"source", "artifact"}, "provenance externalParameters")
    if external_parameters["source"] != intent["source"]:
        die("provenance source does not match intent")
    artifact = external_parameters["artifact"]
    if not isinstance(artifact, dict):
        die("provenance predicate artifact must be an object")
    strict_keys(artifact, {"repository", "version", "digest"}, "provenance predicate artifact")
    if artifact["repository"] != intent["artifact"]["repository"]:
        die("provenance artifact repository does not match intent")
    if artifact["version"] != intent["artifact"]["version"]:
        die("provenance artifact version does not match intent")
    if artifact["digest"] != digest:
        die("provenance artifact digest does not match artifact")
    internal_parameters = build_definition["internalParameters"]
    if not isinstance(internal_parameters, dict):
        die("provenance internalParameters must be an object")
    strict_keys(internal_parameters, {"release_control_sha"}, "provenance internalParameters")
    if internal_parameters["release_control_sha"] != require_string(
        release_control_sha, GIT_SHA, "release-control SHA"
    ):
        die("provenance internal release-control SHA does not match")
    dependencies = build_definition["resolvedDependencies"]
    if not isinstance(dependencies, list) or len(dependencies) != 1 or not isinstance(dependencies[0], dict):
        die("provenance must contain exactly one resolved source dependency")
    dependency = dependencies[0]
    strict_keys(dependency, {"uri", "digest"}, "provenance resolved dependency")
    if dependency["uri"] != f"git+https://github.com/{intent['source']['repository']}":
        die("provenance source URI does not match intent")
    dependency_digest = dependency["digest"]
    if not isinstance(dependency_digest, dict):
        die("provenance source digest must be an object")
    strict_keys(dependency_digest, {"gitCommit", "gitTree"}, "provenance source digest")
    if dependency_digest != {
        "gitCommit": intent["source"]["commit_sha"],
        "gitTree": intent["source"]["tree_sha"],
    }:
        die("provenance source digest does not match intent")
    run_details = value["runDetails"]
    if not isinstance(run_details, dict):
        die("provenance runDetails must be an object")
    strict_keys(run_details, {"builder", "metadata"}, "provenance runDetails")
    builder = run_details["builder"]
    if not isinstance(builder, dict):
        die("provenance builder must be an object")
    strict_keys(builder, {"id"}, "provenance builder")
    if builder["id"] != "https://github.com/Arconath/release-control/.github/workflows/release.yml@refs/heads/main":
        die("provenance builder workflow is not canonical")
    metadata = run_details["metadata"]
    if not isinstance(metadata, dict):
        die("provenance metadata must be an object")
    strict_keys(metadata, {"invocationId"}, "provenance metadata")
    if metadata["invocationId"] != f"{intent['intent_id']}@{release_control_sha}":
        die("provenance invocation ID does not match release intent")


def validate_json_evidence(path: Path, key: str) -> dict[str, Any]:
    value = require_json_object(path, f"{key} evidence")
    if key == "sbom":
        if (
            not isinstance(value.get("spdxVersion"), str)
            or not re.fullmatch(r"SPDX-[0-9]+\.[0-9]+", value["spdxVersion"])
            or not isinstance(value.get("packages"), list)
            or not value["packages"]
        ):
            die("SBOM evidence is not an SPDX JSON document")
    elif key == "licenses":
        strict_keys(
            value,
            {"schema_version", "spdx_version", "package_count", "packages"},
            "license evidence",
        )
        if value["schema_version"] != 1:
            die("unsupported license evidence schema_version")
        spdx_version = value["spdx_version"]
        if not isinstance(spdx_version, str) or not re.fullmatch(
            r"SPDX-[0-9]+\.[0-9]+", spdx_version
        ):
            die("license evidence spdx_version is not canonical")
        packages = value["packages"]
        package_count = value["package_count"]
        if (
            isinstance(package_count, bool)
            or not isinstance(package_count, int)
            or package_count < 1
            or not isinstance(packages, list)
            or len(packages) != package_count
        ):
            die("license evidence package_count does not match packages")
        for index, package in enumerate(packages):
            context = f"license evidence packages[{index}]"
            if not isinstance(package, dict):
                die(f"{context} must be an object")
            strict_keys(package, {"name", "licenses"}, context)
            name = package["name"]
            if (
                not isinstance(name, str)
                or not name.strip()
                or "\r" in name
                or "\n" in name
            ):
                die(f"{context}.name must be a non-empty single-line string")
            licenses = package["licenses"]
            if (
                not isinstance(licenses, list)
                or len(licenses) != 1
                or not isinstance(licenses[0], str)
                or not licenses[0].strip()
                or licenses[0].strip() != licenses[0]
                or "\r" in licenses[0]
                or "\n" in licenses[0]
            ):
                die(f"{context}.licenses must contain exactly one asserted license string")
    elif key == "vulnerabilities":
        if not isinstance(value.get("matches"), list) or not isinstance(value.get("descriptor"), dict):
            die("vulnerability evidence is not a complete Grype report")
    return value


def validate_license_evidence_binding(
    sbom: dict[str, Any], licenses: dict[str, Any]
) -> None:
    """Require license evidence to preserve each SBOM licenseDeclared value exactly."""

    sbom_packages = sbom.get("packages")
    if not isinstance(sbom_packages, list) or not sbom_packages:
        die("SBOM evidence must contain packages before license binding")
    if licenses["spdx_version"] != sbom["spdxVersion"]:
        die("license evidence SPDX version does not match SBOM")
    if licenses["package_count"] != len(sbom_packages):
        die("license evidence package list does not match SBOM")
    for index, (sbom_package, license_package) in enumerate(
        zip(sbom_packages, licenses["packages"])
    ):
        context = f"SBOM package {index}"
        if not isinstance(sbom_package, dict):
            die(f"{context} must be an object before license binding")
        name = sbom_package.get("name")
        if not isinstance(name, str) or not name.strip() or "\r" in name or "\n" in name:
            die(f"{context} must have a canonical name before license binding")
        declared = sbom_package.get("licenseDeclared")
        if (
            not isinstance(declared, str)
            or not declared
            or declared.strip() != declared
            or declared in {"NONE", "NOASSERTION"}
            or "\r" in declared
            or "\n" in declared
        ):
            die(f"{context}.licenseDeclared must be an asserted SPDX value")
        if license_package["name"] != name:
            die("license evidence package list does not match SBOM")
        if license_package["licenses"] != [declared]:
            die(f"license evidence for {name} does not match SBOM licenseDeclared exactly")


def create_evidence_lock(
    intent: dict[str, Any],
    build_evidence_value: dict[str, Any],
    build_evidence_path: Path,
    archive: Path,
    sbom: Path,
    licenses: Path,
    provenance: Path,
    vulnerabilities: Path,
    release_control_sha: str,
) -> dict[str, Any]:
    """Bind all pre-publication evidence to one source/tree and OCI digest."""

    control_sha = require_string(
        release_control_sha, GIT_SHA, "release-control SHA"
    )
    validate_build_evidence(build_evidence_value, intent, control_sha)
    archive_digest, archive_hash = inspect_oci_archive(archive)
    if archive_hash != build_evidence_value["oci_archive_sha256"]:
        die("evidence lock archive SHA-256 differs from build evidence")
    if archive_digest != build_evidence_value["artifact"]["digest"]:
        die("evidence lock artifact digest differs from build evidence")
    sbom_value = validate_json_evidence(sbom, "sbom")
    licenses_value = validate_json_evidence(licenses, "licenses")
    validate_license_evidence_binding(sbom_value, licenses_value)
    provenance_value = validate_json_evidence(provenance, "provenance")
    validate_provenance_value(provenance_value, intent, archive_digest, control_sha)
    validate_json_evidence(vulnerabilities, "vulnerabilities")
    return {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "release_control_sha": control_sha,
        "source": intent["source"],
        "artifact": {
            "repository": intent["artifact"]["repository"],
            "digest": archive_digest,
            "reference": f"{intent['artifact']['repository']}@{archive_digest}",
            "version": intent["artifact"]["version"],
        },
        "oci_archive_sha256": archive_hash,
        "build_evidence": evidence_file(build_evidence_path, "build_evidence"),
        "evidence": {
            "sbom": evidence_file(sbom, "sbom"),
            "licenses": evidence_file(licenses, "licenses"),
            "provenance": evidence_file(provenance, "provenance"),
            "vulnerabilities": evidence_file(vulnerabilities, "vulnerabilities"),
        },
    }


def verify_evidence_lock(
    value: dict[str, Any],
    intent: dict[str, Any],
    *,
    release_control_sha: str,
    build_evidence_path: Path,
    archive: Path | None = None,
    evidence_dir: Path,
) -> None:
    require_directory(evidence_dir, "evidence directory")
    if build_evidence_path.name != EVIDENCE_FILE_NAMES["build_evidence"]:
        die("build evidence path is not canonical")
    try:
        if build_evidence_path.parent.resolve(strict=False) != evidence_dir.resolve(strict=True):
            die("build evidence path must be directly inside the evidence directory")
    except (OSError, RuntimeError) as exc:
        die(f"cannot resolve evidence paths: {exc}")
    strict_keys(
        value,
        {
            "schema_version",
            "intent_id",
            "release_control_sha",
            "source",
            "artifact",
            "oci_archive_sha256",
            "build_evidence",
            "evidence",
        },
        "evidence lock",
    )
    if value["schema_version"] != 1:
        die("unsupported evidence lock schema_version")
    if value["intent_id"] != intent["intent_id"]:
        die("evidence lock intent_id does not match intent")
    control_sha = require_string(release_control_sha, GIT_SHA, "release-control SHA")
    if value["release_control_sha"] != control_sha:
        die("evidence lock release-control SHA does not match")
    if value["source"] != intent["source"]:
        die("evidence lock source does not match intent")
    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        die("evidence lock artifact must be an object")
    strict_keys(artifact, {"repository", "digest", "reference", "version"}, "evidence lock artifact")
    if artifact["repository"] != intent["artifact"]["repository"]:
        die("evidence lock artifact repository does not match intent")
    digest = require_nonzero_digest(artifact["digest"], "evidence lock artifact digest")
    if artifact["reference"] != f"{artifact['repository']}@{digest}":
        die("evidence lock artifact reference is not digest exact")
    if artifact["version"] != intent["artifact"]["version"]:
        die("evidence lock artifact version does not match intent")
    require_string(
        value["oci_archive_sha256"],
        NONZERO_HEX_SHA256,
        "evidence lock OCI archive SHA-256",
    )
    validate_file_hash(value["build_evidence"], "build_evidence", expected_name="build-evidence.json")
    evidence = value["evidence"]
    if not isinstance(evidence, dict):
        die("evidence lock evidence must be an object")
    strict_keys(evidence, {"sbom", "licenses", "provenance", "vulnerabilities"}, "evidence lock evidence")
    for key in ("sbom", "licenses", "provenance", "vulnerabilities"):
        validate_file_hash(evidence[key], key)

    if sha256_file(build_evidence_path) != value["build_evidence"]["sha256"]:
        die("build evidence SHA-256 differs from evidence lock")
    build_evidence = load_json(build_evidence_path)
    require_canonical(build_evidence_path, build_evidence)
    validate_build_evidence(build_evidence, intent, control_sha)
    if build_evidence["artifact"]["digest"] != digest:
        die("build evidence digest differs from evidence lock")
    if build_evidence["oci_archive_sha256"] != value["oci_archive_sha256"]:
        die("build evidence archive hash differs from evidence lock")

    if archive is not None:
        archive_digest, archive_hash = inspect_oci_archive(archive)
        if archive_digest != digest:
            die("OCI archive digest differs from evidence lock")
        if archive_hash != value["oci_archive_sha256"]:
            die("OCI archive SHA-256 differs from evidence lock")

    for key in ("sbom", "licenses", "provenance", "vulnerabilities"):
        path = evidence_dir / evidence[key]["filename"]
        if sha256_file(path) != evidence[key]["sha256"]:
            die(f"{key} evidence SHA-256 differs from evidence lock")
    sbom_value = validate_json_evidence(evidence_dir / evidence["sbom"]["filename"], "sbom")
    licenses_value = validate_json_evidence(
        evidence_dir / evidence["licenses"]["filename"], "licenses"
    )
    validate_license_evidence_binding(sbom_value, licenses_value)
    provenance_value = validate_json_evidence(
        evidence_dir / evidence["provenance"]["filename"], "provenance"
    )
    validate_provenance_value(provenance_value, intent, digest, control_sha)
    validate_json_evidence(
        evidence_dir / evidence["vulnerabilities"]["filename"], "vulnerabilities"
    )


def _handoff_source(intent: dict[str, Any]) -> dict[str, Any]:
    source = intent.get("source")
    if not isinstance(source, dict):
        die("intent source must be an object for handoff")
    strict_keys(source, {"repository", "commit_sha", "tree_sha"}, "intent source")
    require_string(source["repository"], SOURCE_REPO, "intent source.repository")
    require_string(source["commit_sha"], SHA, "intent source.commit_sha")
    require_string(source["tree_sha"], SHA, "intent source.tree_sha")
    return source


def _validate_handoff_value(
    value: dict[str, Any],
    *,
    intent: dict[str, Any],
    kind: str,
    run_id: str,
    recipient: str,
) -> dict[str, Any]:
    if kind not in HANDOFF_FILES:
        die(f"unsupported handoff kind: {kind}")
    strict_keys(
        value,
        {
            "schema_version",
            "handoff_type",
            "intent_id",
            "run_id",
            "source",
            "plaintext_sha256",
            "ciphertext",
        },
        "source handoff",
    )
    if value["schema_version"] != 1:
        die("unsupported source handoff schema_version")
    if value["handoff_type"] != kind:
        die("source handoff type does not match the expected boundary")
    expected_intent_id = require_string(intent.get("intent_id"), INTENT_ID, "intent.intent_id")
    if value["intent_id"] != expected_intent_id:
        die("source handoff intent_id does not match intent")
    expected_run_id = require_string(run_id, RUN_ID, "GitHub run id")
    if value["run_id"] != expected_run_id:
        die("source handoff run_id does not match this workflow run")
    source = _handoff_source(intent)
    if value["source"] != source:
        die("source handoff source identity does not match intent")
    require_string(
        value["plaintext_sha256"],
        NONZERO_HEX_SHA256,
        "source handoff plaintext SHA-256",
    )

    ciphertext = value["ciphertext"]
    if not isinstance(ciphertext, dict):
        die("source handoff ciphertext must be an object")
    strict_keys(
        ciphertext,
        {"filename", "sha256", "encryption", "recipient"},
        "source handoff ciphertext",
    )
    expected_filename = HANDOFF_FILES[kind]
    if ciphertext["filename"] != expected_filename:
        die("source handoff ciphertext filename is not canonical")
    require_string(
        ciphertext["sha256"],
        NONZERO_HEX_SHA256,
        "source handoff ciphertext SHA-256",
    )
    if ciphertext["encryption"] != "age-v1":
        die("source handoff encryption must be age-v1")
    require_string(ciphertext["recipient"], AGE_RECIPIENT, "source handoff age recipient")
    expected_recipient = require_string(recipient, AGE_RECIPIENT, "configured age recipient")
    if ciphertext["recipient"] != expected_recipient:
        die("source handoff recipient does not match the configured key")
    return value


def create_handoff(
    intent: dict[str, Any],
    *,
    kind: str,
    run_id: str,
    plaintext: Path,
    ciphertext: Path,
    recipient: str,
) -> dict[str, Any]:
    if kind not in HANDOFF_FILES:
        die(f"unsupported handoff kind: {kind}")
    require_string(run_id, RUN_ID, "GitHub run id")
    require_string(recipient, AGE_RECIPIENT, "configured age recipient")
    expected_name = HANDOFF_FILES[kind]
    if ciphertext.name != expected_name:
        die(f"source handoff ciphertext must be named {expected_name}")
    if plaintext.name != HANDOFF_PLAINTEXT_FILES[kind]:
        die(f"source handoff plaintext must be named {HANDOFF_PLAINTEXT_FILES[kind]}")
    if not plaintext.is_file() or not ciphertext.is_file():
        die("source handoff plaintext and ciphertext must be regular files")
    value = {
        "schema_version": 1,
        "handoff_type": kind,
        "intent_id": require_string(intent.get("intent_id"), INTENT_ID, "intent.intent_id"),
        "run_id": run_id,
        "source": _handoff_source(intent),
        "plaintext_sha256": sha256_file(plaintext),
        "ciphertext": {
            "filename": expected_name,
            "sha256": sha256_file(ciphertext),
            "encryption": "age-v1",
            "recipient": recipient,
        },
    }
    _validate_handoff_value(
        value,
        intent=intent,
        kind=kind,
        run_id=run_id,
        recipient=recipient,
    )
    return value


def verify_handoff(
    handoff_path: Path,
    ciphertext_path: Path,
    intent_path: Path,
    *,
    kind: str,
    run_id: str,
    recipient: str,
    plaintext_path: Path | None = None,
) -> None:
    intent = load_json(intent_path)
    require_canonical(intent_path, intent)
    value = load_json(handoff_path)
    require_canonical(handoff_path, value)
    _validate_handoff_value(
        value,
        intent=intent,
        kind=kind,
        run_id=run_id,
        recipient=recipient,
    )
    expected_name = HANDOFF_FILES[kind]
    if ciphertext_path.name != expected_name:
        die("source handoff ciphertext path is not canonical")
    if not ciphertext_path.is_file() or ciphertext_path.is_symlink():
        die("source handoff ciphertext must be a regular file")
    if sha256_file(ciphertext_path) != value["ciphertext"]["sha256"]:
        die("source handoff ciphertext SHA-256 differs from its envelope")
    if plaintext_path is not None:
        if plaintext_path.name != HANDOFF_PLAINTEXT_FILES[kind]:
            die("decrypted source handoff path is not canonical")
        if not plaintext_path.is_file() or plaintext_path.is_symlink():
            die("decrypted source handoff must be a regular file")
        if sha256_file(plaintext_path) != value["plaintext_sha256"]:
            die("decrypted source handoff SHA-256 differs from its envelope")


def validate_build_evidence(
    value: dict[str, Any], intent: dict[str, Any], expected_control_sha: str | None = None
) -> None:
    strict_keys(
        value,
        {
            "schema_version",
            "intent_id",
            "release_control_sha",
            "source",
            "artifact",
            "oci_archive_sha256",
        },
        "build evidence",
    )
    if value["schema_version"] != 1 or value["intent_id"] != intent["intent_id"]:
        die("build evidence identity does not match intent")
    control_sha = require_string(
        value["release_control_sha"], GIT_SHA, "build evidence release-control SHA"
    )
    if expected_control_sha is not None and control_sha != require_string(
        expected_control_sha, GIT_SHA, "release-control SHA"
    ):
        die("build evidence release-control SHA does not match the protected workflow SHA")
    source = value["source"]
    if not isinstance(source, dict):
        die("build evidence source must be an object")
    strict_keys(source, {"repository", "commit_sha", "tree_sha"}, "build evidence source")
    require_string(source["repository"], SOURCE_REPO, "build evidence source.repository")
    require_string(source["commit_sha"], SHA, "build evidence source.commit_sha")
    require_string(source["tree_sha"], SHA, "build evidence source.tree_sha")
    if source != intent["source"]:
        die("build evidence source does not match intent")
    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        die("build evidence artifact must be an object")
    strict_keys(artifact, {"repository", "digest"}, "build evidence artifact")
    if artifact["repository"] != intent["artifact"]["repository"]:
        die("build evidence artifact repository does not match intent")
    require_nonzero_digest(artifact["digest"], "build evidence artifact digest")
    require_string(value["oci_archive_sha256"], NONZERO_HEX_SHA256, "OCI archive SHA-256")


def verify_published(
    intent: dict[str, Any],
    evidence: dict[str, Any],
    archive: Path,
    published_digest: str,
    release_control_sha: str,
) -> dict[str, Any]:
    if not GIT_SHA.fullmatch(release_control_sha):
        die("release-control SHA must be a 40-character lowercase Git SHA")
    validate_build_evidence(evidence, intent, release_control_sha)
    require_nonzero_digest(published_digest, "published digest")
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
        "release_control_sha": release_control_sha,
        "source": intent["source"],
        "artifact": {
            "repository": intent["artifact"]["repository"],
            "digest": published_digest,
            "reference": f"{intent['artifact']['repository']}@{published_digest}",
            "version": intent["artifact"]["version"],
        },
        "oci_archive_sha256": archive_hash,
    }


def _validate_release_record_base(
    intent: dict[str, Any],
    record: dict[str, Any],
    *,
    expected_digest: str | None = None,
    release_control_sha: str | None = None,
    require_evidence: bool,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "intent_id",
        "release_control_sha",
        "source",
        "artifact",
        "oci_archive_sha256",
    }
    if require_evidence:
        required.add("evidence")
    strict_keys(record, required, "release record")
    if record["schema_version"] != 1:
        die("unsupported release record schema_version")
    if record["intent_id"] != intent["intent_id"] or record["source"] != intent["source"]:
        die("release record identity does not match intent")
    record_control_sha = require_string(
        record["release_control_sha"], GIT_SHA, "release record release-control SHA"
    )
    if release_control_sha is not None and record_control_sha != require_string(
        release_control_sha, GIT_SHA, "release-control SHA"
    ):
        die("release record release-control SHA does not match the protected workflow SHA")
    artifact = record["artifact"]
    if not isinstance(artifact, dict):
        die("release record artifact missing")
    strict_keys(artifact, {"repository", "digest", "reference", "version"}, "release record artifact")
    digest = require_nonzero_digest(artifact["digest"], "release record digest")
    if expected_digest is not None and digest != require_string(
        expected_digest, NONZERO_DIGEST, "expected published digest"
    ):
        die("release record digest does not match publish job output")
    if artifact["repository"] != intent["artifact"]["repository"]:
        die("release record artifact repository does not match intent")
    if artifact["reference"] != f"{artifact['repository']}@{digest}":
        die("release record artifact reference is not digest exact")
    if artifact["version"] != intent["artifact"]["version"]:
        die("release record version does not match intent")
    require_string(
        record["oci_archive_sha256"],
        NONZERO_HEX_SHA256,
        "release record OCI archive SHA-256",
    )
    if require_evidence:
        _validate_release_evidence_map(record["evidence"])
    return record


def _validate_release_evidence_map(value: Any) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict):
        die("release record evidence must be an object")
    strict_keys(value, set(RELEASE_EVIDENCE_KEYS), "release record evidence")
    return {
        key: validate_file_hash(value[key], key)
        for key in RELEASE_EVIDENCE_KEYS
    }


def finalize_release(
    intent: dict[str, Any],
    record: dict[str, Any],
    evidence_dir: Path,
    archive: Path,
    release_control_sha: str,
) -> dict[str, Any]:
    """Attach and verify signature/attestation evidence after publication."""

    _validate_release_record_base(
        intent, record, release_control_sha=release_control_sha, require_evidence=False
    )
    lock_path = evidence_dir / EVIDENCE_FILE_NAMES["lock"]
    build_evidence_path = evidence_dir / EVIDENCE_FILE_NAMES["build_evidence"]
    lock = load_json(lock_path)
    require_canonical(lock_path, lock)
    verify_evidence_lock(
        lock,
        intent,
        release_control_sha=release_control_sha,
        build_evidence_path=build_evidence_path,
        archive=archive,
        evidence_dir=evidence_dir,
    )
    if lock["artifact"]["digest"] != record["artifact"]["digest"]:
        die("evidence lock digest does not match release record")
    if lock["oci_archive_sha256"] != record["oci_archive_sha256"]:
        die("evidence lock archive hash does not match release record")
    evidence: dict[str, dict[str, str]] = {
        "lock": evidence_file(lock_path, "lock"),
        **lock["evidence"],
    }
    for key in (
        "artifact_signature",
        "build_evidence_attestation",
        "license_attestation",
        "sbom_attestation",
        "provenance_attestation",
        "vulnerability_attestation",
    ):
        evidence[key] = evidence_file(evidence_dir / EVIDENCE_FILE_NAMES[key], key)
    return {**record, "evidence": _validate_release_evidence_map(evidence)}


def validate_release_bundle_files(
    intent: dict[str, Any],
    record: dict[str, Any],
    evidence_dir: Path,
    release_control_sha: str,
) -> None:
    """Verify every downloaded evidence file before manifest emission."""

    _validate_release_record_base(
        intent,
        record,
        release_control_sha=release_control_sha,
        require_evidence=True,
    )
    evidence = record["evidence"]
    lock_path = evidence_dir / evidence["lock"]["filename"]
    build_evidence_path = evidence_dir / EVIDENCE_FILE_NAMES["build_evidence"]
    lock = load_json(lock_path)
    require_canonical(lock_path, lock)
    verify_evidence_lock(
        lock,
        intent,
        release_control_sha=release_control_sha,
        build_evidence_path=build_evidence_path,
        evidence_dir=evidence_dir,
    )
    if sha256_file(lock_path) != evidence["lock"]["sha256"]:
        die("evidence lock SHA-256 differs from release record")
    if lock["artifact"] != record["artifact"]:
        die("evidence lock artifact does not match release record")
    if lock["oci_archive_sha256"] != record["oci_archive_sha256"]:
        die("evidence lock archive hash does not match release record")
    for key in RELEASE_EVIDENCE_KEYS:
        path = evidence_dir / evidence[key]["filename"]
        if sha256_file(path) != evidence[key]["sha256"]:
            die(f"{key} evidence SHA-256 differs from release record")
        if key not in {"sbom", "licenses", "provenance", "vulnerabilities", "lock"}:
            require_json_object(path, f"{key} evidence")


def release_manifests(
    intent: dict[str, Any],
    record: dict[str, Any],
    expected_digest: str | None = None,
    release_control_sha: str | None = None,
    *,
    evidence_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_release_record_base(
        intent,
        record,
        expected_digest=expected_digest,
        release_control_sha=release_control_sha,
        require_evidence=True,
    )
    validate_release_bundle_files(
        intent,
        record,
        evidence_dir,
        record["release_control_sha"],
    )
    record_control_sha = record["release_control_sha"]
    artifact = record["artifact"]
    digest = artifact["digest"]
    previous = intent["rollback"]["previous_digest"]
    if digest == previous:
        die("rollback digest must differ from the released digest")
    promotion = {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "release_control_sha": record_control_sha,
        "source": intent["source"],
        "artifact": {
            "repository": artifact["repository"],
            "digest": digest,
            "reference": f"{artifact['repository']}@{digest}",
            "version": intent["artifact"]["version"],
        },
        "evidence": record["evidence"],
        "rollback_digest": previous,
    }
    rollback = {
        "schema_version": 1,
        "intent_id": intent["intent_id"],
        "release_control_sha": record_control_sha,
        "source": intent["source"],
        "artifact_repository": artifact["repository"],
        "evidence": record["evidence"],
        "replace_digest": digest,
        "restore_digest": previous,
        "reason": intent["rollback"]["reason"],
    }
    return promotion, rollback


def artifact_lock_proposal(
    intent: dict[str, Any],
    policy: dict[str, Any],
    record: dict[str, Any],
    *,
    expected_digest: str | None = None,
    release_control_sha: str | None = None,
    evidence_dir: Path,
) -> dict[str, Any]:
    """Emit a reviewed GitOps proposal without mutating desired state.

    Release-control can prove image identity and supply-chain evidence.  It
    cannot prove environment readiness, backup/restore, or rollout health, so
    deployment eligibility remains false until platform-apps review adds that
    independent evidence.
    """

    validate_policy(policy)
    if policy.get("product_id") not in CANONICAL_PRODUCTS:
        die("artifact-lock proposals require a canonical product policy")
    issued = parse_time(intent.get("issued_at"), "issued_at")
    validate_intent_value(intent, policy, now=issued + dt.timedelta(seconds=1))
    promotion, _ = release_manifests(
        intent,
        record,
        expected_digest,
        release_control_sha,
        evidence_dir=evidence_dir,
    )
    binding = policy["artifact_lock"]
    return {
        "schema_version": 1,
        "proposal_only": True,
        "deployment_eligibility": False,
        "policy_id": policy["policy_id"],
        "target": {
            "repository": binding["repository"],
            "product_id": policy["product_id"],
            "artifact_lock_key": binding["key"],
            "desired_state_path": binding["desired_state_path"],
            "workloads": binding["workloads"],
        },
        "release": {
            "intent_id": promotion["intent_id"],
            "release_control_sha": promotion["release_control_sha"],
            "source": promotion["source"],
            "artifact": promotion["artifact"],
            "evidence": promotion["evidence"],
        },
        "rollback": {
            "digest": promotion["rollback_digest"],
            "reason": intent["rollback"]["reason"],
        },
    }


def write_json(path: Path, value: Any) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        die(f"output must be a regular non-symlink file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def utc_now(value: str | None) -> dt.datetime:
    if value:
        return parse_time(value, "now")
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def emit_outputs(path: Path, intent: dict[str, Any], policy: dict[str, Any]) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        die(f"workflow output must be a regular non-symlink file: {path}")
    build_args = policy["build"].get("build_args", {})
    if not isinstance(build_args, dict):
        die("validated policy build arguments must be an object")
    identity_values = {
        "created": intent["issued_at"],
        "revision": intent["source"]["commit_sha"],
        "version": intent["artifact"]["version"],
    }
    identity_args: dict[str, str] = {}
    for kind, names in policy["build"].get("identity_args", {}).items():
        for name in names:
            identity_args[name] = identity_values[kind]
    outputs = {
        "intent-id": intent["intent_id"],
        "policy-id": policy["policy_id"],
        "product-id": policy.get("product_id", ""),
        "source-repository": intent["source"]["repository"],
        "source-name": intent["source"]["repository"].split("/", 1)[1],
        "source-sha": intent["source"]["commit_sha"],
        "source-tree": intent["source"]["tree_sha"],
        "artifact-repository": intent["artifact"]["repository"],
        "registry-host": policy["registry_host"],
        "context": policy["build"]["context"],
        "dockerfile": policy["build"]["dockerfile"],
        "platform": policy["build"]["platform"],
        "build-args-json": json.dumps(build_args, sort_keys=True, separators=(",", ":")),
        "identity-build-args-json": json.dumps(
            identity_args, sort_keys=True, separators=(",", ":")
        ),
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

    policy_set_parser = sub.add_parser("validate-policy-set")
    policy_set_parser.add_argument("--policy-dir", type=Path, required=True)

    governance_parser = sub.add_parser("validate-governance")
    governance_parser.add_argument("--codeowners", type=Path, required=True)
    governance_parser.add_argument("--allowed-signers", type=Path, required=True)
    governance_parser.add_argument("--settings", type=Path, required=True)
    governance_parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="print checked-in readiness diagnostics without allowing an incomplete release",
    )

    readiness_parser = sub.add_parser(
        "merge-readiness",
        help="diagnose checked-in merge gates without inspecting live GitHub configuration",
    )
    readiness_parser.add_argument("--codeowners", type=Path, required=True)
    readiness_parser.add_argument("--allowed-signers", type=Path, required=True)
    readiness_parser.add_argument("--settings", type=Path, required=True)
    readiness_parser.add_argument("--policy-dir", type=Path, required=True)
    readiness_parser.add_argument("--contract-dir", type=Path, required=True)
    readiness_parser.add_argument("--workflow-dir", type=Path, required=True)
    readiness_parser.add_argument(
        "--require-ready",
        action="store_true",
        help="return failure when any checked-in merge gate is blocked",
    )

    intent_parser = sub.add_parser("validate-intent")
    intent_parser.add_argument("--intent", type=Path, required=True)
    intent_parser.add_argument(
        "--signature", dest="signatures", type=Path, action="append", required=True
    )
    intent_parser.add_argument("--allowed-signers", type=Path, required=True)
    intent_parser.add_argument("--policy-dir", type=Path, required=True)
    intent_parser.add_argument("--now")
    intent_parser.add_argument("--github-output", type=Path)

    evidence_parser = sub.add_parser("build-evidence")
    evidence_parser.add_argument("--intent", type=Path, required=True)
    evidence_parser.add_argument("--archive", type=Path, required=True)
    evidence_parser.add_argument("--release-control-sha", required=True)
    evidence_parser.add_argument("--output", type=Path, required=True)

    provenance_parser = sub.add_parser("build-provenance")
    provenance_parser.add_argument("--intent", type=Path, required=True)
    provenance_parser.add_argument("--archive", type=Path, required=True)
    provenance_parser.add_argument("--release-control-sha", required=True)
    provenance_parser.add_argument("--output", type=Path, required=True)

    lock_parser = sub.add_parser("create-evidence-lock")
    lock_parser.add_argument("--intent", type=Path, required=True)
    lock_parser.add_argument("--build-evidence", type=Path, required=True)
    lock_parser.add_argument("--archive", type=Path, required=True)
    lock_parser.add_argument("--sbom", type=Path, required=True)
    lock_parser.add_argument("--licenses", type=Path, required=True)
    lock_parser.add_argument("--provenance", type=Path, required=True)
    lock_parser.add_argument("--vulnerabilities", type=Path, required=True)
    lock_parser.add_argument("--release-control-sha", required=True)
    lock_parser.add_argument("--output", type=Path, required=True)

    verify_lock_parser = sub.add_parser("verify-evidence-lock")
    verify_lock_parser.add_argument("--intent", type=Path, required=True)
    verify_lock_parser.add_argument("--lock", type=Path, required=True)
    verify_lock_parser.add_argument("--build-evidence", type=Path, required=True)
    verify_lock_parser.add_argument("--archive", type=Path, required=True)
    verify_lock_parser.add_argument("--evidence-dir", type=Path, required=True)
    verify_lock_parser.add_argument("--release-control-sha", required=True)

    finalize_parser = sub.add_parser("finalize-release")
    finalize_parser.add_argument("--intent", type=Path, required=True)
    finalize_parser.add_argument("--release-record", type=Path, required=True)
    finalize_parser.add_argument("--evidence-dir", type=Path, required=True)
    finalize_parser.add_argument("--archive", type=Path, required=True)
    finalize_parser.add_argument("--release-control-sha", required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)

    attestation_parser = sub.add_parser("verify-attestation-payload")
    attestation_parser.add_argument("--envelope", type=Path, required=True)
    attestation_parser.add_argument("--predicate", type=Path, required=True)
    attestation_parser.add_argument("--predicate-type", required=True)
    attestation_parser.add_argument("--artifact-repository", required=True)
    attestation_parser.add_argument("--artifact-digest", required=True)

    create_handoff_parser = sub.add_parser("create-handoff")
    create_handoff_parser.add_argument("--kind", choices=sorted(HANDOFF_FILES), required=True)
    create_handoff_parser.add_argument("--intent", type=Path, required=True)
    create_handoff_parser.add_argument("--run-id", required=True)
    create_handoff_parser.add_argument("--plaintext", type=Path, required=True)
    create_handoff_parser.add_argument("--ciphertext", type=Path, required=True)
    create_handoff_parser.add_argument("--recipient", required=True)
    create_handoff_parser.add_argument("--output", type=Path, required=True)

    verify_handoff_parser = sub.add_parser("verify-handoff")
    verify_handoff_parser.add_argument("--kind", choices=sorted(HANDOFF_FILES), required=True)
    verify_handoff_parser.add_argument("--handoff", type=Path, required=True)
    verify_handoff_parser.add_argument("--intent", type=Path, required=True)
    verify_handoff_parser.add_argument("--run-id", required=True)
    verify_handoff_parser.add_argument("--ciphertext", type=Path, required=True)
    verify_handoff_parser.add_argument("--recipient", required=True)
    verify_handoff_parser.add_argument("--plaintext", type=Path)

    verify_parser = sub.add_parser("verify-published")
    verify_parser.add_argument("--intent", type=Path, required=True)
    verify_parser.add_argument("--evidence", type=Path, required=True)
    verify_parser.add_argument("--archive", type=Path, required=True)
    verify_parser.add_argument("--published-digest", required=True)
    verify_parser.add_argument("--release-control-sha", required=True)
    verify_parser.add_argument("--output", type=Path, required=True)

    manifest_parser = sub.add_parser("emit-manifests")
    manifest_parser.add_argument("--intent", type=Path, required=True)
    manifest_parser.add_argument("--release-record", type=Path, required=True)
    manifest_parser.add_argument("--promotion", type=Path, required=True)
    manifest_parser.add_argument("--rollback", type=Path, required=True)
    manifest_parser.add_argument("--artifact-lock-proposal", type=Path, required=True)
    manifest_parser.add_argument("--policy", type=Path, required=True)
    manifest_parser.add_argument("--expected-digest", required=True)
    manifest_parser.add_argument("--release-control-sha", required=True)
    manifest_parser.add_argument("--evidence-dir", type=Path, required=True)

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
        elif args.command == "validate-policy-set":
            validate_policy_set(args.policy_dir)
        elif args.command == "validate-governance":
            readiness = validate_governance(
                args.codeowners,
                args.allowed_signers,
                args.settings,
                require_ready=not args.allow_incomplete,
            )
            if args.allow_incomplete:
                print(json.dumps(readiness, sort_keys=True, separators=(",", ":")))
        elif args.command == "merge-readiness":
            readiness = merge_readiness(
                args.codeowners,
                args.allowed_signers,
                args.settings,
                args.policy_dir,
                args.contract_dir,
                args.workflow_dir,
            )
            print(json.dumps(readiness, sort_keys=True, separators=(",", ":")))
            if args.require_ready and not readiness["merge_ready"]:
                die("merge-readiness is blocked")
        elif args.command == "validate-intent":
            intent, policy = validate_intent(
                args.intent,
                args.signatures,
                args.allowed_signers,
                args.policy_dir,
                utc_now(args.now),
            )
            if args.github_output:
                emit_outputs(args.github_output, intent, policy)
        elif args.command == "build-evidence":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            write_json(
                args.output,
                build_evidence(intent, args.archive, args.release_control_sha),
            )
        elif args.command == "build-provenance":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            write_json(
                args.output,
                provenance_evidence(intent, args.archive, args.release_control_sha),
            )
        elif args.command == "create-evidence-lock":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            build_evidence_value = load_json(args.build_evidence)
            require_canonical(args.build_evidence, build_evidence_value)
            write_json(
                args.output,
                create_evidence_lock(
                    intent,
                    build_evidence_value,
                    args.build_evidence,
                    args.archive,
                    args.sbom,
                    args.licenses,
                    args.provenance,
                    args.vulnerabilities,
                    args.release_control_sha,
                ),
            )
        elif args.command == "verify-evidence-lock":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            lock = load_json(args.lock)
            require_canonical(args.lock, lock)
            verify_evidence_lock(
                lock,
                intent,
                release_control_sha=args.release_control_sha,
                build_evidence_path=args.build_evidence,
                archive=args.archive,
                evidence_dir=args.evidence_dir,
            )
        elif args.command == "finalize-release":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            record = load_json(args.release_record)
            require_canonical(args.release_record, record)
            write_json(
                args.output,
                finalize_release(
                    intent,
                    record,
                    args.evidence_dir,
                    args.archive,
                    args.release_control_sha,
                ),
            )
        elif args.command == "verify-attestation-payload":
            verify_attestation_payload(
                args.envelope,
                args.predicate,
                args.predicate_type,
                args.artifact_repository,
                args.artifact_digest,
            )
        elif args.command == "create-handoff":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            write_json(
                args.output,
                create_handoff(
                    intent,
                    kind=args.kind,
                    run_id=args.run_id,
                    plaintext=args.plaintext,
                    ciphertext=args.ciphertext,
                    recipient=args.recipient,
                ),
            )
        elif args.command == "verify-handoff":
            verify_handoff(
                args.handoff,
                args.ciphertext,
                args.intent,
                kind=args.kind,
                run_id=args.run_id,
                recipient=args.recipient,
                plaintext_path=args.plaintext,
            )
        elif args.command == "verify-published":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            evidence = load_json(args.evidence)
            require_canonical(args.evidence, evidence)
            write_json(
                args.output,
                verify_published(
                    intent,
                    evidence,
                    args.archive,
                    args.published_digest,
                    args.release_control_sha,
                ),
            )
        elif args.command == "emit-manifests":
            intent = load_json(args.intent)
            require_canonical(args.intent, intent)
            record = load_json(args.release_record)
            require_canonical(args.release_record, record)
            policy = load_json(args.policy)
            require_canonical(args.policy, policy)
            promotion, rollback = release_manifests(
                intent,
                record,
                args.expected_digest,
                args.release_control_sha,
                evidence_dir=args.evidence_dir,
            )
            write_json(args.promotion, promotion)
            write_json(args.rollback, rollback)
            write_json(
                args.artifact_lock_proposal,
                artifact_lock_proposal(
                    intent,
                    policy,
                    record,
                    expected_digest=args.expected_digest,
                    release_control_sha=args.release_control_sha,
                    evidence_dir=args.evidence_dir,
                ),
            )
        elif args.command == "run-policy":
            policy = load_json(args.policy)
            require_canonical(args.policy, policy)
            run_policy(policy, args.source)
        return 0
    except ContractError as exc:
        print(f"release-control: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"release-control: fail-closed operating-system error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
