#!/usr/bin/env python3
"""Strict release identity and digest contracts for Arconath release-control."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IDENT = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,127}$")
POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
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
ZERO_DIGEST = "sha256:" + "0" * 64
NAMESPACE = "arconath-release-intent"
HANDOFF_FILES = {
    "source": "product.tar.age",
    "candidate": "candidate.oci.tar.age",
}
HANDOFF_PLAINTEXT_FILES = {
    "source": "product.tar",
    "candidate": "candidate.oci.tar",
}


class ContractError(ValueError):
    """A fail-closed contract validation error."""


def die(message: str) -> None:
    raise ContractError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot load JSON {path}: {exc}")
    if not isinstance(value, dict):
        die(f"JSON document must be an object: {path}")
    return value


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        die(f"cannot read file {path}: {exc}")
    return digest.hexdigest()


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
    if registry_host != CANONICAL_REGISTRY_HOST:
        die(
            "registry_host must be the canonical internal Distribution host: "
            f"{CANONICAL_REGISTRY_HOST}"
        )
    if not value["artifact_repository"].startswith(f"{registry_host}/"):
        die("artifact_repository must be hosted by registry_host")
    if not value["artifact_repository"].startswith(CANONICAL_ARTIFACT_PREFIX):
        die("artifact_repository must use the canonical arconath/ namespace")
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
    require_two_operator_keys(allowed)
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


def require_two_operator_keys(allowed: Path) -> None:
    """Require two distinct named operator keys before any release can verify.

    GitHub branch protection supplies the second human review for the change
    that adds an intent.  This local check prevents a future repository
    configuration from silently reducing the cryptographic operator set to a
    single key.  We intentionally inspect only public key metadata and never
    include key material in an error message.
    """

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

    if len(operator_keys) < 2 or len(operator_identities) < 2:
        die("at least two distinct named operator keys are required")


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
    require_string(value["plaintext_sha256"], re.compile(r"^[0-9a-f]{64}$"), "source handoff plaintext SHA-256")

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
    require_string(ciphertext["sha256"], re.compile(r"^[0-9a-f]{64}$"), "source handoff ciphertext SHA-256")
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
    intent: dict[str, Any],
    evidence: dict[str, Any],
    archive: Path,
    published_digest: str,
    release_control_sha: str,
) -> dict[str, Any]:
    if not GIT_SHA.fullmatch(release_control_sha):
        die("release-control SHA must be a 40-character lowercase Git SHA")
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


def release_manifests(
    intent: dict[str, Any],
    record: dict[str, Any],
    expected_digest: str | None = None,
    release_control_sha: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    strict_keys(
        record,
        {"schema_version", "intent_id", "release_control_sha", "source", "artifact", "oci_archive_sha256"},
        "release record",
    )
    if record["schema_version"] != 1:
        die("unsupported release record schema_version")
    if record.get("intent_id") != intent["intent_id"] or record.get("source") != intent["source"]:
        die("release record identity does not match intent")
    record_control_sha = record.get("release_control_sha")
    if not isinstance(record_control_sha, str) or not GIT_SHA.fullmatch(record_control_sha):
        die("release record release-control SHA is invalid")
    if release_control_sha is not None:
        if not GIT_SHA.fullmatch(release_control_sha):
            die("release-control SHA must be a 40-character lowercase Git SHA")
        if record_control_sha != release_control_sha:
            die("release record release-control SHA does not match the protected workflow SHA")
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
        "release_control_sha": record_control_sha,
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
        "release_control_sha": record_control_sha,
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
    manifest_parser.add_argument("--expected-digest", required=True)
    manifest_parser.add_argument("--release-control-sha", required=True)

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
            write_json(
                args.output,
                verify_published(
                    load_json(args.intent),
                    load_json(args.evidence),
                    args.archive,
                    args.published_digest,
                    args.release_control_sha,
                ),
            )
        elif args.command == "emit-manifests":
            promotion, rollback = release_manifests(
                load_json(args.intent),
                load_json(args.release_record),
                args.expected_digest,
                args.release_control_sha,
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
