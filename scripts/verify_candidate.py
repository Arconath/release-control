#!/usr/bin/env python3
"""Validate a candidate checkout with code from the trusted base only.

The candidate checkout is untrusted data.  This module never imports or
executes a candidate file.  It binds both checkouts to the caller-supplied
commit and tree identities, creates one immutable archive from the candidate
commit, safely materializes that archive, and validates only the materialized
bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Optional


REPOSITORY = "Arconath/release-control"
SHA = re.compile(r"^[0-9a-f]{40}$")
VALIDATION_WORKFLOW = ".github/workflows/validate.yml"
VERIFY_SCRIPT = "scripts/verify.sh"
VALIDATOR_SCRIPT = "scripts/verify_candidate.py"
WORKFLOW_DIRECTORY = ".github/workflows"

# This is the exact Stage0 workflow allowlist.  The semantic checks below make
# the policy legible; the digest closes whitespace, YAML alias, and obfuscation
# gaps that a fragment-only check would leave open.
EXPECTED_VALIDATION_WORKFLOW_SHA256 = "f4dfe282896fbdf76e07142f637c4fdbf4eaf80980b00c5f1dd45131dca6dbc2"


class ValidationError(ValueError):
    """A fail-closed candidate-boundary error."""


def fail(message: str) -> None:
    raise ValidationError(message)


def require_sha(value: str, context: str) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        fail(f"{context} must be a 40-character lowercase SHA")
    return value


def require_repository(value: str, context: str) -> str:
    if value != REPOSITORY:
        fail(f"{context} must be {REPOSITORY}")
    return value


def regular_directory(path: Path, context: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"{context} cannot be inspected: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{context} must be a regular non-symlink directory")
    try:
        path.resolve(strict=True)
    except OSError as exc:
        fail(f"{context} cannot be resolved: {exc}")
    return path


def regular_file(path: Path, context: str, *, required: bool = True) -> Optional[Path]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not required:
            return None
        fail(f"{context} is missing")
    except OSError as exc:
        fail(f"{context} cannot be inspected: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{context} must be a regular non-symlink file")
    return path


def read_regular_file(path: Path, context: str, *, required: bool = True) -> Optional[bytes]:
    checked = regular_file(path, context, required=required)
    if checked is None:
        return None
    try:
        descriptor = os.open(checked, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            fail(f"{context} must remain a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            return stream.read()
    except OSError as exc:
        fail(f"{context} cannot be read: {exc}")
    return None


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }


def git_command(
    root: Path,
    arguments: list[str],
    context: str,
    *,
    stdout: Any = subprocess.PIPE,
) -> bytes:
    regular_directory(root, context)
    command = [
        "git",
        "--no-optional-locks",
        "-C",
        str(root),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            env=git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        fail(f"{context} Git command could not be completed")
    if result.returncode:
        fail(f"{context} Git command could not be completed")
    if stdout is subprocess.PIPE:
        return result.stdout
    return b""


def git_identity(root: Path, expected_sha: str, expected_tree: str, context: str) -> tuple[str, str]:
    expected_sha = require_sha(expected_sha, f"{context} expected commit")
    expected_tree = require_sha(expected_tree, f"{context} expected tree")
    try:
        commit = git_command(root, ["rev-parse", "--verify", "HEAD^{commit}"], context)
        tree = git_command(root, ["rev-parse", "--verify", "HEAD^{tree}"], context)
        values = [commit.decode("ascii").strip(), tree.decode("ascii").strip()]
    except UnicodeError:
        fail(f"{context} Git identity is not valid ASCII")
    if len(values) != 2 or values[0] != expected_sha or values[1] != expected_tree:
        fail(f"{context} commit or tree differs from the expected identity")
    return values[0], values[1]


def validate_context(
    event_name: str,
    repository: str,
    base_repository: str,
    head_repository: str,
    base_ref: str,
    trusted_sha: str,
    candidate_sha: str,
) -> None:
    if event_name not in {"pull_request_target", "push"}:
        fail("validation is allowed only for pull_request_target or protected main push")
    require_repository(repository, "workflow repository")
    require_repository(base_repository, "base repository")
    require_repository(head_repository, "head repository")
    if base_ref != "main":
        fail("validation requires the protected main base branch")
    require_sha(trusted_sha, "trusted commit")
    require_sha(candidate_sha, "candidate commit")
    if event_name == "push" and trusted_sha != candidate_sha:
        fail("protected main push must use one exact commit for base and candidate")


def validate_workflow_semantics(text: str) -> None:
    """Require the one-job, one-trusted-run Stage0 workflow shape."""

    if "\t" in text:
        fail("validation workflow must not contain tabs")
    if re.search(r"(?m)^\s*pull_request:\s*(?:#.*)?$", text):
        fail("validation workflow must not run from pull_request")
    required = (
        "pull_request_target:\n",
        "push:\n    branches: [main]\n",
        "permissions:\n  contents: read\n",
        "name: Stage0 trusted candidate boundary\n",
        "name: trusted-base candidate boundary\n",
        "runs-on:\n      group: arconath-jit\n      labels: [self-hosted, linux, x64, arconath-jit, rootless-buildkit]\n",
        "if: ${{ github.repository == 'Arconath/release-control' && ((github.event_name == 'pull_request_target' && github.event.pull_request.base.ref == 'main' && github.event.pull_request.base.repo.full_name == 'Arconath/release-control' && github.event.pull_request.head.repo.full_name == 'Arconath/release-control') || (github.event_name == 'push' && github.ref == 'refs/heads/main')) }}\n",
        "python3 trusted/scripts/verify_candidate.py ",
        "--trusted-root trusted",
        "--candidate-root candidate",
        "--trusted-sha \"$EXPECTED_BASE_SHA\"",
        "--trusted-tree \"$trusted_tree\"",
        "--candidate-sha \"$EXPECTED_HEAD_SHA\"",
        "--candidate-tree \"$candidate_tree\"",
    )
    missing = [fragment for fragment in required if fragment not in text]
    if missing:
        fail("validation workflow is missing trusted-boundary markers: " + ", ".join(missing))

    if text.count("runs-on:") != 1:
        fail("validation workflow must have exactly one job")
    if text.count("actions/checkout@") != 3:
        fail("validation workflow must have exactly three pinned checkouts")
    if len(re.findall(r"(?m)^\s+run:\s*", text)) != 1:
        fail("validation workflow must have exactly one trusted run block")
    if text.count("python3 trusted/scripts/verify_candidate.py") != 1:
        fail("validation workflow must invoke exactly one trusted validator")
    if text.count("path: trusted") != 1 or text.count("path: candidate") != 2:
        fail("validation workflow checkout paths are not exact")
    if text.count("persist-credentials: false") != 3:
        fail("validation workflow must disable credentials on every checkout")
    if text.count("submodules: false") != 3:
        fail("validation workflow must disable submodules on every checkout")
    if text.count("fetch-depth: 1") != 3 or text.count("fetch-tags: false") != 3:
        fail("validation workflow must use shallow immutable checkouts")

    external_actions = re.findall(r"(?m)^\s+uses:\s*([^\s#]+)", text)
    if external_actions != [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    ]:
        fail("validation workflow contains a non-allowlisted action")
    if re.search(r"(?im)secrets(?:\.|\[)|^\s*credentials\s*:|password|private[-_ ]?key|token", text):
        fail("validation workflow contains credentials or a credential-bearing operation")
    forbidden = (
        r"(?im)^\s*(?:upload-artifact|download-artifact|docker|podman|buildah|cosign|skopeo|kubectl|helm|terraform|gh|curl|wget|ssh|scp|rsync|aws|gcloud|az)\b",
        r"(?im)^\s*(?:eval|exec|source)\b",
        r"(?im)^\s*(?:python3?|node|ruby|perl|bash|sh)\s+(?:-c|-e)\b",
        r"(?i)\./scripts/verify\.sh|candidate/(?:scripts|tests)/|python3?\s+candidate/",
    )
    for pattern in forbidden:
        if re.search(pattern, text):
            fail("validation workflow contains a forbidden candidate-controlled operation")

    # Only the two inert data checkouts may have a `with` section.  The exact
    # digest below then closes any remaining YAML-level alias or expression
    # ambiguity.
    if re.search(r"(?m)^\s+uses:\s+(?!actions/checkout@)", text):
        fail("validation workflow contains an unapproved action")


def validate_workflow_text(text: str) -> None:
    validate_workflow_semantics(text)
    if EXPECTED_VALIDATION_WORKFLOW_SHA256 == "__WORKFLOW_SHA256__":
        fail("trusted workflow allowlist is not frozen")
    if sha256(text.encode("utf-8")) != EXPECTED_VALIDATION_WORKFLOW_SHA256:
        fail("validation workflow does not match the exact Stage0 allowlist")


def validate_git_tree(root: Path, context: str) -> list[str]:
    output = git_command(root, ["ls-tree", "--full-tree", "-r", "-z", "HEAD"], context)
    paths: list[str] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.split()
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeError):
            fail(f"{context} Git tree contains an invalid entry")
        if not SHA.fullmatch(object_id.decode("ascii", errors="ignore")):
            fail(f"{context} Git tree contains an invalid object identity")
        if mode in {b"120000", b"160000"} or object_type in {b"commit", b"symlink"}:
            fail(f"{context} contains a symlink or submodule: {path}")
        components = PurePosixPath(path).parts
        lowered = {component.lower() for component in components}
        if ".gitmodules" in lowered or "hooks" in lowered or ".githooks" in lowered:
            fail(f"{context} contains a submodule or hook path: {path}")
        credential_names = {
            ".env",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "credentials",
            "credentials.json",
            "id_ed25519",
            "id_rsa",
            "secrets",
            "secrets.json",
        }
        if lowered & credential_names:
            fail(f"{context} contains a credential-bearing path: {path}")
        if path.startswith(".git/") or path == ".git":
            fail(f"{context} contains Git metadata as source: {path}")
        paths.append(path)
    return paths


def _git_hook_snapshot(root: Path) -> tuple[Any, ...]:
    dot_git = root / ".git"
    try:
        metadata = dot_git.lstat()
    except FileNotFoundError:
        fail("candidate checkout Git metadata is missing")
    except OSError as exc:
        fail(f"candidate checkout Git metadata cannot be inspected: {exc}")
    if stat.S_ISLNK(metadata.st_mode):
        fail("candidate checkout Git metadata must not be a symlink")
    if stat.S_ISREG(metadata.st_mode):
        data = read_regular_file(dot_git, "candidate checkout Git metadata") or b""
        return ("git-file", sha256(data))
    if not stat.S_ISDIR(metadata.st_mode):
        fail("candidate checkout Git metadata has an unsupported type")
    config = dot_git / "config"
    config_bytes = read_regular_file(config, "candidate Git config", required=False)
    if config_bytes is not None and re.search(
        rb"(?i)(?:credential|extraheader|password|private[-_ ]?key|token)",
        config_bytes,
    ):
        fail("candidate checkout Git config contains credentials")
    hooks = dot_git / "hooks"
    try:
        hooks_metadata = hooks.lstat()
    except FileNotFoundError:
        return ("git-directory",)
    if stat.S_ISLNK(hooks_metadata.st_mode) or not stat.S_ISDIR(hooks_metadata.st_mode):
        fail("candidate checkout hooks directory must be a regular directory")
    entries: list[tuple[str, int, str]] = []
    try:
        hook_files = sorted(hooks.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        fail(f"candidate checkout hooks cannot be inspected: {exc}")
    for hook in hook_files:
        metadata = hook.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            fail(f"candidate checkout contains an unsupported hook: {hook.name}")
        if not hook.name.endswith(".sample"):
            fail(f"candidate checkout contains an executable hook: {hook.name}")
        data = read_regular_file(hook, f"candidate hook {hook.name}") or b""
        entries.append((hook.name, stat.S_IMODE(metadata.st_mode), sha256(data)))
    return ("git-directory", tuple(entries))


def tree_snapshot(root: Path) -> dict[str, tuple[Any, ...]]:
    """Snapshot bytes and modes without following links or executing files."""

    regular_directory(root, "candidate checkout")
    snapshot: dict[str, tuple[Any, ...]] = {".": ("directory",)}

    def visit(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            fail(f"candidate tree cannot be inspected: {exc}")
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                metadata = entry.lstat()
            except OSError as exc:
                fail(f"candidate tree cannot be inspected: {relative}: {exc}")
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                fail(f"candidate tree contains an unsupported symlink: {relative}")
            if stat.S_ISDIR(mode):
                if not prefix and entry.name == ".git":
                    snapshot[relative] = _git_hook_snapshot(root)
                    continue
                snapshot[relative] = ("directory",)
                visit(entry, relative)
            elif stat.S_ISREG(mode):
                data = read_regular_file(entry, f"candidate file {relative}") or b""
                snapshot[relative] = ("file", bool(mode & stat.S_IXUSR), sha256(data))
            else:
                fail(f"candidate tree contains an unsupported file type: {relative}")

    visit(root, "")
    return snapshot


def materialized_snapshot(root: Path) -> dict[str, tuple[Any, ...]]:
    snapshot = tree_snapshot(root)
    snapshot.pop(".git", None)
    return snapshot


def safe_materialize(archive: bytes, destination: Path) -> None:
    regular_directory(destination, "archive materialization directory")
    seen: set[str] = set()
    try:
        handle = tarfile.open(fileobj=io.BytesIO(archive), mode="r:")
    except (tarfile.TarError, OSError) as exc:
        fail(f"candidate archive cannot be opened: {exc}")
    with handle:
        for member in handle:
            name = member.name
            if name == "candidate":
                if not member.isdir():
                    fail("candidate archive root is not a directory")
                continue
            if not name.startswith("candidate/"):
                fail(f"candidate archive contains an unexpected path: {name}")
            relative = PurePosixPath(name.removeprefix("candidate/"))
            if relative.is_absolute() or ".." in relative.parts:
                fail(f"candidate archive contains an unsafe path: {name}")
            if not relative.parts:
                if name != "candidate/":
                    fail(f"candidate archive contains an invalid root path: {name}")
                continue
            relative_name = "/".join(relative.parts)
            if relative_name in seen:
                fail(f"candidate archive contains a duplicate path: {name}")
            seen.add(relative_name)
            target = destination.joinpath(*relative.parts)
            if member.issym() or member.islnk():
                fail(f"candidate archive contains a symlink or hardlink: {name}")
            if member.isdir():
                try:
                    target_metadata = target.lstat()
                except FileNotFoundError:
                    target.mkdir(parents=True, exist_ok=False)
                except OSError as exc:
                    fail(f"candidate archive directory cannot be inspected: {name}: {exc}")
                else:
                    if not stat.S_ISDIR(target_metadata.st_mode):
                        fail(f"candidate archive directory collides with a file: {name}")
                os.chmod(target, stat.S_IMODE(member.mode) or 0o755)
                continue
            if not member.isfile():
                fail(f"candidate archive contains an unsupported file type: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = handle.extractfile(member)
            if stream is None:
                fail(f"candidate archive file cannot be read: {name}")
            with stream, target.open("xb") as output:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
            os.chmod(target, stat.S_IMODE(member.mode))


def archive_candidate(root: Path) -> tuple[bytes, str]:
    archive = git_command(
        root,
        ["archive", "--format=tar", "--prefix=candidate/", "HEAD"],
        "candidate archive",
    )
    if not archive:
        fail("candidate archive is empty")
    return archive, sha256(archive)


def read_protected_bytes(root: Path, relative: str, *, required: bool = True) -> Optional[bytes]:
    return read_regular_file(root / PurePosixPath(relative), relative, required=required)


def validate_protected_files(trusted_root: Path, materialized_root: Path) -> dict[str, str]:
    trusted_guard = read_protected_bytes(trusted_root, VERIFY_SCRIPT)
    candidate_guard = read_protected_bytes(materialized_root, VERIFY_SCRIPT)
    if trusted_guard != candidate_guard:
        fail("candidate modified the trusted guard/verify script")

    trusted_workflow = read_protected_bytes(trusted_root, VALIDATION_WORKFLOW)
    candidate_workflow = read_protected_bytes(materialized_root, VALIDATION_WORKFLOW)
    if trusted_workflow is None or candidate_workflow is None:
        fail("validation workflow is missing")
    trusted_text = trusted_workflow.decode("utf-8")
    candidate_text = candidate_workflow.decode("utf-8")
    validate_workflow_text(trusted_text)
    validate_workflow_text(candidate_text)
    if trusted_workflow != candidate_workflow:
        fail("candidate modified the trusted validation workflow")

    trusted_validator = read_protected_bytes(trusted_root, VALIDATOR_SCRIPT)
    candidate_validator = read_protected_bytes(materialized_root, VALIDATOR_SCRIPT)
    if trusted_validator is None or candidate_validator is None:
        fail("trusted candidate validator is missing")
    if trusted_validator != candidate_validator:
        fail("candidate modified the trusted candidate validator")

    trusted_workflow_dir = trusted_root / PurePosixPath(WORKFLOW_DIRECTORY)
    candidate_workflow_dir = materialized_root / PurePosixPath(WORKFLOW_DIRECTORY)
    trusted_names = {
        path.name
        for path in trusted_workflow_dir.iterdir()
        if path.name.endswith((".yml", ".yaml"))
    }
    candidate_names = {
        path.name
        for path in candidate_workflow_dir.iterdir()
        if path.name.endswith((".yml", ".yaml"))
    }
    if trusted_names != candidate_names:
        fail("candidate added or removed a workflow")
    for name in trusted_names:
        if name == Path(VALIDATION_WORKFLOW).name:
            continue
        relative = f"{WORKFLOW_DIRECTORY}/{name}"
        trusted_bytes = read_regular_file(trusted_workflow_dir / name, relative)
        candidate_bytes = read_regular_file(candidate_workflow_dir / name, relative)
        if trusted_bytes != candidate_bytes:
            fail(f"candidate modified the trusted workflow: {name}")

    return {
        "validation_workflow_sha256": sha256(candidate_workflow),
        "verify_script_sha256": sha256(candidate_guard),
        "validator_script_sha256": sha256(candidate_validator),
    }


def validate_candidate(
    trusted_root: Path,
    candidate_root: Path,
    event_name: str,
    repository: str,
    base_repository: str,
    head_repository: str,
    base_ref: str,
    trusted_sha: str,
    trusted_tree: str,
    candidate_sha: str,
    candidate_tree: str,
) -> dict[str, Any]:
    validate_context(
        event_name,
        repository,
        base_repository,
        head_repository,
        base_ref,
        trusted_sha,
        candidate_sha,
    )
    trusted_root = regular_directory(trusted_root, "trusted base checkout")
    candidate_root = regular_directory(candidate_root, "candidate checkout")
    if trusted_root.resolve() == candidate_root.resolve():
        fail("trusted base and candidate checkouts must be separate")

    trusted_identity = git_identity(trusted_root, trusted_sha, trusted_tree, "trusted base checkout")
    candidate_identity = git_identity(candidate_root, candidate_sha, candidate_tree, "candidate checkout")
    candidate_before = tree_snapshot(candidate_root)
    validate_git_tree(candidate_root, "candidate checkout")
    archive, archive_sha256 = archive_candidate(candidate_root)
    with tempfile.TemporaryDirectory(prefix="trusted-candidate-materialized-") as temporary:
        materialized = Path(temporary)
        safe_materialize(archive, materialized)
        if materialized_snapshot(candidate_root) != materialized_snapshot(materialized):
            fail("candidate checkout does not match its immutable archive")
        protected = validate_protected_files(trusted_root, materialized)

    candidate_after = tree_snapshot(candidate_root)
    if candidate_before != candidate_after:
        fail("candidate checkout changed during trusted validation")
    if git_identity(trusted_root, trusted_sha, trusted_tree, "trusted base checkout") != trusted_identity:
        fail("trusted base Git identity changed during validation")
    if git_identity(candidate_root, candidate_sha, candidate_tree, "candidate checkout") != candidate_identity:
        fail("candidate Git identity changed during validation")
    return {
        "status": "validated",
        "event": event_name,
        "repository": repository,
        "trusted_sha": trusted_sha,
        "trusted_tree": trusted_tree,
        "candidate_sha": candidate_sha,
        "candidate_tree": candidate_tree,
        "archive_sha256": archive_sha256,
        "candidate_entries": len(candidate_after),
        "protected_files": protected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate candidate bytes with trusted-base code")
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--base-repository", required=True)
    parser.add_argument("--head-repository", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--trusted-sha", required=True)
    parser.add_argument("--trusted-tree", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-tree", required=True)
    args = parser.parse_args()
    try:
        result = validate_candidate(
            args.trusted_root,
            args.candidate_root,
            args.event_name,
            args.repository,
            args.base_repository,
            args.head_repository,
            args.base_ref,
            args.trusted_sha,
            args.trusted_tree,
            args.candidate_sha,
            args.candidate_tree,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except ValidationError as exc:
        print(f"trusted candidate validator: {exc}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError, tarfile.TarError) as exc:
        print(f"trusted candidate validator: operating-system error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
