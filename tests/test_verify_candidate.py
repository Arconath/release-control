#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_candidate.py"
REPOSITORY = "Arconath/release-control"
GOLDEN_BASE_COMMIT = "e3911e1ebc927d475e4dfc340b71460b6971c3c9"
GOLDEN_BASE_TREE = "5d00558cff38971b9f488a8472f3669d4df86756"

SPEC = importlib.util.spec_from_file_location("verify_candidate", SCRIPT)
assert SPEC and SPEC.loader
verify_candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_candidate)


def git(path: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


class VerifyCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source = self.root / "source"
        source.mkdir()
        golden_tree = git(ROOT, "rev-parse", f"{GOLDEN_BASE_COMMIT}^{{tree}}")
        self.assertEqual(golden_tree, GOLDEN_BASE_TREE)
        archive = subprocess.check_output(
            ["git", "archive", "--format=tar", GOLDEN_BASE_COMMIT],
            cwd=ROOT,
        )
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as handle:
            handle.extractall(source)
        git(source, "init", "-q")
        git(source, "config", "user.name", "Stage0 test")
        git(source, "config", "user.email", "stage0@example.invalid")
        git(source, "add", "--all")
        git(source, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")
        self.assertEqual(git(source, "rev-parse", "HEAD^{tree}"), GOLDEN_BASE_TREE)
        self.trusted = self.root / "trusted"
        self.candidate = self.root / "candidate"
        subprocess.run(["git", "clone", "--no-local", "-q", str(source), str(self.trusted)], check=True)
        subprocess.run(["git", "clone", "--no-local", "-q", str(source), str(self.candidate)], check=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def identity(self, path: Path) -> tuple[str, str]:
        return (
            git(path, "rev-parse", "HEAD"),
            git(path, "rev-parse", "HEAD^{tree}"),
        )

    def commit_candidate(self, relative: str, content: str, *, mode: int | None = None) -> None:
        path = self.candidate / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)
        git(self.candidate, "add", "--all")
        git(self.candidate, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "candidate change")

    def run_validator(self, *, event: str = "pull_request_target") -> subprocess.CompletedProcess[str]:
        trusted_sha, trusted_tree = self.identity(self.trusted)
        candidate_sha, candidate_tree = self.identity(self.candidate)
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [
                "python3",
                # The exact-base fixture supplies the trusted data tree.  The
                # correction under test is loaded from this worktree so the
                # fixture cannot silently self-approve a changed validator.
                str(SCRIPT),
                "--trusted-root",
                str(self.trusted),
                "--candidate-root",
                str(self.candidate),
                "--event-name",
                event,
                "--repository",
                REPOSITORY,
                "--base-repository",
                REPOSITORY,
                "--head-repository",
                REPOSITORY,
                "--base-ref",
                "main",
                "--trusted-sha",
                trusted_sha,
                "--trusted-tree",
                trusted_tree,
                "--candidate-sha",
                candidate_sha,
                "--candidate-tree",
                candidate_tree,
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_valid_candidate_is_bound_to_commit_tree_and_immutable_archive(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"status":"validated"', result.stdout)
        self.assertIn('"archive_sha256":', result.stdout)

    def test_commit_or_tree_mismatch_fails_closed(self) -> None:
        trusted_sha, trusted_tree = self.identity(self.trusted)
        candidate_sha, candidate_tree = self.identity(self.candidate)
        command = [
            "python3",
            str(self.trusted / "scripts" / "verify_candidate.py"),
            "--trusted-root",
            str(self.trusted),
            "--candidate-root",
            str(self.candidate),
            "--event-name",
            "pull_request_target",
            "--repository",
            REPOSITORY,
            "--base-repository",
            REPOSITORY,
            "--head-repository",
            REPOSITORY,
            "--base-ref",
            "main",
            "--trusted-sha",
            trusted_sha,
            "--trusted-tree",
            "0" * 40,
            "--candidate-sha",
            candidate_sha,
            "--candidate-tree",
            candidate_tree,
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("commit or tree", result.stderr)

    def test_golden_legacy_base_allows_only_current_workflow_transition(self) -> None:
        current_workflow = (ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        legacy_workflow = (self.candidate / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        self.commit_candidate(".github/workflows/validate.yml", current_workflow)
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)

        current_trusted = self.root / "trusted-current"
        rollback_candidate = self.root / "candidate-rollback"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.candidate), str(current_trusted)], check=True)
        subprocess.run(["git", "clone", "--no-local", "-q", str(current_trusted), str(rollback_candidate)], check=True)
        self.trusted = current_trusted
        self.candidate = rollback_candidate
        self.commit_candidate(".github/workflows/validate.yml", legacy_workflow)
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)

    def test_extra_and_obfuscated_run_steps_are_rejected(self) -> None:
        workflow = (self.candidate / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        self.commit_candidate(
            ".github/workflows/validate.yml",
            workflow + "\n      - name: extra\n        run: echo unsafe\n",
        )
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.candidate / "unsafe").exists())

        self.candidate = self.root / "candidate-obfuscated"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.trusted), str(self.candidate)], check=True)
        obfuscated = workflow.replace(
            "python3 trusted/scripts/verify_candidate.py \\",
            "python3${IFS}trusted/scripts/verify_candidate.py \\",
        )
        self.commit_candidate(".github/workflows/validate.yml", obfuscated)
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)

    def test_credentials_submodules_hooks_and_symlinks_are_rejected(self) -> None:
        credential_workflow = (self.candidate / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        self.commit_candidate(
            ".github/workflows/validate.yml",
            credential_workflow + "\nenv:\n  GH_TOKEN: ${{ secrets.PUBLISH_TOKEN }}\n",
        )
        self.assertNotEqual(self.run_validator().returncode, 0)

        self.candidate = self.root / "candidate-credential-file"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.trusted), str(self.candidate)], check=True)
        self.commit_candidate(".env", "PUBLISH_TOKEN=unsafe\n")
        self.assertNotEqual(self.run_validator().returncode, 0)

        self.candidate = self.root / "candidate-submodule"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.trusted), str(self.candidate)], check=True)
        self.commit_candidate(".gitmodules", "[submodule \"unsafe\"]\n\tpath = unsafe\n")
        self.assertNotEqual(self.run_validator().returncode, 0)

        self.candidate = self.root / "candidate-hook"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.trusted), str(self.candidate)], check=True)
        self.commit_candidate("hooks/pre-commit", "#!/bin/sh\nexit 0\n", mode=0o755)
        self.assertNotEqual(self.run_validator().returncode, 0)

        self.candidate = self.root / "candidate-symlink"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.trusted), str(self.candidate)], check=True)
        os.symlink("README.md", self.candidate / "candidate-link")
        self.assertNotEqual(self.run_validator().returncode, 0)

    def test_candidate_code_and_legacy_verify_script_are_never_executed(self) -> None:
        marker = self.root / "candidate-executed"
        literal = repr(str(marker))
        self.commit_candidate(
            "scripts/release_control.py",
            f"from pathlib import Path\nPath({literal}).write_text('executed')\n",
        )
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

        self.candidate = self.root / "candidate-guard"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.trusted), str(self.candidate)], check=True)
        self.commit_candidate(
            "scripts/verify.sh",
            f"#!/bin/sh\nfrom pathlib import Path\nPath({literal}).write_text('executed')\n",
        )
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

        self.candidate = self.root / "candidate-verifier"
        subprocess.run(["git", "clone", "--no-local", "-q", str(self.trusted), str(self.candidate)], check=True)
        self.commit_candidate(
            "scripts/verify_candidate.py",
            f"from pathlib import Path\nPath({literal}).write_text('executed')\n",
        )
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_toctou_change_after_archive_is_rejected(self) -> None:
        original = verify_candidate.archive_candidate

        def archive_then_change(path: Path) -> tuple[bytes, str]:
            archive, digest = original(path)
            (path / "README.md").write_text("changed during validation\n", encoding="utf-8")
            return archive, digest

        trusted_sha, trusted_tree = self.identity(self.trusted)
        candidate_sha, candidate_tree = self.identity(self.candidate)
        with mock.patch.object(verify_candidate, "archive_candidate", archive_then_change):
            with self.assertRaisesRegex(verify_candidate.ValidationError, "immutable archive"):
                verify_candidate.validate_candidate(
                    self.trusted,
                    self.candidate,
                    "pull_request_target",
                    REPOSITORY,
                    REPOSITORY,
                    REPOSITORY,
                    "main",
                    trusted_sha,
                    trusted_tree,
                    candidate_sha,
                    candidate_tree,
                )

    def test_archive_materialization_rejects_symlink_members(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            root = tarfile.TarInfo("candidate")
            root.type = tarfile.DIRTYPE
            handle.addfile(root)
            member = tarfile.TarInfo("candidate/unsafe")
            member.type = tarfile.SYMTYPE
            member.linkname = "/tmp/unsafe"
            handle.addfile(member)
        with tempfile.TemporaryDirectory() as destination:
            with self.assertRaisesRegex(verify_candidate.ValidationError, "symlink"):
                verify_candidate.safe_materialize(archive.getvalue(), Path(destination))

    def test_materialization_traverses_nested_directories_without_path_following(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            root = tarfile.TarInfo("candidate")
            root.type = tarfile.DIRTYPE
            handle.addfile(root)
            nested = tarfile.TarInfo("candidate/nested")
            nested.type = tarfile.DIRTYPE
            handle.addfile(nested)
            member = tarfile.TarInfo("candidate/nested/payload")
            payload = b"descriptor-relative\n"
            member.size = len(payload)
            handle.addfile(member, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as destination:
            verify_candidate.safe_materialize(archive.getvalue(), Path(destination))
            self.assertEqual(
                (Path(destination) / "nested" / "payload").read_bytes(),
                b"descriptor-relative\n",
            )

    def test_materialization_requires_empty_validator_owned_destination(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            root = tarfile.TarInfo("candidate")
            root.type = tarfile.DIRTYPE
            handle.addfile(root)
        with tempfile.TemporaryDirectory() as destination:
            destination_path = Path(destination)
            existing = destination_path / "existing"
            existing.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(verify_candidate.ValidationError, "empty"):
                verify_candidate.safe_materialize(archive.getvalue(), destination_path)
            self.assertEqual(existing.read_text(encoding="utf-8"), "preserve\n")

            with mock.patch.object(verify_candidate, "effective_uid", return_value=os.geteuid() + 1):
                with self.assertRaisesRegex(verify_candidate.ValidationError, "owned"):
                    verify_candidate.safe_materialize(archive.getvalue(), Path(destination))

    def test_preexisting_symlink_directory_cannot_escape_destination(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            root = tarfile.TarInfo("candidate")
            root.type = tarfile.DIRTYPE
            handle.addfile(root)
            member = tarfile.TarInfo("candidate/escape/payload")
            payload = b"must not escape\n"
            member.size = len(payload)
            handle.addfile(member, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            destination = temporary_path / "destination"
            outside = temporary_path / "outside"
            destination.mkdir()
            outside.mkdir()
            os.symlink(outside, destination / "escape")
            with self.assertRaises(verify_candidate.ValidationError):
                verify_candidate.safe_materialize(archive.getvalue(), destination)
            self.assertFalse((outside / "payload").exists())

    def test_symlink_directory_race_is_rejected_without_an_escape_write(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            root = tarfile.TarInfo("candidate")
            root.type = tarfile.DIRTYPE
            handle.addfile(root)
            nested = tarfile.TarInfo("candidate/raced")
            nested.type = tarfile.DIRTYPE
            handle.addfile(nested)
            member = tarfile.TarInfo("candidate/raced/payload")
            payload = b"must not escape\n"
            member.size = len(payload)
            handle.addfile(member, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            destination = temporary_path / "destination"
            outside = temporary_path / "outside"
            destination.mkdir()
            outside.mkdir()
            original_open = verify_candidate.os.open
            raced = False

            def replace_directory_before_open(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
                nonlocal raced
                if path == "raced" and dir_fd is not None and not raced:
                    raced_path = destination / "raced"
                    if raced_path.is_dir() and not raced_path.is_symlink():
                        raced = True
                        raced_path.rmdir()
                        os.symlink(outside, raced_path)
                return original_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(verify_candidate.os, "open", replace_directory_before_open):
                with self.assertRaisesRegex(verify_candidate.ValidationError, "opened safely|changed"):
                    verify_candidate.safe_materialize(archive.getvalue(), destination)
            self.assertTrue(raced)
            self.assertFalse((outside / "payload").exists())

    def test_hardlink_archive_member_is_rejected(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            root = tarfile.TarInfo("candidate")
            root.type = tarfile.DIRTYPE
            handle.addfile(root)
            member = tarfile.TarInfo("candidate/hardlink")
            member.type = tarfile.LNKTYPE
            member.linkname = "candidate/other"
            handle.addfile(member)
        with tempfile.TemporaryDirectory() as destination:
            with self.assertRaisesRegex(verify_candidate.ValidationError, "hardlink"):
                verify_candidate.safe_materialize(archive.getvalue(), Path(destination))


if __name__ == "__main__":
    unittest.main(verbosity=2)
