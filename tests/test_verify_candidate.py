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
        shutil.copytree(
            ROOT,
            source,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        git(source, "init", "-q")
        git(source, "config", "user.name", "Stage0 test")
        git(source, "config", "user.email", "stage0@example.invalid")
        git(source, "add", "--all")
        git(source, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")
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
                str(self.trusted / "scripts" / "verify_candidate.py"),
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
            member = tarfile.TarInfo("candidate/unsafe")
            member.type = tarfile.SYMTYPE
            member.linkname = "/tmp/unsafe"
            handle.addfile(member)
        with tempfile.TemporaryDirectory() as destination:
            with self.assertRaisesRegex(verify_candidate.ValidationError, "symlink"):
                verify_candidate.safe_materialize(archive.getvalue(), Path(destination))


if __name__ == "__main__":
    unittest.main(verbosity=2)
