#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_candidate.py"


def current_sha() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def malicious_candidate(parent: Path, marker: Path) -> Path:
    candidate = parent / "candidate"
    shutil.copytree(
        ROOT,
        candidate,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    marker_literal = repr(str(marker))
    (candidate / "scripts" / "verify.sh").write_text(
        f"#!/usr/bin/env bash\nprintf executed > {marker_literal}\n",
        encoding="utf-8",
    )
    (candidate / "scripts" / "verify_candidate.py").write_text(
        f"from pathlib import Path\nPath({marker_literal}).write_text('executed')\n",
        encoding="utf-8",
    )
    (candidate / "scripts" / "release_control.py").write_text(
        f"from pathlib import Path\nPath({marker_literal}).write_text('executed')\n",
        encoding="utf-8",
    )
    return candidate


class TrustedCandidateValidatorTests(unittest.TestCase):
    def run_validator(
        self, candidate: Path, trusted_sha: str, candidate_sha: str
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--trusted-root",
                str(ROOT),
                "--candidate-root",
                str(candidate),
                "--trusted-sha",
                trusted_sha,
                "--candidate-sha",
                candidate_sha,
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_candidate_scripts_and_validator_are_inert_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            marker = temporary_root / "candidate-executed"
            candidate = malicious_candidate(temporary_root, marker)
            sha = current_sha()
            result = self.run_validator(candidate, sha, sha)

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertNotIn("candidate-executed", result.stdout + result.stderr)

    def test_candidate_sha_mismatch_fails_closed_before_candidate_data_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            marker = temporary_root / "candidate-executed"
            candidate = malicious_candidate(temporary_root, marker)
            sha = current_sha()
            wrong_sha = "0" * 40
            result = self.run_validator(candidate, sha, wrong_sha)

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
