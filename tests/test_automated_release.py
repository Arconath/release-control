#!/usr/bin/env python3

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_control", ROOT / "scripts" / "release_control.py"
)
assert SPEC and SPEC.loader
rc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rc)


NOW = dt.datetime(2026, 9, 4, 0, 5, tzinfo=dt.timezone.utc)
ARTIFACT_DIGEST = "sha256:" + "f" * 64


class AutomatedReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = rc.load_json(ROOT / "policies" / "automated-release-policy.json")
        evidence_digests = {
            "artifact_signature": "3" * 64,
            "machine_attestation_signature": "4" * 64,
            "provenance": "5" * 64,
            "sbom": "6" * 64,
            "canary": "2" * 64,
            "rollback": "7" * 64,
            "backup_guard": "8" * 64,
            "production_domain_guard": "9" * 64,
        }
        self.attestation = {
            "artifact": {
                "digest": ARTIFACT_DIGEST,
                "repository": "registry.arconath.internal/arconath/releasepassport/api",
            },
            "attestation_id": "releasepassport-api-automated-01",
            "audit": {
                "append_only": True,
                "entry_sha256": "1" * 64,
                "immutable": True,
                "ledger": "github-release-evidence",
                "sequence": 1,
            },
            "authorization": {
                "human_reviewers": 0,
                "human_signers": 0,
                "manual_override": False,
                "mode": "machine-only",
            },
            "canary": {
                "abort_thresholds": {
                    "error_rate_percent_max": 5.0,
                    "p95_latency_ms_max": 2000,
                    "restart_count_max": 3,
                },
                "health": {"evidence_sha256": "2" * 64, "status": "pass"},
                "observability": {"logs": "pass", "metrics": "pass", "traces": "pass"},
                "observed": {
                    "error_rate_percent": 0.2,
                    "p95_latency_ms": 120,
                    "restart_count": 0,
                },
                "required": True,
            },
            "checks": {
                "all_completed": True,
                "no_skips": True,
                "queried_at": "2026-09-04T00:04:00Z",
                "required_contexts": list(rc.AUTOMATED_REQUIRED_CHECKS),
                "results": [
                    {
                        "conclusion": "success",
                        "context": context,
                        "head_sha": "a" * 40,
                        "run_id": "123",
                        "status": "completed",
                    }
                    for context in rc.AUTOMATED_REQUIRED_CHECKS
                ],
            },
            "evidence": {
                name: {
                    "artifact_digest": ARTIFACT_DIGEST,
                    "sha256": digest,
                    "path": f"evidence/{name}.json",
                    "signature_path": f"evidence/{name}.json.sig",
                    "signer_identity": rc.AUTOMATED_SIGNER_IDENTITY,
                    "verified": True,
                }
                for name, digest in evidence_digests.items()
            },
            "expires_at": "2026-09-04T00:15:00Z",
            "issued_at": "2026-09-04T00:00:00Z",
            "policy_id": "arconath-automated-release",
            "release_control": {
                "commit_sha": "a" * 40,
                "repository": "Arconath/release-control",
                "tree_sha": "b" * 40,
                "workflow": {
                    "commit_sha": "c" * 40,
                    "path": ".github/workflows/release-control.yml",
                    "public_runner_allowed": False,
                    "ref": "refs/heads/main",
                    "repository": "Arconath/.github",
                    "run_id": "123",
                    "runner_group": "arconath-jit",
                    "tree_sha": "d" * 40,
                },
            },
            "replay_protection": {
                "consumed": False,
                "cooldown_seconds": 300,
                "max_promotions": 1,
                "nonce": "N" * 22,
                "single_use": True,
            },
            "rollback": {
                "automatic": True,
                "evidence_sha256": "7" * 64,
                "restore_digest": "sha256:" + "9" * 64,
                "strategy": "gitops-revert",
                "tested": True,
            },
            "runner": {
                "attestation_sha256": "8" * 64,
                "ephemeral": True,
                "group": "arconath-jit",
                "labels": list(rc.AUTOMATED_RUNNER_LABELS),
            },
            "schema_version": 1,
            "source": {
                "commit_sha": "d" * 40,
                "repository": "Arconath/releasepassport",
                "tree_sha": "e" * 40,
            },
            "target": {
                "environment": "canary",
                "backup_mode": rc.AUTOMATED_BACKUP_MODE,
                "external_backup_guard": True,
                "guard_evidence": {
                    "backup": "backup_guard",
                    "production_domain": "production_domain_guard",
                },
                "production_domain_guard": True,
                "routes": ["releasepassport.com"],
            },
        }
        self.attestation["canary"]["health"]["evidence_sha256"] = evidence_digests["canary"]
        self.attestation["rollback"]["evidence_sha256"] = evidence_digests["rollback"]
        self.attestation["audit"]["entry_sha256"] = rc.machine_attestation_audit_digest(
            self.attestation
        )

    def validate(self, value: dict | None = None) -> None:
        rc.validate_machine_release_attestation(
            value or self.attestation, self.policy, now=NOW
        )

    def test_valid_machine_attestation(self) -> None:
        rc.validate_automated_release_policy(self.policy)
        self.validate()

    def test_checked_in_settings_remove_human_release_gates(self) -> None:
        settings = rc.load_json(ROOT / "bootstrap" / "repository-settings.json")
        rc.validate_automated_release_settings(settings)
        self.assertEqual(settings["main_protection"]["required_approvals"], 0)
        self.assertFalse(settings["main_protection"]["require_code_owner_review"])
        self.assertFalse(settings["main_protection"]["require_last_push_approval"])
        for environment in settings["environments"].values():
            self.assertEqual(environment["required_reviewers"], 0)
            self.assertFalse(environment["can_admins_bypass"])

    def test_registry_lookup_is_pinned_to_the_attested_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authfile = Path(directory) / "registry-auth.json"
            authfile.write_text("{}\n", encoding="utf-8")
            completed = subprocess.CompletedProcess(
                ["skopeo"], 0, stdout=(ARTIFACT_DIGEST + "\n").encode(), stderr=b""
            )
            with mock.patch.object(rc.subprocess, "run", return_value=completed) as run:
                rc.verify_registry_digest(
                    "registry.arconath.internal/arconath/releasepassport/api",
                    ARTIFACT_DIGEST,
                    authfile,
                )
            command = run.call_args.args[0]
            self.assertEqual(
                command[-1],
                "docker://registry.arconath.internal/arconath/releasepassport/api@"
                + ARTIFACT_DIGEST,
            )

    def test_registry_lookup_rejects_tagged_or_zero_digest_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authfile = Path(directory) / "registry-auth.json"
            authfile.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(rc.ContractError, "invalid registry repository"):
                rc.verify_registry_digest(
                    "registry.arconath.internal/arconath/releasepassport/api:latest",
                    ARTIFACT_DIGEST,
                    authfile,
                )
            with self.assertRaisesRegex(rc.ContractError, "must not be the zero digest"):
                rc.verify_registry_digest(
                    "registry.arconath.internal/arconath/releasepassport/api",
                    "sha256:" + "0" * 64,
                    authfile,
                )

    def test_ledger_consumption_rechecks_expiry_with_fresh_clock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "replay.jsonl"
            expired_at_lock = dt.datetime(2026, 9, 4, 0, 16, tzinfo=dt.timezone.utc)
            lock_acquired = False

            def record_lock(_file_descriptor: int, _operation: int) -> None:
                nonlocal lock_acquired
                lock_acquired = True

            def expired_clock() -> dt.datetime:
                self.assertTrue(lock_acquired)
                return expired_at_lock

            with mock.patch.object(rc.fcntl, "flock", side_effect=record_lock):
                with self.assertRaisesRegex(rc.ContractError, "expired before ledger consumption"):
                    rc.consume_machine_attestation(
                        self.attestation,
                        self.policy,
                        ledger,
                        now=NOW,
                        clock=expired_clock,
                    )
            self.assertFalse(ledger.exists() and ledger.read_text(encoding="utf-8"))
            consumed_at = NOW + dt.timedelta(seconds=1)
            entry = rc.consume_machine_attestation(
                self.attestation,
                self.policy,
                ledger,
                now=NOW,
                clock=lambda: consumed_at,
            )
            self.assertEqual(entry["consumed_at"], "2026-09-04T00:05:01Z")

    def test_admission_uses_fresh_clock_after_external_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = root / "replay.jsonl"
            authfile = root / "registry-auth.json"
            authfile.write_text("{}\n", encoding="utf-8")
            external_calls: list[str] = []

            def registry_check(*_args: object) -> None:
                external_calls.append("registry")

            def expired_clock() -> dt.datetime:
                self.assertEqual(external_calls, ["registry"])
                return dt.datetime(2026, 9, 4, 0, 16, tzinfo=dt.timezone.utc)

            with (
                mock.patch.object(rc, "validate_machine_release_attestation"),
                mock.patch.object(rc, "git_checkout_repository"),
                mock.patch.object(rc, "git_checkout_identity"),
                mock.patch.object(rc, "verify_registry_digest", side_effect=registry_check),
            ):
                with self.assertRaisesRegex(rc.ContractError, "expired before ledger consumption"):
                    rc.admit_machine_release(
                        self.attestation,
                        self.policy,
                        now=NOW,
                        evidence_root=root,
                        allowed_machine_signers=root / "allowed-signers",
                        release_control_root=root,
                        source_root=root,
                        control_plane_root=root,
                        registry_authfile=authfile,
                        replay_ledger=ledger,
                        clock=expired_clock,
                    )
            self.assertEqual(external_calls, ["registry"])
            self.assertFalse(ledger.exists() and ledger.read_text(encoding="utf-8"))

    def test_missing_required_ci_context_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["checks"]["required_contexts"].pop()
        with self.assertRaisesRegex(rc.ContractError, "required CI contexts"):
            self.validate(value)

    def test_skipped_ci_context_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["checks"]["results"][0]["conclusion"] = "skipped"
        with self.assertRaisesRegex(rc.ContractError, "not completed successfully"):
            self.validate(value)

    def test_forged_ci_head_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["checks"]["results"][0]["head_sha"] = "0" * 40
        with self.assertRaisesRegex(rc.ContractError, "head does not match"):
            self.validate(value)

    def test_untrusted_control_plane_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["release_control"]["workflow"]["repository"] = "Arconath/release-control"
        with self.assertRaisesRegex(rc.ContractError, "workflow repository"):
            self.validate(value)

    def test_missing_provenance_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        del value["evidence"]["provenance"]
        with self.assertRaisesRegex(rc.ContractError, "evidence missing fields"):
            self.validate(value)

    def test_mismatched_evidence_digest_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["evidence"]["provenance"]["artifact_digest"] = "sha256:" + "a" * 64
        with self.assertRaisesRegex(rc.ContractError, "does not match artifact"):
            self.validate(value)

    def test_failed_canary_threshold_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["canary"]["observed"]["error_rate_percent"] = 6
        with self.assertRaisesRegex(rc.ContractError, "error rate"):
            self.validate(value)

    def test_routes_and_abort_thresholds_are_policy_bound(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["target"]["routes"] = ["unapproved.example"]
        with self.assertRaisesRegex(rc.ContractError, "outside the canonical allowlist"):
            self.validate(value)
        value = copy.deepcopy(self.attestation)
        value["canary"]["abort_thresholds"]["error_rate_percent_max"] = 50.0
        with self.assertRaisesRegex(rc.ContractError, "do not match policy"):
            self.validate(value)

    def test_failed_automatic_rollback_is_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["rollback"]["automatic"] = False
        with self.assertRaisesRegex(rc.ContractError, "automatic GitOps revert"):
            self.validate(value)

    def test_replayed_or_expired_attestation_is_rejected(self) -> None:
        replayed = copy.deepcopy(self.attestation)
        replayed["replay_protection"]["consumed"] = True
        with self.assertRaisesRegex(rc.ContractError, "already been consumed"):
            self.validate(replayed)
        with self.assertRaisesRegex(rc.ContractError, "expired"):
            self.validate(self.attestation | {"expires_at": "2026-09-04T00:05:00Z"})

    def test_manual_override_or_human_gate_cannot_be_reintroduced(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["authorization"]["manual_override"] = True
        with self.assertRaisesRegex(rc.ContractError, "machine-only"):
            self.validate(value)
        policy = copy.deepcopy(self.policy)
        policy["human_signers_required"] = True
        with self.assertRaisesRegex(rc.ContractError, "must not require human signers"):
            rc.validate_automated_release_policy(policy)

    def test_zero_digest_and_zero_runner_attestation_are_rejected(self) -> None:
        value = copy.deepcopy(self.attestation)
        value["artifact"]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(rc.ContractError, "zero digest"):
            self.validate(value)
        value = copy.deepcopy(self.attestation)
        value["runner"]["attestation_sha256"] = "0" * 64
        with self.assertRaisesRegex(rc.ContractError, "invalid machine attestation runner"):
            self.validate(value)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(rc.ContractError, "duplicate JSON object key"):
                rc.load_json(path)

    def test_admission_verifies_signed_evidence_and_consumes_once(self) -> None:
        value = copy.deepcopy(self.attestation)
        actual_sha = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        actual_tree = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        value["release_control"]["commit_sha"] = actual_sha
        value["release_control"]["tree_sha"] = actual_tree
        value["release_control"]["workflow"]["commit_sha"] = actual_sha
        value["release_control"]["workflow"]["tree_sha"] = actual_tree
        value["source"]["commit_sha"] = actual_sha
        value["source"]["tree_sha"] = actual_tree
        for result in value["checks"]["results"]:
            result["head_sha"] = actual_sha
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_root = root / "evidence"
            evidence_root.mkdir()
            private_key = root / "machine-ed25519"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
                check=True,
                capture_output=True,
            )
            public_key = private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
            allowed_signers = root / "allowed-signers"
            allowed_signers.write_text(
                f"{rc.AUTOMATED_SIGNER_IDENTITY} {public_key}\n", encoding="utf-8"
            )
            for name in rc.AUTOMATED_REQUIRED_EVIDENCE:
                if name == "machine_attestation_signature":
                    continue
                item = value["evidence"][name]
                payload = rc._expected_signed_evidence_payload(
                    name, value, value["artifact"]["digest"]
                )
                assert payload is not None
                payload_path = evidence_root / item["path"]
                payload_path.parent.mkdir(parents=True, exist_ok=True)
                payload_path.write_bytes(rc.canonical_bytes(payload))
                item["sha256"] = hashlib.sha256(payload_path.read_bytes()).hexdigest()
                signature_path = evidence_root / item["signature_path"]
                subprocess.run(
                    [
                        "ssh-keygen",
                        "-Y",
                        "sign",
                        "-f",
                        str(private_key),
                        "-n",
                        rc.MACHINE_EVIDENCE_NAMESPACE,
                        str(payload_path),
                    ],
                    check=True,
                    capture_output=True,
                )
                self.assertEqual(signature_path, payload_path.with_name(payload_path.name + ".sig"))
            value["canary"]["health"]["evidence_sha256"] = value["evidence"]["canary"]["sha256"]
            value["rollback"]["evidence_sha256"] = value["evidence"]["rollback"]["sha256"]
            value["audit"]["entry_sha256"] = rc.machine_attestation_audit_digest(value)
            name = "machine_attestation_signature"
            item = value["evidence"][name]
            payload = rc._expected_signed_evidence_payload(
                name, value, value["artifact"]["digest"]
            )
            assert payload is not None
            payload_path = evidence_root / item["path"]
            payload_path.parent.mkdir(parents=True, exist_ok=True)
            payload_path.write_bytes(rc.canonical_bytes(payload))
            item["sha256"] = hashlib.sha256(payload_path.read_bytes()).hexdigest()
            signature_path = evidence_root / item["signature_path"]
            subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(private_key),
                    "-n",
                    rc.MACHINE_EVIDENCE_NAMESPACE,
                    str(payload_path),
                ],
                check=True,
                capture_output=True,
            )
            self.assertEqual(signature_path, payload_path.with_name(payload_path.name + ".sig"))
            ledger = root / "replay.jsonl"
            authfile = root / "registry-auth.json"
            authfile.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(rc, "git_checkout_repository") as git_repository, mock.patch.object(
                rc, "verify_registry_digest"
            ) as registry:
                entry = rc.admit_machine_release(
                    value,
                    self.policy,
                    now=NOW,
                    evidence_root=evidence_root,
                    allowed_machine_signers=allowed_signers,
                    release_control_root=ROOT,
                    source_root=ROOT,
                    control_plane_root=ROOT,
                    registry_authfile=authfile,
                    replay_ledger=ledger,
                    clock=lambda: NOW,
                )
            self.assertEqual(entry["sequence"], 1)
            self.assertEqual(git_repository.call_count, 3)
            registry.assert_called_once_with(
                value["artifact"]["repository"], value["artifact"]["digest"], authfile
            )
            with mock.patch.object(rc, "git_checkout_repository"), mock.patch.object(
                rc, "verify_registry_digest"
            ):
                with self.assertRaisesRegex(rc.ContractError, "already been consumed"):
                    rc.admit_machine_release(
                        value,
                        self.policy,
                        now=NOW,
                        evidence_root=evidence_root,
                        allowed_machine_signers=allowed_signers,
                        release_control_root=ROOT,
                        source_root=ROOT,
                        control_plane_root=ROOT,
                        registry_authfile=authfile,
                        replay_ledger=ledger,
                        clock=lambda: NOW,
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
