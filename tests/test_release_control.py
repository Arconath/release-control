#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_CONTROL_SHA = "a" * 40
AGE_RECIPIENT = "age1" + "b" * 32
MODULE_PATH = ROOT / "scripts" / "release_control.py"
SPEC = importlib.util.spec_from_file_location("release_control", MODULE_PATH)
assert SPEC and SPEC.loader
rc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rc)


def write_json(path: Path, value: object) -> None:
    path.write_bytes(rc.canonical_bytes(value))


class ReleaseControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy_dir = self.root / "policies"
        self.policy_dir.mkdir()
        self.policy = {
            "artifact_repository": "registry.arconath.internal/arconath/example-api",
            "build": {
                "context": ".",
                "dockerfile": "Dockerfile",
                "platform": "linux/amd64",
            },
            "enabled": True,
            "max_intent_age_seconds": 86400,
            "policy_id": "example-api",
            "registry_host": "registry.arconath.internal",
            "schema_version": 1,
            "source_repository": "Arconath/example",
            "verification_commands": [["./scripts/verify.sh"]],
        }
        write_json(self.policy_dir / "example-api.json", self.policy)
        self.now = dt.datetime(2026, 8, 31, 0, 30, tzinfo=dt.timezone.utc)
        self.intent = {
            "artifact": {
                "repository": "registry.arconath.internal/arconath/example-api",
                "version": "1.2.3",
            },
            "expires_at": "2026-08-31T01:00:00Z",
            "intent_id": "example-api-1.2.3",
            "issued_at": "2026-08-31T00:00:00Z",
            "policy_id": "example-api",
            "rollback": {
                "previous_digest": "sha256:" + "1" * 64,
                "reason": "Restore the last verified production image.",
            },
            "schema_version": 1,
            "signer_identity": "hermawan22",
            "source": {
                "repository": "Arconath/example",
                "commit_sha": "2" * 40,
                "tree_sha": "3" * 40,
            },
        }
        self.intent_path = self.root / "intent.json"
        write_json(self.intent_path, self.intent)
        self.key = self.root / "release-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        public = (self.key.with_suffix(".pub")).read_text(encoding="utf-8").strip()
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(f"hermawan22 {public}\n", encoding="utf-8")
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(self.key),
                "-n",
                rc.NAMESPACE,
                str(self.intent_path),
            ],
            check=True,
            capture_output=True,
        )
        self.signature = Path(f"{self.intent_path}.sig")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_oci(self, digest: str | None = None) -> Path:
        digest = digest or "sha256:" + "4" * 64
        index = rc.canonical_bytes(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": digest,
                        "size": 123,
                    }
                ],
            }
        )
        archive = self.root / "candidate.oci.tar"
        with tarfile.open(archive, "w") as handle:
            info = tarfile.TarInfo("index.json")
            info.size = len(index)
            handle.addfile(info, io.BytesIO(index))
        return archive

    def validate(self) -> tuple[dict, dict]:
        return rc.validate_intent(
            self.intent_path,
            self.signature,
            self.allowed,
            self.policy_dir,
            self.now,
        )

    def test_valid_signed_intent_binds_full_source_identity(self) -> None:
        intent, policy = self.validate()
        self.assertEqual(intent["source"]["commit_sha"], "2" * 40)
        self.assertEqual(intent["source"]["tree_sha"], "3" * 40)
        self.assertEqual(policy["artifact_repository"], intent["artifact"]["repository"])

    def test_validate_signers_cli_accepts_one_operator_key(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(MODULE_PATH),
                "validate-signers",
                "--allowed-signers",
                str(self.allowed),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tampered_tree_is_rejected_by_signature(self) -> None:
        tampered = dict(self.intent)
        tampered["source"] = dict(self.intent["source"], tree_sha="5" * 40)
        write_json(self.intent_path, tampered)
        with self.assertRaisesRegex(rc.ContractError, "signature verification failed"):
            self.validate()

    def test_noncanonical_intent_is_rejected_before_signature(self) -> None:
        self.intent_path.write_text(json.dumps(self.intent, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(rc.ContractError, "not canonical JSON"):
            self.validate()

    def test_expired_intent_is_rejected(self) -> None:
        with self.assertRaisesRegex(rc.ContractError, "expired"):
            rc.validate_intent(
                self.intent_path,
                self.signature,
                self.allowed,
                self.policy_dir,
                dt.datetime(2026, 8, 31, 1, 0, tzinfo=dt.timezone.utc),
            )

    def test_unknown_intent_field_is_rejected(self) -> None:
        value = dict(self.intent, surprise=True)
        with self.assertRaisesRegex(rc.ContractError, "unknown fields"):
            rc.validate_intent_value(value, self.policy, now=self.now)

    def test_multiple_operator_keys_are_rejected_before_signature_verification(self) -> None:
        extra = self.root / "multiple-operator-signers"
        public = self.key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        extra.write_text(f"hermawan22 {public}\nhermawan22 {public}\n", encoding="utf-8")
        with self.assertRaisesRegex(rc.ContractError, "exactly one named release operator key"):
            rc.validate_intent(
                self.intent_path,
                self.signature,
                extra,
                self.policy_dir,
                self.now,
            )

    def test_operator_aliases_are_rejected(self) -> None:
        one_key = self.root / "aliased-operator-signers"
        public = self.key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        one_key.write_text(f"hermawan22,backup-operator {public}\n", encoding="utf-8")
        with self.assertRaisesRegex(rc.ContractError, "exactly one hermawan22 identity"):
            rc.validate_intent(
                self.intent_path,
                self.signature,
                one_key,
                self.policy_dir,
                self.now,
            )

    def test_non_bootstrap_signer_identity_is_rejected(self) -> None:
        value = dict(self.intent, signer_identity="other-operator")
        with self.assertRaisesRegex(rc.ContractError, "configured release operator: hermawan22"):
            rc.validate_intent_value(value, self.policy, now=self.now)

    def test_noncanonical_registry_host_is_rejected(self) -> None:
        self.policy["registry_host"] = "registry.example.invalid"
        self.policy["artifact_repository"] = "registry.example.invalid/arconath/example-api"
        with self.assertRaisesRegex(rc.ContractError, "canonical internal Distribution host"):
            rc.validate_policy(self.policy)

    def test_artifact_outside_canonical_namespace_is_rejected(self) -> None:
        self.policy["artifact_repository"] = "registry.arconath.internal/other/example-api"
        with self.assertRaisesRegex(rc.ContractError, "canonical arconath/ namespace"):
            rc.validate_policy(self.policy)

    def test_registry_repository_traversal_is_rejected(self) -> None:
        self.intent["artifact"]["repository"] = (
            "registry.arconath.internal/arconath/../other"
        )
        with self.assertRaisesRegex(rc.ContractError, "invalid artifact.repository"):
            rc.validate_intent_value(self.intent, self.policy, now=self.now)

    def test_invalid_registry_port_is_rejected(self) -> None:
        self.policy["registry_host"] = "registry.arconath.internal:99999"
        with self.assertRaisesRegex(rc.ContractError, "port"):
            rc.validate_policy(self.policy)

    def test_policy_can_pin_central_component_build_inputs(self) -> None:
        self.policy["build"]["build_args"] = {
            "BASE_IMAGE": "quay.io/keycloak/keycloak:26.7.2@sha256:" + "a" * 64,
            "BUILDER_IMAGE": "docker.io/library/maven:3.9.11@sha256:" + "b" * 64,
            "UPSTREAM_VERSION": "26.7.2",
        }
        validated = rc.validate_policy(self.policy)
        self.assertEqual(validated["build"]["build_args"]["UPSTREAM_VERSION"], "26.7.2")

    def test_policy_rejects_mutable_component_build_input(self) -> None:
        self.policy["build"]["build_args"] = {"BASE_IMAGE": "quay.io/keycloak/keycloak:latest"}
        with self.assertRaisesRegex(rc.ContractError, "pinned by sha256 digest"):
            rc.validate_policy(self.policy)

    def test_policy_reserves_source_identity_build_arguments(self) -> None:
        self.policy["build"]["build_args"] = {"SOURCE_REVISION": "a" * 40}
        with self.assertRaisesRegex(rc.ContractError, "reserved"):
            rc.validate_policy(self.policy)

    def test_disabled_policy_fails_closed(self) -> None:
        self.policy["enabled"] = False
        write_json(self.policy_dir / "example-api.json", self.policy)
        with self.assertRaisesRegex(rc.ContractError, "disabled"):
            self.validate()

    def test_exact_artifact_digest_survives_transport_and_publication(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive)
        record = rc.verify_published(
            self.intent, evidence, archive, "sha256:" + "4" * 64, RELEASE_CONTROL_SHA
        )
        self.assertEqual(record["artifact"]["digest"], evidence["artifact"]["digest"])
        self.assertEqual(record["release_control_sha"], RELEASE_CONTROL_SHA)
        self.assertEqual(
            record["artifact"]["reference"],
            "registry.arconath.internal/arconath/example-api@sha256:" + "4" * 64,
        )

    def test_slsa_provenance_binds_source_artifact_and_control_revision(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive)
        provenance = rc.build_provenance(self.intent, evidence, RELEASE_CONTROL_SHA)
        rc.validate_provenance(provenance, self.intent, evidence, RELEASE_CONTROL_SHA)
        self.assertEqual(provenance["subject"][0]["digest"]["sha256"], "4" * 64)
        self.assertEqual(
            provenance["predicate"]["buildDefinition"]["internalParameters"]["release_control_sha"],
            RELEASE_CONTROL_SHA,
        )

        tampered = json.loads(json.dumps(provenance))
        tampered["predicate"]["buildDefinition"]["externalParameters"]["source_tree"] = "5" * 40
        with self.assertRaisesRegex(rc.ContractError, "external parameters"):
            rc.validate_provenance(tampered, self.intent, evidence, RELEASE_CONTROL_SHA)

    def test_changed_archive_is_rejected(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive)
        with archive.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaisesRegex(rc.ContractError, "archive SHA-256 differs"):
            rc.verify_published(self.intent, evidence, archive, "sha256:" + "4" * 64, RELEASE_CONTROL_SHA)

    def test_published_digest_mismatch_is_rejected(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive)
        with self.assertRaisesRegex(rc.ContractError, "published digest differs"):
            rc.verify_published(self.intent, evidence, archive, "sha256:" + "5" * 64, RELEASE_CONTROL_SHA)

    def test_promotion_and_rollback_are_bound_to_exact_digest(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive)
        record = rc.verify_published(self.intent, evidence, archive, "sha256:" + "4" * 64, RELEASE_CONTROL_SHA)
        promotion, rollback = rc.release_manifests(self.intent, record)
        self.assertEqual(promotion["artifact"]["digest"], "sha256:" + "4" * 64)
        self.assertEqual(promotion["rollback_digest"], "sha256:" + "1" * 64)
        self.assertEqual(promotion["release_control_sha"], RELEASE_CONTROL_SHA)
        self.assertEqual(rollback["replace_digest"], "sha256:" + "4" * 64)
        self.assertEqual(rollback["restore_digest"], "sha256:" + "1" * 64)
        self.assertEqual(rollback["release_control_sha"], RELEASE_CONTROL_SHA)

    def test_rollback_must_not_point_to_new_release(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive)
        record = rc.verify_published(self.intent, evidence, archive, "sha256:" + "4" * 64, RELEASE_CONTROL_SHA)
        self.intent["rollback"]["previous_digest"] = "sha256:" + "4" * 64
        with self.assertRaisesRegex(rc.ContractError, "must differ"):
            rc.release_manifests(self.intent, record)

    def test_promotion_rejects_digest_different_from_publish_job(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive)
        record = rc.verify_published(self.intent, evidence, archive, "sha256:" + "4" * 64, RELEASE_CONTROL_SHA)
        with self.assertRaisesRegex(rc.ContractError, "publish job output"):
            rc.release_manifests(self.intent, record, "sha256:" + "5" * 64)

    def test_source_handoff_is_canonical_and_binds_ciphertext_and_run(self) -> None:
        plaintext = self.root / "product.tar"
        ciphertext = self.root / "product.tar.age"
        plaintext.write_bytes(b"private source archive")
        ciphertext.write_bytes(b"age-encrypted source archive")
        handoff = rc.create_handoff(
            self.intent,
            kind="source",
            run_id="123456789",
            plaintext=plaintext,
            ciphertext=ciphertext,
            recipient=AGE_RECIPIENT,
        )
        handoff_path = self.root / "source-handoff.json"
        write_json(handoff_path, handoff)
        rc.verify_handoff(
            handoff_path,
            ciphertext,
            self.intent_path,
            kind="source",
            run_id="123456789",
            recipient=AGE_RECIPIENT,
            plaintext_path=plaintext,
        )
        self.assertEqual(handoff["ciphertext"]["filename"], "product.tar.age")
        self.assertEqual(handoff["ciphertext"]["encryption"], "age-v1")

    def test_source_handoff_rejects_ciphertext_tampering_and_replay(self) -> None:
        plaintext = self.root / "product.tar"
        ciphertext = self.root / "product.tar.age"
        plaintext.write_bytes(b"private source archive")
        ciphertext.write_bytes(b"age-encrypted source archive")
        handoff_path = self.root / "source-handoff.json"
        write_json(
            handoff_path,
            rc.create_handoff(
                self.intent,
                kind="source",
                run_id="123456789",
                plaintext=plaintext,
                ciphertext=ciphertext,
                recipient=AGE_RECIPIENT,
            ),
        )
        ciphertext.write_bytes(b"tampered ciphertext")
        with self.assertRaisesRegex(rc.ContractError, "ciphertext SHA-256 differs"):
            rc.verify_handoff(
                handoff_path,
                ciphertext,
                self.intent_path,
                kind="source",
                run_id="123456789",
                recipient=AGE_RECIPIENT,
            )
        ciphertext.write_bytes(b"age-encrypted source archive")
        with self.assertRaisesRegex(rc.ContractError, "run_id does not match"):
            rc.verify_handoff(
                handoff_path,
                ciphertext,
                self.intent_path,
                kind="source",
                run_id="987654321",
                recipient=AGE_RECIPIENT,
            )

    def test_candidate_handoff_uses_a_distinct_canonical_filename(self) -> None:
        plaintext = self.root / "candidate.oci.tar"
        ciphertext = self.root / "candidate.oci.tar.age"
        plaintext.write_bytes(b"oci archive")
        ciphertext.write_bytes(b"age-encrypted oci archive")
        handoff = rc.create_handoff(
            self.intent,
            kind="candidate",
            run_id="123456789",
            plaintext=plaintext,
            ciphertext=ciphertext,
            recipient=AGE_RECIPIENT,
        )
        self.assertEqual(handoff["handoff_type"], "candidate")
        self.assertEqual(handoff["ciphertext"]["filename"], "candidate.oci.tar.age")


if __name__ == "__main__":
    unittest.main(verbosity=2)
