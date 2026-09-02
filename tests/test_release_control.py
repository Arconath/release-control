#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import base64
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_CONTROL_SHA = "a" * 40
AGE_RECIPIENT = "age1" + "b" * 32
MODULE_PATH = ROOT / "scripts" / "release_control.py"
SPEC = importlib.util.spec_from_file_location("release_control", MODULE_PATH)
assert SPEC and SPEC.loader
rc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rc)

OCI_CONFIG = rc.canonical_bytes(
    {
        "architecture": "amd64",
        "config": {},
        "os": "linux",
        "rootfs": {"diff_ids": [], "type": "layers"},
    }
)
OCI_CONFIG_DIGEST = "sha256:" + hashlib.sha256(OCI_CONFIG).hexdigest()
OCI_MANIFEST = rc.canonical_bytes(
    {
        "config": {
            "digest": OCI_CONFIG_DIGEST,
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(OCI_CONFIG),
        },
        "layers": [],
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
    }
)
OCI_DIGEST = "sha256:" + hashlib.sha256(OCI_MANIFEST).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_bytes(rc.canonical_bytes(value))


class ReleaseControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy_dir = self.root / "policies"
        self.policy_dir.mkdir()
        self.policy = {
            "artifact_lock": {
                "desired_state_path": "apps/releasepassport/desired-state.yaml",
                "key": "releasepassport-api",
                "proposal_only": True,
                "repository": "Arconath/platform-apps",
                "workloads": ["Deployment/releasepassport-api"],
            },
            "artifact_repository": "registry.arconath.internal/arconath/releasepassport/api",
            "build": {
                "context": ".",
                "dockerfile": "Dockerfile",
                "identity_args": {
                    "revision": ["REVISION"],
                    "version": ["VERSION"],
                },
                "platform": "linux/amd64",
            },
            "enabled": True,
            "max_intent_age_seconds": 86400,
            "policy_id": "releasepassport-api",
            "product_id": "release-passport",
            "registry_host": "registry.arconath.internal",
            "schema_version": 1,
            "source_repository": "Arconath/releasepassport",
            "verification_commands": [["./scripts/verify.sh"]],
        }
        write_json(self.policy_dir / "releasepassport-api.json", self.policy)
        self.now = dt.datetime(2026, 8, 31, 0, 30, tzinfo=dt.timezone.utc)
        self.intent = {
            "artifact": {
                "repository": "registry.arconath.internal/arconath/releasepassport/api",
                "version": "1.2.3",
            },
            "expires_at": "2026-08-31T01:00:00Z",
            "intent_id": "releasepassport-api-1.2.3",
            "issued_at": "2026-08-31T00:00:00Z",
            "policy_id": "releasepassport-api",
            "rollback": {
                "previous_digest": "sha256:" + "1" * 64,
                "reason": "Restore the last verified production image.",
            },
            "schema_version": 1,
            "signer_identities": ["release-operator", "second-operator"],
            "source": {
                "repository": "Arconath/releasepassport",
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
        self.second_key = self.root / "release-key-two"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.second_key)],
            check=True,
        )
        public = (self.key.with_suffix(".pub")).read_text(encoding="utf-8").strip()
        second_public = (self.second_key.with_suffix(".pub")).read_text(encoding="utf-8").strip()
        self.allowed = self.root / "allowed_signers"
        self.allowed.write_text(
            f"release-operator {public}\nsecond-operator {second_public}\n", encoding="utf-8"
        )
        self.signatures = []
        for index, key in enumerate((self.key, self.second_key), 1):
            subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(key),
                    "-n",
                    rc.NAMESPACE,
                    str(self.intent_path),
                ],
                check=True,
                capture_output=True,
            )
            generated = Path(f"{self.intent_path}.sig")
            signature = Path(f"{self.intent_path}.sig.{index}")
            generated.rename(signature)
            self.signatures.append(signature)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_oci(
        self,
        digest: str | None = None,
        *,
        include_manifest: bool = True,
        corrupt_manifest: bool = False,
    ) -> Path:
        digest = digest or OCI_DIGEST
        index = rc.canonical_bytes(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": digest,
                        "size": len(OCI_MANIFEST),
                    }
                ],
            }
        )
        layout = rc.canonical_bytes({"imageLayoutVersion": "1.0.0"})
        archive = self.root / "candidate.oci.tar"
        with tarfile.open(archive, "w") as handle:
            for name, data in (
                ("oci-layout", layout),
                ("index.json", index),
                (f"blobs/sha256/{OCI_CONFIG_DIGEST.removeprefix('sha256:')}", OCI_CONFIG),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))
            if include_manifest:
                manifest = (
                    OCI_MANIFEST[:-1] + b" " if corrupt_manifest else OCI_MANIFEST
                )
                info = tarfile.TarInfo(
                    f"blobs/sha256/{digest.removeprefix('sha256:')}"
                )
                info.size = len(manifest)
                handle.addfile(info, io.BytesIO(manifest))
        return archive

    def make_final_release(self) -> tuple[Path, dict, dict]:
        archive = self.make_oci()
        evidence_dir = self.root / "evidence"
        evidence_dir.mkdir()
        sbom = evidence_dir / "sbom.spdx.json"
        write_json(
            sbom,
            {
                "packages": [
                    {
                        "licenseConcluded": "Apache-2.0",
                        "licenseDeclared": "Apache-2.0",
                        "name": "example",
                    }
                ],
                "spdxVersion": "SPDX-2.3",
            },
        )
        licenses = evidence_dir / "licenses.json"
        write_json(
            licenses,
            {
                "package_count": 1,
                "packages": [{"licenses": ["Apache-2.0"], "name": "example"}],
                "schema_version": 1,
                "spdx_version": "SPDX-2.3",
            },
        )
        vulnerabilities = evidence_dir / "vulnerabilities.json"
        write_json(vulnerabilities, {"descriptor": {}, "matches": []})
        provenance = evidence_dir / "provenance.intoto.json"
        write_json(provenance, rc.provenance_evidence(self.intent, archive, RELEASE_CONTROL_SHA))
        build_path = evidence_dir / "build-evidence.json"
        build_evidence = rc.build_evidence(self.intent, archive, RELEASE_CONTROL_SHA)
        write_json(build_path, build_evidence)
        lock_path = evidence_dir / "evidence-lock.json"
        write_json(
            lock_path,
            rc.create_evidence_lock(
                self.intent,
                build_evidence,
                build_path,
                archive,
                sbom,
                licenses,
                provenance,
                vulnerabilities,
                RELEASE_CONTROL_SHA,
            ),
        )
        base = rc.verify_published(
            self.intent,
            build_evidence,
            archive,
            OCI_DIGEST,
            RELEASE_CONTROL_SHA,
        )
        write_json(evidence_dir / "artifact.sigstore.json", {"bundle": "artifact"})
        attestation_specs = (
            (
                "build-evidence.attestation.sigstore.json",
                build_evidence,
                "https://arconath.com/BuildEvidence/v1",
            ),
            (
                "license.attestation.sigstore.json",
                json.loads(licenses.read_text(encoding="utf-8")),
                "https://arconath.com/LicenseEvidence/v1",
            ),
            (
                "sbom.attestation.sigstore.json",
                json.loads(sbom.read_text(encoding="utf-8")),
                "https://spdx.dev/Document",
            ),
            (
                "provenance.attestation.sigstore.json",
                json.loads(provenance.read_text(encoding="utf-8")),
                "https://slsa.dev/provenance/v1",
            ),
            (
                "vulnerability.attestation.sigstore.json",
                json.loads(vulnerabilities.read_text(encoding="utf-8")),
                "https://arconath.com/VulnerabilityScan/v1",
            ),
        )
        for filename, predicate, predicate_type in attestation_specs:
            statement = {
                "_type": "https://in-toto.io/Statement/v0.1",
                "predicate": predicate,
                "predicateType": predicate_type,
                "subject": [
                    {
                        "digest": {"sha256": OCI_DIGEST.removeprefix("sha256:")},
                        "name": self.intent["artifact"]["repository"],
                    }
                ],
            }
            write_json(
                evidence_dir / filename,
                {
                    "payload": base64.b64encode(rc.canonical_bytes(statement)).decode(
                        "ascii"
                    ),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [
                        {
                            "keyid": "",
                            "sig": base64.b64encode(b"verified-by-cosign").decode(
                                "ascii"
                            ),
                        }
                    ],
                },
            )
        record = rc.finalize_release(
            self.intent,
            base,
            evidence_dir,
            archive,
            RELEASE_CONTROL_SHA,
        )
        write_json(evidence_dir / "release-record.json", record)
        return archive, build_evidence, record

    def make_verified_attestation(
        self,
        predicate: dict[str, object],
        *,
        predicate_type: str,
        artifact_digest: str = OCI_DIGEST,
    ) -> Path:
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicate": predicate,
            "predicateType": predicate_type,
            "subject": [
                {
                    "digest": {
                        "sha256": artifact_digest.removeprefix("sha256:")
                    },
                    "name": self.intent["artifact"]["repository"],
                }
            ],
        }
        envelope = {
            "payload": base64.b64encode(rc.canonical_bytes(statement)).decode("ascii"),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [
                {
                    "keyid": "",
                    "sig": base64.b64encode(b"verified-by-cosign").decode("ascii"),
                }
            ],
        }
        path = self.root / "verified-attestation.json"
        write_json(path, envelope)
        return path

    def validate(self) -> tuple[dict, dict]:
        return rc.validate_intent(
            self.intent_path,
            self.signatures,
            self.allowed,
            self.policy_dir,
            self.now,
        )

    def test_valid_signed_intent_binds_full_source_identity(self) -> None:
        intent, policy = self.validate()
        self.assertEqual(intent["source"]["commit_sha"], "2" * 40)
        self.assertEqual(intent["source"]["tree_sha"], "3" * 40)
        self.assertEqual(policy["artifact_repository"], intent["artifact"]["repository"])

    def test_build_evidence_binds_the_protected_release_control_sha(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive, RELEASE_CONTROL_SHA)
        evidence["release_control_sha"] = "b" * 40
        with self.assertRaisesRegex(rc.ContractError, "release-control SHA"):
            rc.verify_published(
                self.intent,
                evidence,
                archive,
                OCI_DIGEST,
                RELEASE_CONTROL_SHA,
            )

    def test_provenance_file_is_a_slsa_predicate_not_a_nested_statement(self) -> None:
        predicate = rc.provenance_evidence(
            self.intent,
            self.make_oci(),
            RELEASE_CONTROL_SHA,
        )
        self.assertEqual(set(predicate), {"buildDefinition", "runDetails"})
        self.assertNotIn("predicate", predicate)
        self.assertEqual(
            predicate["buildDefinition"]["internalParameters"]["release_control_sha"],
            RELEASE_CONTROL_SHA,
        )

    def test_verified_attestation_must_contain_the_exact_local_predicate(self) -> None:
        predicate = {"build": "exact", "schema_version": 1}
        predicate_path = self.root / "predicate.json"
        write_json(predicate_path, predicate)
        envelope = self.make_verified_attestation(
            predicate,
            predicate_type="https://arconath.com/BuildEvidence/v1",
        )
        rc.verify_attestation_payload(
            envelope,
            predicate_path,
            "https://arconath.com/BuildEvidence/v1",
            self.intent["artifact"]["repository"],
            OCI_DIGEST,
        )

        write_json(predicate_path, {"build": "tampered", "schema_version": 1})
        with self.assertRaisesRegex(rc.ContractError, "predicate does not match"):
            rc.verify_attestation_payload(
                envelope,
                predicate_path,
                "https://arconath.com/BuildEvidence/v1",
                self.intent["artifact"]["repository"],
                OCI_DIGEST,
            )

    def test_verified_attestation_must_bind_the_exact_artifact_digest(self) -> None:
        predicate = {"schema_version": 1}
        predicate_path = self.root / "predicate.json"
        write_json(predicate_path, predicate)
        envelope = self.make_verified_attestation(
            predicate,
            predicate_type="https://arconath.com/BuildEvidence/v1",
            artifact_digest="sha256:" + "f" * 64,
        )
        with self.assertRaisesRegex(rc.ContractError, "subject digest does not match"):
            rc.verify_attestation_payload(
                envelope,
                predicate_path,
                "https://arconath.com/BuildEvidence/v1",
                self.intent["artifact"]["repository"],
                OCI_DIGEST,
            )

    def test_verified_attestation_requires_a_nonempty_signature(self) -> None:
        predicate = {"schema_version": 1}
        predicate_path = self.root / "predicate.json"
        write_json(predicate_path, predicate)
        envelope_path = self.make_verified_attestation(
            predicate,
            predicate_type="https://arconath.com/BuildEvidence/v1",
        )
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        envelope["signatures"] = []
        write_json(envelope_path, envelope)

        with self.assertRaisesRegex(rc.ContractError, "signature is missing"):
            rc.verify_attestation_payload(
                envelope_path,
                predicate_path,
                "https://arconath.com/BuildEvidence/v1",
                self.intent["artifact"]["repository"],
                OCI_DIGEST,
            )

        envelope["signatures"] = [{"sig": "not-base64"}]
        write_json(envelope_path, envelope)
        with self.assertRaisesRegex(rc.ContractError, "signature 0 is invalid"):
            rc.verify_attestation_payload(
                envelope_path,
                predicate_path,
                "https://arconath.com/BuildEvidence/v1",
                self.intent["artifact"]["repository"],
                OCI_DIGEST,
            )

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
                self.signatures,
                self.allowed,
                self.policy_dir,
                dt.datetime(2026, 8, 31, 1, 0, tzinfo=dt.timezone.utc),
            )

    def test_unknown_intent_field_is_rejected(self) -> None:
        value = dict(self.intent, surprise=True)
        with self.assertRaisesRegex(rc.ContractError, "unknown fields"):
            rc.validate_intent_value(value, self.policy, now=self.now)

    def test_release_intent_requires_two_distinct_signatures(self) -> None:
        self.signatures[1].unlink()
        with self.assertRaisesRegex(rc.ContractError, "missing detached signature"):
            self.validate()

    def test_release_intent_rejects_one_or_duplicate_signer_identity(self) -> None:
        for identities in (["release-operator"], ["release-operator", "release-operator"]):
            with self.subTest(identities=identities):
                value = dict(self.intent, signer_identities=identities)
                with self.assertRaisesRegex(
                    rc.ContractError, "exactly two distinct signer identities"
                ):
                    rc.validate_intent_value(value, self.policy, now=self.now)

    def test_single_operator_key_is_rejected_before_signature_verification(self) -> None:
        single = self.root / "single-operator-signers"
        single.write_text(self.allowed.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(rc.ContractError, "at least two distinct named operator keys"):
            rc.validate_intent(
                self.intent_path,
                self.signatures,
                single,
                self.policy_dir,
                self.now,
            )

    def test_two_operator_aliases_cannot_share_one_key(self) -> None:
        one_key = self.root / "aliased-operator-signers"
        public = self.key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        one_key.write_text(f"release-operator,second-operator {public}\n", encoding="utf-8")
        with self.assertRaisesRegex(rc.ContractError, "at least two distinct named operator keys"):
            rc.validate_intent(
                self.intent_path,
                self.signatures,
                one_key,
                self.policy_dir,
                self.now,
            )

    def test_release_intent_rejects_two_signatures_from_one_key(self) -> None:
        public = self.key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        second_public = self.second_key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        mixed_key_signers = self.root / "mixed-key-signers"
        mixed_key_signers.write_text(
            f"release-operator {public}\n"
            f"second-operator {public}\n"
            f"unused-operator {second_public}\n",
            encoding="utf-8",
        )
        self.signatures[1].write_bytes(self.signatures[0].read_bytes())
        with self.assertRaisesRegex(rc.ContractError, "distinct cryptographic keys"):
            rc.validate_intent(
                self.intent_path,
                self.signatures,
                mixed_key_signers,
                self.policy_dir,
                self.now,
            )

    def test_release_governance_requires_two_named_codeowners(self) -> None:
        codeowners = self.root / "CODEOWNERS"
        settings = self.root / "repository-settings.json"
        settings_value = json.loads(
            (ROOT / "bootstrap/repository-settings.json").read_text(encoding="utf-8")
        )
        write_json(settings, settings_value)
        patterns = settings_value["release_governance"]["required_codeowner_patterns"]
        codeowners.write_text(
            "".join(f"{pattern} @release-one\n" for pattern in patterns),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(rc.ContractError, "two distinct named CODEOWNER"):
            rc.validate_governance(codeowners, self.allowed, settings)

        codeowners.write_text(
            "".join(
                f"{pattern} @release-one @release-two\n" for pattern in patterns
            ),
            encoding="utf-8",
        )
        readiness = rc.validate_governance(codeowners, self.allowed, settings)
        self.assertEqual(readiness["named_codeowners"], 2)
        self.assertEqual(readiness["protected_codeowner_rules_ready"], len(patterns))
        self.assertEqual(readiness["release_signer_identities"], 2)
        self.assertEqual(readiness["release_signer_keys"], 2)
        self.assertEqual(readiness["missing_codeowner_rules"], [])
        self.assertEqual(readiness["blocking_reasons"], [])
        self.assertTrue(readiness["checked_in_contract_ready"])
        self.assertEqual(readiness["status"], "ready")
        self.assertTrue(readiness["merge_ready"])
        self.assertEqual(readiness["live_github_configuration"], "unverified")

    def test_incomplete_governance_diagnostic_cannot_claim_live_readiness(self) -> None:
        readiness = rc.validate_governance(
            ROOT / ".github/CODEOWNERS",
            ROOT / "policies/release-signers",
            ROOT / "bootstrap/repository-settings.json",
            require_ready=False,
        )
        self.assertFalse(readiness["checked_in_contract_ready"])
        self.assertEqual(readiness["status"], "blocked")
        self.assertFalse(readiness["merge_ready"])
        self.assertIn("CODEOWNERS_INCOMPLETE", readiness["blocking_reasons"])
        self.assertIn("CODEOWNER_RULES_UNDERPROTECTED", readiness["blocking_reasons"])
        self.assertIn("RELEASE_SIGNER_KEYS_INCOMPLETE", readiness["blocking_reasons"])
        self.assertEqual(readiness["live_github_configuration"], "unverified")
        self.assertEqual(readiness["minimum_named_codeowners"], 2)
        self.assertEqual(readiness["minimum_release_signer_keys"], 2)
        self.assertEqual(readiness["minimum_environment_reviewers"], 2)

    def test_merge_readiness_reports_each_local_gate_and_external_hold(self) -> None:
        readiness = rc.merge_readiness(
            ROOT / ".github/CODEOWNERS",
            ROOT / "policies/release-signers",
            ROOT / "bootstrap/repository-settings.json",
            ROOT / "policies/products",
            ROOT / "contracts",
            ROOT / ".github/workflows",
        )
        self.assertEqual(readiness["status"], "blocked")
        self.assertFalse(readiness["merge_ready"])
        self.assertFalse(readiness["checked_in_contract_ready"])
        self.assertEqual(readiness["live_github_configuration"], "unverified")
        self.assertEqual(
            [check["name"] for check in readiness["checks"]],
            ["governance", "contracts", "policies", "workflows"],
        )
        self.assertIn("GITHUB_CONFIGURATION_UNVERIFIED", readiness["external_blockers"])
        self.assertIn("RELEASE_SIGNER_KEYS_INCOMPLETE", readiness["blocking_reasons"])

    def test_contract_and_workflow_inventories_are_closed_world(self) -> None:
        contracts = rc.validate_contract_inventory(ROOT / "contracts")
        workflows = rc.validate_workflow_policy(ROOT / ".github/workflows")
        self.assertEqual(contracts, {"schema_files": 11})
        self.assertEqual(workflows["workflow_files"], 2)
        self.assertEqual(workflows["runner_blocks"], 7)
        self.assertEqual(workflows["permission_blocks"], 8)
        self.assertGreater(workflows["external_actions"], 0)

    def test_contract_inventory_rejects_a_schema_id_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            contract_dir = Path(directory)
            for source in (ROOT / "contracts").iterdir():
                target = contract_dir / source.name
                target.write_bytes(source.read_bytes())
            aliased = contract_dir / "source-handoff.schema.json"
            value = json.loads(aliased.read_text(encoding="utf-8"))
            value["$id"] = "https://release-control.arconath.com/contracts/alias.json"
            write_json(aliased, value)
            with self.assertRaisesRegex(rc.ContractError, r"schema \$id must be"):
                rc.validate_contract_inventory(contract_dir)

    def test_merge_readiness_cli_has_explicit_fail_closed_mode(self) -> None:
        command = [
            "python3",
            str(MODULE_PATH),
            "merge-readiness",
            "--codeowners",
            str(ROOT / ".github/CODEOWNERS"),
            "--allowed-signers",
            str(ROOT / "policies/release-signers"),
            "--settings",
            str(ROOT / "bootstrap/repository-settings.json"),
            "--policy-dir",
            str(ROOT / "policies/products"),
            "--contract-dir",
            str(ROOT / "contracts"),
            "--workflow-dir",
            str(ROOT / ".github/workflows"),
        ]
        diagnostic = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stderr)
        value = json.loads(diagnostic.stdout)
        self.assertEqual(value["status"], "blocked")
        strict = subprocess.run(
            [*command, "--require-ready"], capture_output=True, text=True, check=False
        )
        self.assertNotEqual(strict.returncode, 0)
        self.assertIn("merge-readiness is blocked", strict.stderr)

    def test_readiness_diagnostics_enumerate_source_reader_secret_without_value(self) -> None:
        readiness = rc.validate_governance(
            ROOT / ".github/CODEOWNERS",
            ROOT / "policies/release-signers",
            ROOT / "bootstrap/repository-settings.json",
            require_ready=False,
        )
        self.assertEqual(
            readiness["runtime_prerequisites"]["repository_secrets"],
            ["SOURCE_READER_PRIVATE_KEY"],
        )
        self.assertNotIn("BEGIN", json.dumps(readiness["runtime_prerequisites"]))

    def test_merge_readiness_cli_has_permissive_diagnostic_and_strict_mode(self) -> None:
        command = [
            "python3",
            str(MODULE_PATH),
            "merge-readiness",
            "--codeowners",
            str(ROOT / ".github/CODEOWNERS"),
            "--allowed-signers",
            str(ROOT / "policies/release-signers"),
            "--settings",
            str(ROOT / "bootstrap/repository-settings.json"),
            "--policy-dir",
            str(ROOT / "policies/products"),
            "--contract-dir",
            str(ROOT / "contracts"),
            "--workflow-dir",
            str(ROOT / ".github/workflows"),
        ]
        diagnostic = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stderr)
        value = json.loads(diagnostic.stdout)
        self.assertFalse(value["merge_ready"])
        self.assertIn(
            "SOURCE_READER_PRIVATE_KEY",
            value["external_prerequisites"]["repository_secrets"],
        )

        strict = subprocess.run(
            [*command, "--require-ready"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(strict.returncode, 0)
        self.assertIn("merge-readiness is blocked", strict.stderr)

    def test_release_governance_requires_source_handoff_reviewers(self) -> None:
        codeowners = self.root / "CODEOWNERS"
        settings = self.root / "repository-settings.json"
        settings_value = json.loads(
            (ROOT / "bootstrap/repository-settings.json").read_text(encoding="utf-8")
        )
        settings_value["environments"]["source-handoff"]["required_reviewers"] = 1
        write_json(settings, settings_value)
        patterns = settings_value["release_governance"]["required_codeowner_patterns"]
        codeowners.write_text(
            "".join(f"{pattern} @release-one @release-two\n" for pattern in patterns),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(rc.ContractError, "source-handoff.required_reviewers"):
            rc.validate_governance(codeowners, self.allowed, settings)

    def test_release_governance_casefolds_codeowner_accounts(self) -> None:
        codeowners = self.root / "CODEOWNERS"
        settings = self.root / "repository-settings.json"
        settings_value = json.loads(
            (ROOT / "bootstrap/repository-settings.json").read_text(encoding="utf-8")
        )
        write_json(settings, settings_value)
        patterns = settings_value["release_governance"]["required_codeowner_patterns"]
        codeowners.write_text(
            "".join(f"{pattern} @release-one @RELEASE-ONE\n" for pattern in patterns),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(rc.ContractError, "two distinct named CODEOWNER"):
            rc.validate_governance(codeowners, self.allowed, settings)

    def test_release_governance_requires_two_owners_on_every_protected_path(self) -> None:
        codeowners = self.root / "CODEOWNERS"
        settings = self.root / "repository-settings.json"
        settings_value = json.loads(
            (ROOT / "bootstrap/repository-settings.json").read_text(encoding="utf-8")
        )
        write_json(settings, settings_value)
        patterns = settings_value["release_governance"]["required_codeowner_patterns"]
        codeowners.write_text(
            "".join(
                f"{pattern} @release-one @release-two\n"
                if pattern == "*"
                else f"{pattern} @release-one\n"
                for pattern in patterns
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(rc.ContractError, "protected CODEOWNERS rule"):
            rc.validate_governance(codeowners, self.allowed, settings)

    def test_release_governance_rejects_an_underprotected_narrow_rule(self) -> None:
        codeowners = self.root / "CODEOWNERS"
        settings = self.root / "repository-settings.json"
        settings_value = json.loads(
            (ROOT / "bootstrap/repository-settings.json").read_text(encoding="utf-8")
        )
        write_json(settings, settings_value)
        patterns = settings_value["release_governance"]["required_codeowner_patterns"]
        codeowners.write_text(
            "".join(f"{pattern} @release-one @release-two\n" for pattern in patterns)
            + "/.github/workflows/release.yml @release-one\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(rc.ContractError, "every CODEOWNERS rule"):
            rc.validate_governance(codeowners, self.allowed, settings)

    def test_noncanonical_registry_host_is_rejected(self) -> None:
        self.policy["registry_host"] = "registry.example.invalid"
        self.policy["artifact_repository"] = "registry.example.invalid/arconath/releasepassport-api"
        with self.assertRaisesRegex(rc.ContractError, "canonical internal Distribution host"):
            rc.validate_policy(self.policy)

    def test_artifact_outside_canonical_namespace_is_rejected(self) -> None:
        self.policy["artifact_repository"] = "registry.arconath.internal/other/releasepassport-api"
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

    def test_policy_rejects_empty_identity_argument_contract(self) -> None:
        self.policy["build"]["identity_args"] = {}
        with self.assertRaisesRegex(rc.ContractError, "non-empty object"):
            rc.validate_policy(self.policy)

    def test_policy_rejects_oversized_build_argument_value(self) -> None:
        self.policy["build"]["build_args"] = {"PROFILE": "x" * 513}
        with self.assertRaisesRegex(rc.ContractError, "at most 512"):
            rc.validate_policy(self.policy)

    def test_enabled_policy_requires_canonical_product_binding(self) -> None:
        self.policy.pop("product_id")
        with self.assertRaisesRegex(rc.ContractError, "canonical product_id"):
            rc.validate_policy(self.policy)

    def test_policy_source_must_match_the_canonical_product_binding(self) -> None:
        self.policy["product_id"] = "foundiqo"
        with self.assertRaisesRegex(rc.ContractError, "does not match canonical product_id"):
            rc.validate_policy(self.policy)

    def test_policy_rejects_artifact_lock_binding_outside_canonical_product(self) -> None:
        self.policy["artifact_lock"]["workloads"] = ["Deployment/not-releasepassport"]
        with self.assertRaisesRegex(rc.ContractError, "artifact-lock binding"):
            rc.validate_policy(self.policy)

    def test_identity_build_arguments_come_from_signed_intent(self) -> None:
        output = self.root / "github-output"
        rc.emit_outputs(output, self.intent, rc.validate_policy(self.policy))
        values = dict(
            line.split("=", 1)
            for line in output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(
            json.loads(values["identity-build-args-json"]),
            {"REVISION": "2" * 40, "VERSION": "1.2.3"},
        )

    def test_artifact_lock_proposal_is_exact_and_never_mutates_gitops(self) -> None:
        _, _, record = self.make_final_release()
        proposal = rc.artifact_lock_proposal(
            self.intent,
            self.policy,
            record,
            expected_digest=OCI_DIGEST,
            release_control_sha=RELEASE_CONTROL_SHA,
            evidence_dir=self.root / "evidence",
        )
        self.assertTrue(proposal["proposal_only"])
        self.assertFalse(proposal["deployment_eligibility"])
        self.assertEqual(
            proposal["target"],
            {
                "artifact_lock_key": "releasepassport-api",
                "desired_state_path": "apps/releasepassport/desired-state.yaml",
                "product_id": "release-passport",
                "repository": "Arconath/platform-apps",
                "workloads": ["Deployment/releasepassport-api"],
            },
        )
        self.assertEqual(proposal["release"]["artifact"]["digest"], OCI_DIGEST)
        self.assertEqual(
            proposal["rollback"]["digest"], "sha256:" + "1" * 64
        )

    def test_artifact_lock_proposal_rejects_platform_policy(self) -> None:
        platform_policy = copy.deepcopy(self.policy)
        platform_policy.pop("product_id")
        platform_policy.pop("artifact_lock")
        platform_policy["policy_id"] = "platform-keycloak"
        platform_policy["source_repository"] = "Arconath/platform-components"
        platform_policy["artifact_repository"] = (
            "registry.arconath.internal/arconath/platform-keycloak"
        )

        with self.assertRaisesRegex(rc.ContractError, "canonical product policy"):
            rc.artifact_lock_proposal(
                self.intent,
                platform_policy,
                {},
                evidence_dir=self.root / "evidence",
            )

    def test_canonical_product_snapshot_contains_exactly_the_portfolio_products(self) -> None:
        self.assertEqual(
            set(rc.CANONICAL_PRODUCTS),
            {
                "release-passport",
                "foundiqo",
                "opportunity-radar",
                "boringkit",
                "abra",
                "aeliqo",
                "spatial-studio",
                "efficient-ai-compute",
                "people-passport",
                "agentdeck",
                "syviora",
            },
        )
        self.assertEqual(
            rc.CANONICAL_PRODUCTS["opportunity-radar"][0], "Arconath/loklyo"
        )
        self.assertEqual(
            rc.CANONICAL_PRODUCTS["spatial-studio"][0], "Arconath/spatial"
        )

    def test_product_validation_runs_in_a_disposable_copy(self) -> None:
        source = self.root / "product"
        source.mkdir()
        (source / "input.txt").write_text("source", encoding="utf-8")
        policy = dict(self.policy)
        policy["verification_commands"] = [
            [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('validation-output').write_text('ok')",
            ]
        ]
        rc.run_policy(policy, source)
        self.assertFalse((source / "validation-output").exists())

    def test_product_validation_rejects_mutation_of_the_original_source(self) -> None:
        source = self.root / "product"
        source.mkdir()
        changed = source / "changed.txt"
        policy = dict(self.policy)
        policy["verification_commands"] = [
            [
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(changed)!r}).write_text('changed')",
            ]
        ]
        with self.assertRaisesRegex(rc.ContractError, "must be read-only"):
            rc.run_policy(policy, source)

    def test_product_validation_rejects_source_symlinks(self) -> None:
        source = self.root / "product"
        source.mkdir()
        (source / "input.txt").write_text("source", encoding="utf-8")
        (source / "link").symlink_to(source / "input.txt")
        with self.assertRaisesRegex(rc.ContractError, "unsupported symlink"):
            rc.run_policy(self.policy, source)

    def test_zero_oci_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(rc.ContractError, "OCI image manifest descriptor digest"):
            rc.build_evidence(self.intent, self.make_oci(rc.ZERO_DIGEST), RELEASE_CONTROL_SHA)

    def test_oci_manifest_blob_must_exist(self) -> None:
        with self.assertRaisesRegex(rc.ContractError, "referenced OCI blob is missing"):
            rc.build_evidence(
                self.intent,
                self.make_oci(include_manifest=False),
                RELEASE_CONTROL_SHA,
            )

    def test_oci_manifest_blob_must_match_its_descriptor_digest(self) -> None:
        with self.assertRaisesRegex(rc.ContractError, "OCI blob digest mismatch"):
            rc.build_evidence(
                self.intent,
                self.make_oci(corrupt_manifest=True),
                RELEASE_CONTROL_SHA,
            )

    def test_zero_evidence_hash_is_rejected(self) -> None:
        with self.assertRaisesRegex(rc.ContractError, "evidence SHA-256"):
            rc.validate_file_hash(
                {"filename": "sbom.spdx.json", "sha256": "0" * 64},
                "sbom",
            )

    def test_disabled_policy_fails_closed(self) -> None:
        self.policy["enabled"] = False
        write_json(self.policy_dir / "releasepassport-api.json", self.policy)
        with self.assertRaisesRegex(rc.ContractError, "disabled"):
            self.validate()

    def test_exact_artifact_digest_survives_transport_and_publication(self) -> None:
        archive, evidence, record = self.make_final_release()
        self.assertEqual(record["artifact"]["digest"], evidence["artifact"]["digest"])
        self.assertEqual(record["release_control_sha"], RELEASE_CONTROL_SHA)
        self.assertEqual(
            record["artifact"]["reference"],
            "registry.arconath.internal/arconath/releasepassport/api@" + OCI_DIGEST,
        )

    def test_evidence_lock_binds_sbom_license_provenance_and_vulnerability_report(self) -> None:
        _, _, record = self.make_final_release()
        sbom = self.root / "evidence/sbom.spdx.json"
        sbom.write_text('{"packages":[],"spdxVersion":"SPDX-2.3","tampered":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(rc.ContractError, "sbom evidence SHA-256 differs"):
            rc.validate_release_bundle_files(
                self.intent,
                record,
                self.root / "evidence",
                RELEASE_CONTROL_SHA,
            )

    def test_license_evidence_is_bound_to_the_exact_sbom_package_list(self) -> None:
        archive, build_evidence, _ = self.make_final_release()
        evidence_dir = self.root / "evidence"
        licenses = evidence_dir / "licenses.json"
        write_json(
            licenses,
            {
                "package_count": 1,
                "packages": [{"licenses": ["Apache-2.0"], "name": "different"}],
                "schema_version": 1,
                "spdx_version": "SPDX-2.3",
            },
        )
        with self.assertRaisesRegex(rc.ContractError, "package list does not match SBOM"):
            rc.create_evidence_lock(
                self.intent,
                build_evidence,
                evidence_dir / "build-evidence.json",
                archive,
                evidence_dir / "sbom.spdx.json",
                licenses,
                evidence_dir / "provenance.intoto.json",
                evidence_dir / "vulnerabilities.json",
                RELEASE_CONTROL_SHA,
            )

    def test_license_evidence_binding_requires_exact_declared_value(self) -> None:
        archive, build_evidence, _ = self.make_final_release()
        evidence_dir = self.root / "evidence"
        licenses = evidence_dir / "licenses.json"
        value = json.loads(licenses.read_text(encoding="utf-8"))
        value["packages"][0]["licenses"] = ["MIT"]
        write_json(licenses, value)
        with self.assertRaisesRegex(rc.ContractError, "licenseDeclared exactly"):
            rc.create_evidence_lock(
                self.intent,
                build_evidence,
                evidence_dir / "build-evidence.json",
                archive,
                evidence_dir / "sbom.spdx.json",
                licenses,
                evidence_dir / "provenance.intoto.json",
                evidence_dir / "vulnerabilities.json",
                RELEASE_CONTROL_SHA,
            )

    def test_malformed_license_values_fail_as_contract_errors(self) -> None:
        path = self.root / "licenses.json"
        write_json(
            path,
            {
                "package_count": 1,
                "packages": [{"licenses": [{"not": "a string"}], "name": "example"}],
                "schema_version": 1,
                "spdx_version": "SPDX-2.3",
            },
        )
        with self.assertRaisesRegex(rc.ContractError, "exactly one asserted license string"):
            rc.validate_json_evidence(path, "licenses")

    def test_release_record_requires_signature_and_attestation_evidence(self) -> None:
        archive = self.make_oci()
        evidence = rc.build_evidence(self.intent, archive, RELEASE_CONTROL_SHA)
        base = rc.verify_published(
            self.intent,
            evidence,
            archive,
            OCI_DIGEST,
            RELEASE_CONTROL_SHA,
        )
        evidence_dir = self.root / "incomplete-evidence"
        evidence_dir.mkdir()
        with self.assertRaisesRegex(rc.ContractError, "cannot load JSON"):
            rc.finalize_release(
                self.intent,
                base,
                evidence_dir,
                archive,
                RELEASE_CONTROL_SHA,
            )

    def test_promotion_and_rollback_reject_unknown_evidence_fields(self) -> None:
        _, _, record = self.make_final_release()
        record["evidence"]["unexpected"] = {"filename": "x", "sha256": "0" * 64}
        with self.assertRaisesRegex(rc.ContractError, "unknown fields"):
            rc.release_manifests(self.intent, record, evidence_dir=self.root / "evidence")

    def test_cli_verifies_the_final_evidence_bundle_before_manifest_emission(self) -> None:
        _, _, record = self.make_final_release()
        evidence_dir = self.root / "evidence"

        def run(*arguments: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, str(MODULE_PATH), *arguments],
                cwd=ROOT,
                check=False,
                text=True,
                capture_output=True,
            )

        result = run(
            "verify-evidence-lock",
            "--intent",
            str(self.intent_path),
            "--lock",
            str(evidence_dir / "evidence-lock.json"),
            "--build-evidence",
            str(evidence_dir / "build-evidence.json"),
            "--archive",
            str(self.root / "candidate.oci.tar"),
            "--evidence-dir",
            str(evidence_dir),
            "--release-control-sha",
            RELEASE_CONTROL_SHA,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        promotion = self.root / "promotion-manifest.json"
        rollback = self.root / "rollback-manifest.json"
        artifact_lock_proposal = self.root / "artifact-lock-proposal.json"
        result = run(
            "emit-manifests",
            "--intent",
            str(self.intent_path),
            "--release-record",
            str(evidence_dir / "release-record.json"),
            "--policy",
            str(self.policy_dir / "releasepassport-api.json"),
            "--promotion",
            str(promotion),
            "--rollback",
            str(rollback),
            "--artifact-lock-proposal",
            str(artifact_lock_proposal),
            "--expected-digest",
            OCI_DIGEST,
            "--release-control-sha",
            RELEASE_CONTROL_SHA,
            "--evidence-dir",
            str(evidence_dir),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(promotion.read_text())["artifact"], record["artifact"])
        self.assertEqual(json.loads(rollback.read_text())["evidence"], record["evidence"])
        self.assertEqual(
            json.loads(artifact_lock_proposal.read_text())["release"]["artifact"],
            record["artifact"],
        )

    def test_changed_archive_is_rejected(self) -> None:
        archive, evidence, _ = self.make_final_release()
        with archive.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaisesRegex(rc.ContractError, "archive SHA-256 differs"):
            rc.verify_evidence_lock(
                json.loads((self.root / "evidence/evidence-lock.json").read_text()),
                self.intent,
                release_control_sha=RELEASE_CONTROL_SHA,
                build_evidence_path=self.root / "evidence/build-evidence.json",
                archive=archive,
                evidence_dir=self.root / "evidence",
            )

    def test_published_digest_mismatch_is_rejected(self) -> None:
        archive, evidence, _ = self.make_final_release()
        with self.assertRaisesRegex(rc.ContractError, "published digest differs"):
            rc.verify_published(self.intent, evidence, archive, "sha256:" + "5" * 64, RELEASE_CONTROL_SHA)

    def test_promotion_and_rollback_are_bound_to_exact_digest(self) -> None:
        archive, _, record = self.make_final_release()
        promotion, rollback = rc.release_manifests(
            self.intent, record, evidence_dir=self.root / "evidence"
        )
        self.assertEqual(promotion["artifact"]["digest"], OCI_DIGEST)
        self.assertEqual(promotion["rollback_digest"], "sha256:" + "1" * 64)
        self.assertEqual(promotion["evidence"], record["evidence"])
        self.assertEqual(promotion["release_control_sha"], RELEASE_CONTROL_SHA)
        self.assertEqual(rollback["replace_digest"], OCI_DIGEST)
        self.assertEqual(rollback["restore_digest"], "sha256:" + "1" * 64)
        self.assertEqual(rollback["release_control_sha"], RELEASE_CONTROL_SHA)

    def test_rollback_must_not_point_to_new_release(self) -> None:
        _, _, record = self.make_final_release()
        self.intent["rollback"]["previous_digest"] = OCI_DIGEST
        with self.assertRaisesRegex(rc.ContractError, "must differ"):
            rc.release_manifests(self.intent, record, evidence_dir=self.root / "evidence")

    def test_promotion_rejects_digest_different_from_publish_job(self) -> None:
        _, _, record = self.make_final_release()
        with self.assertRaisesRegex(rc.ContractError, "publish job output"):
            rc.release_manifests(
                self.intent,
                record,
                "sha256:" + "5" * 64,
                evidence_dir=self.root / "evidence",
            )

    def _rollback_provenance_envelope(self, digest: str, control_sha: str) -> bytes:
        predicate = {
            "buildDefinition": {
                "buildType": "https://arconath.com/release-control/build/v1",
                "externalParameters": {
                    "artifact": {
                        "digest": digest,
                        "repository": self.intent["artifact"]["repository"],
                        "version": "1.2.2",
                    },
                    "source": {
                        "commit_sha": "4" * 40,
                        "repository": "Arconath/releasepassport",
                        "tree_sha": "5" * 40,
                    },
                },
                "internalParameters": {"release_control_sha": control_sha},
                "resolvedDependencies": [
                    {
                        "digest": {"gitCommit": "4" * 40, "gitTree": "5" * 40},
                        "uri": "git+https://github.com/Arconath/releasepassport",
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/Arconath/release-control/.github/workflows/release.yml@refs/heads/main"
                },
                "metadata": {"invocationId": f"previous-release@{control_sha}"},
            },
        }
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": predicate,
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {
                    "digest": {"sha256": digest.removeprefix("sha256:")},
                    "name": self.intent["artifact"]["repository"],
                }
            ],
        }
        return rc.canonical_bytes(
            {
                "payload": base64.b64encode(rc.canonical_bytes(statement)).decode(
                    "ascii"
                ),
                "payloadType": "application/vnd.in-toto+json",
                "signatures": [
                    {
                        "keyid": "",
                        "sig": base64.b64encode(b"verified-by-cosign").decode(
                            "ascii"
                        ),
                    }
                ],
            }
        )

    def _mock_rollback_tools(
        self,
        digest: str,
        *,
        inspect_name: str | None = None,
        inspect_digest: str | None = None,
        signature_status: int = 0,
        attestation_status: int = 0,
    ) -> tuple[mock.Mock, list[list[str]]]:
        calls: list[list[str]] = []
        attestation = self._rollback_provenance_envelope(
            digest, "c" * 40
        )
        expected_name = inspect_name or self.intent["artifact"]["repository"]
        expected_digest = inspect_digest or digest

        def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            calls.append(command)
            if command[0] == "skopeo":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(
                        {"Name": expected_name, "Digest": expected_digest}
                    ).encode("utf-8"),
                    stderr=b"",
                )
            if command[0] != "cosign":
                raise AssertionError(f"unexpected external command: {command}")
            if "verify-attestation" in command:
                output = kwargs.get("stdout")
                if attestation_status:
                    return subprocess.CompletedProcess(
                        command, attestation_status, stdout=b"", stderr=b""
                    )
                assert hasattr(output, "write")
                output.write(attestation)  # type: ignore[union-attr]
                output.flush()  # type: ignore[union-attr]
                return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
            return subprocess.CompletedProcess(
                command, signature_status, stdout=b"", stderr=b""
            )

        patched = mock.patch.object(rc.subprocess, "run", side_effect=run)
        patched.start()
        self.addCleanup(patched.stop)
        return patched, calls

    def test_zero_rollback_digest_is_an_explicit_first_release_baseline(self) -> None:
        intent = copy.deepcopy(self.intent)
        intent["rollback"]["previous_digest"] = rc.ZERO_DIGEST
        tools, calls = self._mock_rollback_tools(rc.ZERO_DIGEST)
        result = rc.verify_rollback_digest(intent)
        tools.stop()
        self.assertEqual(result["status"], "baseline")
        self.assertEqual(calls, [])

    def test_rollback_digest_requires_registry_identity_and_cosign_provenance(self) -> None:
        digest = "sha256:" + "6" * 64
        _, calls = self._mock_rollback_tools(digest)
        intent = copy.deepcopy(self.intent)
        intent["rollback"]["previous_digest"] = digest
        result = rc.verify_rollback_digest(intent)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["artifact"]["digest"], digest)
        self.assertEqual(result["workflow"]["sha"], "c" * 40)
        self.assertTrue(any(command[0] == "skopeo" for command in calls))
        self.assertTrue(any("verify-attestation" in command for command in calls))
        signature = next(command for command in calls if command[0] == "cosign" and "verify-attestation" not in command)
        self.assertIn("--certificate-github-workflow-sha", signature)
        self.assertIn("c" * 40, signature)

    def test_rollback_digest_rejects_random_or_missing_registry_digest(self) -> None:
        digest = "sha256:" + "7" * 64
        intent = copy.deepcopy(self.intent)
        intent["rollback"]["previous_digest"] = digest

        def missing(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            self.assertEqual(command[0], "skopeo")
            return subprocess.CompletedProcess(
                command, 1, stdout=b"", stderr=b"manifest unknown"
            )

        with mock.patch.object(rc.subprocess, "run", side_effect=missing):
            with self.assertRaisesRegex(rc.ContractError, "rollback registry lookup"):
                rc.verify_rollback_digest(intent)

    def test_rollback_digest_rejects_wrong_registry_repository(self) -> None:
        digest = "sha256:" + "8" * 64
        intent = copy.deepcopy(self.intent)
        intent["rollback"]["previous_digest"] = digest
        self._mock_rollback_tools(
            digest,
            inspect_name="registry.arconath.internal/arconath/other",
        )
        with self.assertRaisesRegex(rc.ContractError, "repository identity"):
            rc.verify_rollback_digest(intent)

    def test_rollback_digest_rejects_unsigned_image(self) -> None:
        digest = "sha256:" + "9" * 64
        intent = copy.deepcopy(self.intent)
        intent["rollback"]["previous_digest"] = digest
        self._mock_rollback_tools(digest, signature_status=1)
        with self.assertRaisesRegex(rc.ContractError, "rollback artifact signature"):
            rc.verify_rollback_digest(intent)

    def test_rollback_digest_rejects_missing_provenance_attestation(self) -> None:
        digest = "sha256:" + "a" * 64
        intent = copy.deepcopy(self.intent)
        intent["rollback"]["previous_digest"] = digest
        self._mock_rollback_tools(digest, attestation_status=1)
        with self.assertRaisesRegex(rc.ContractError, "rollback provenance attestation"):
            rc.verify_rollback_digest(intent)

    def test_promotion_reverification_rejects_a_tampered_consistent_bundle(self) -> None:
        _, _, record = self.make_final_release()
        evidence_dir = self.root / "evidence"
        original = {
            path: path.read_bytes()
            for path in evidence_dir.glob("*.sigstore.json")
        }

        def verify_bundle(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if command[0] != "cosign":
                raise AssertionError(f"unexpected external command: {command}")
            if "verify-attestation" in command:
                bundle = Path(command[command.index("--bundle") + 1])
                if bundle.read_bytes() != original[bundle]:
                    return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"")
                output = kwargs.get("stdout")
                assert hasattr(output, "write")
                output.write(bundle.read_bytes())  # type: ignore[union-attr]
                output.flush()  # type: ignore[union-attr]
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        bundle = evidence_dir / "build-evidence.attestation.sigstore.json"
        value = json.loads(bundle.read_text(encoding="utf-8"))
        value["signatures"][0]["sig"] = base64.b64encode(b"tampered").decode("ascii")
        write_json(bundle, value)
        record["evidence"]["build_evidence_attestation"]["sha256"] = rc.sha256_file(bundle)

        with mock.patch.object(rc.subprocess, "run", side_effect=verify_bundle):
            with self.assertRaisesRegex(rc.ContractError, "attestation verification"):
                rc.verify_release_bundles(
                    self.intent,
                    record,
                    evidence_dir,
                    RELEASE_CONTROL_SHA,
                )

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
