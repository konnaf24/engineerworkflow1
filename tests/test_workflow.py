import copy
from dataclasses import FrozenInstanceError
from hashlib import sha256
from ipaddress import IPv4Address
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from engineerworkflow.model import (InputError, MAX_BYTES, digest, load_json,
                                    parse_acl, parse_probes)
from engineerworkflow.proposal import apply_proposal
from engineerworkflow.validation import validate
from engineerworkflow.workflow import run

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def fixture(name):
    return json.loads((EXAMPLES / name).read_text())


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.baseline = fixture("baseline.json")
        self.expected = fixture("expected.json")

    def test_first_match_rule_order(self):
        acl = parse_acl(self.baseline)
        src, dst = IPv4Address("192.0.2.140"), IPv4Address("198.51.100.20")
        self.assertEqual(acl.evaluate(src, dst), "deny")
        self.baseline["rules"].reverse()
        self.assertEqual(parse_acl(self.baseline).evaluate(src, dst), "allow")

    def test_implicit_deny_empty_acl(self):
        acl = parse_acl({"schema_version": 1, "rules": []})
        self.assertEqual(acl.evaluate(IPv4Address("192.0.2.1"),
                                      IPv4Address("198.51.100.1")), "deny")

    def test_immutable_parsed_baseline(self):
        acl = parse_acl(self.baseline)
        with self.assertRaises(FrozenInstanceError):
            acl.rules[0].action = "allow"

    def test_strict_acl_fields_and_types(self):
        invalid = [[], {}, {**self.baseline, "extra": 1},
                   {**self.baseline, "schema_version": True},
                   {**self.baseline, "schema_version": 1.0},
                   {**self.baseline, "rules": {}},
                   {**self.baseline, "rules": self.baseline["rules"] * 100}]
        for value in invalid:
            with self.subTest(value=str(value)[:80]), self.assertRaises(InputError):
                parse_acl(value)

    def test_strict_rule_values(self):
        for key, value in [("src", "192.0.2.1/24"), ("src", "::/0"),
                           ("src", "192.0.2.1"), ("dst", 42),
                           ("action", "permit"), ("action", []), ("id", "../bad")]:
            data = copy.deepcopy(self.baseline)
            data["rules"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(InputError):
                parse_acl(data)

    def test_duplicate_rule_ids(self):
        self.baseline["rules"][1]["id"] = self.baseline["rules"][0]["id"]
        with self.assertRaises(InputError):
            parse_acl(self.baseline)

    def test_missing_rule_field(self):
        del self.baseline["rules"][0]["dst"]
        with self.assertRaises(InputError):
            parse_acl(self.baseline)

    def test_probe_validation(self):
        invalid = [[], {}, {"schema_version": 1, "probes": []},
                   {"schema_version": 1, "probes": self.expected["probes"][:1]},
                   {"schema_version": 1, "probes": self.expected["probes"] * 200}]
        for field, value in [("src", "::1"), ("dst", "no-ip"),
                             ("expected", True), ("id", "bad id")]:
            data = copy.deepcopy(self.expected)
            data["probes"][0][field] = value
            invalid.append(data)
        duplicate = copy.deepcopy(self.expected)
        duplicate["probes"][1]["id"] = duplicate["probes"][0]["id"]
        invalid.append(duplicate)
        for value in invalid:
            with self.subTest(value=str(value)[:80]), self.assertRaises(InputError):
                parse_probes(value)

    def test_stable_digest_ignores_object_order_not_rule_order(self):
        reordered = dict(reversed(list(self.baseline.items())))
        self.assertEqual(digest(self.baseline), digest(reordered))
        other = copy.deepcopy(self.baseline)
        other["rules"].reverse()
        self.assertNotEqual(digest(self.baseline), digest(other))

    def test_json_loader_rejects_duplicates_constants_encoding_and_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            for raw in [b'{"a":1,"a":2}', b'NaN', b'Infinity', b'{', b'\xff',
                        b'[' * 2000, b' ' * (MAX_BYTES + 1)]:
                path.write_bytes(raw)
                with self.subTest(raw=raw[:20]), self.assertRaises(InputError):
                    load_json(path)


class ProposalValidationTests(unittest.TestCase):
    def setUp(self):
        self.baseline = fixture("baseline.json")
        self.proposal = fixture("proposal.json")
        self.expected = fixture("expected.json")

    def test_duplicate_removal_preserves_inputs_and_passes(self):
        before = copy.deepcopy(self.baseline)
        candidate = apply_proposal(self.baseline, self.proposal)
        self.assertEqual(len(candidate["rules"]), 2)
        self.assertEqual(self.baseline, before)
        result = validate(self.baseline, candidate, self.expected)
        self.assertTrue(result["passed"])
        self.assertTrue(result["human_review_required"])
        self.assertFalse(result["device_authority"])

    def test_invalid_proposals_fail_closed(self):
        variants = [{**self.proposal, "baseline_digest": "0" * 64},
                    {**self.proposal, "intent": ""},
                    {**self.proposal, "extra": "ignored?"}]
        for removals in [[], ["unknown"], ["block-admin"], ["allow-clients"],
                         ["allow-clients-duplicate"] * 2, ["x"] * 17, "x", [False],
                         ["allow-clients", "allow-clients-duplicate"]]:
            variants.append({**self.proposal, "remove_rule_ids": removals})
        for value in variants:
            with self.subTest(value=value), self.assertRaises(InputError):
                apply_proposal(self.baseline, value)

    def test_broken_candidate_detects_drift_and_failed_assertion(self):
        result = validate(self.baseline, fixture("broken-candidate.json"), self.expected)
        self.assertFalse(result["passed"])
        probe = next(p for p in result["probes"] if p["id"] == "admin-denied-first")
        self.assertTrue(probe["baseline_assertion_passed"])
        self.assertFalse(probe["candidate_assertion_passed"])
        self.assertFalse(probe["behavior_preserved"])

    def test_baseline_failure_blocks_even_when_candidate_matches_expectation(self):
        result = validate(self.baseline, fixture("broken-candidate.json"),
                          fixture("wrong-expected.json"))
        probe = result["probes"][1]
        self.assertFalse(probe["baseline_assertion_passed"])
        self.assertTrue(probe["candidate_assertion_passed"])
        self.assertFalse(result["passed"])

    def test_matching_baseline_candidate_does_not_hide_wrong_expectations(self):
        result = validate(self.baseline, self.baseline, fixture("wrong-expected.json"))
        self.assertTrue(all(p["behavior_preserved"] for p in result["probes"]))
        self.assertFalse(result["passed"])

    def test_validator_rejects_malformed_candidate(self):
        with self.assertRaises(InputError):
            validate(self.baseline, {"rules": []}, self.expected)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.output = self.root / "evidence"
        self.inputs = []
        for name in ("baseline.json", "proposal.json", "expected.json"):
            path = self.root / name
            path.write_bytes((EXAMPLES / name).read_bytes())
            self.inputs.append(path)
        self.originals = [p.read_bytes() for p in self.inputs]

    def execute(self):
        return run(*self.inputs, self.output)

    def cli(self, *extra):
        return subprocess.run([sys.executable, "-m", "engineerworkflow",
                               "--baseline", str(self.inputs[0]),
                               "--proposal", str(self.inputs[1]),
                               "--expected", str(self.inputs[2]),
                               "--output", str(self.output), *extra], cwd=ROOT,
                              capture_output=True, text=True, timeout=10)

    def test_artifacts_bind_all_evidence_and_inputs_unchanged(self):
        self.assertTrue(self.execute()["passed"])
        self.assertEqual([p.read_bytes() for p in self.inputs], self.originals)
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertEqual(len(manifest["artifacts_sha256"]), 9)
        for name, expected_hash in manifest["artifacts_sha256"].items():
            self.assertEqual(sha256((self.output / name).read_bytes()).hexdigest(), expected_hash)
        validation = json.loads((self.output / "validation.json").read_text())
        plan = json.loads((self.output / "dry-run-plan.json").read_text())
        recipe = json.loads((self.output / "recipe-candidate.json").read_text())
        for artifact in (manifest, plan, recipe):
            self.assertEqual(artifact["validation_digest"], digest(validation))
            self.assertTrue(artifact["human_review_required"])
            self.assertFalse(artifact["device_authority"])
        for label, filename in [("baseline", "baseline.json"), ("candidate", "candidate.json"),
                                ("proposal", "proposal.json"), ("expected", "expected.json")]:
            self.assertEqual(validation[label + "_digest"],
                             digest(json.loads((self.output / filename).read_text())))
        for label, raw in zip(("baseline", "proposal", "expected"), self.originals):
            self.assertEqual(manifest["input_raw_sha256"][label], sha256(raw).hexdigest())
        self.assertEqual(plan["executable_commands"], [])
        self.assertEqual(recipe["governance_status"], "candidate")
        self.assertFalse(recipe["validated_for_operational_reuse"])
        self.assertIn("Human review required", (self.output / "REVIEW.md").read_text())

    def test_deterministic_runs(self):
        self.execute()
        second = self.root / "second"
        run(*self.inputs, second)
        for path in self.output.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())

    def test_reuse_is_rejected_without_changes(self):
        self.execute()
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        with self.assertRaises(InputError):
            self.execute()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_existing_empty_directory_is_protected(self):
        self.output.mkdir()
        with self.assertRaises(InputError):
            self.execute()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_input_files_cannot_be_output(self):
        for path in self.inputs:
            with self.assertRaises(InputError):
                run(*self.inputs, path)
        self.assertEqual([p.read_bytes() for p in self.inputs], self.originals)

    def test_symlink_output_is_protected_including_dangling(self):
        for target in (self.inputs[0], self.root / "missing"):
            self.output.symlink_to(target)
            with self.assertRaises(InputError):
                self.execute()
            self.output.unlink()
        self.assertEqual([p.read_bytes() for p in self.inputs], self.originals)

    def test_missing_output_parent_is_rejected(self):
        with self.assertRaises(InputError):
            run(*self.inputs, self.root / "missing" / "out")

    def test_invalid_proposal_creates_no_output(self):
        self.inputs[1].write_bytes((EXAMPLES / "invalid-proposal.json").read_bytes())
        with self.assertRaises(InputError):
            self.execute()
        self.assertFalse(self.output.exists())

    def test_cli_success_still_requires_review(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("HUMAN REVIEW REQUIRED", result.stdout)

    def test_cli_failed_validation_writes_blocked_evidence(self):
        self.inputs[2].write_bytes((EXAMPLES / "wrong-expected.json").read_bytes())
        result = self.cli()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("BLOCKED", result.stderr)
        plan = json.loads((self.output / "dry-run-plan.json").read_text())
        self.assertEqual(plan["status"], "BLOCKED_VALIDATION_FAILED")
        self.assertEqual(plan["executable_commands"], [])
        self.assertFalse(json.loads((self.output / "recipe-candidate.json").read_text())
                         ["synthetic_validation_passed"])

    def test_cli_malformed_input(self):
        self.inputs[0].write_text('{"schema_version":1,"schema_version":1}')
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn("STOP", result.stderr)
        self.assertFalse(self.output.exists())

    def test_cli_invalid_proposal(self):
        self.inputs[1].write_bytes((EXAMPLES / "invalid-proposal.json").read_bytes())
        self.assertEqual(self.cli().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_cli_missing_input_and_existing_output(self):
        self.inputs[0].unlink()
        self.assertEqual(self.cli().returncode, 2)
        self.inputs[0].write_bytes(self.originals[0])
        self.output.mkdir()
        self.assertEqual(self.cli().returncode, 2)

    def test_cli_requires_explicit_paths(self):
        result = subprocess.run([sys.executable, "-m", "engineerworkflow"], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
