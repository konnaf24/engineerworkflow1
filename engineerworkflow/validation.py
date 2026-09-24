"""Offline validation independent of the proposal interpreter's claims.

This is a separate stage, NOT an independently implemented formal verifier.
"""
from .model import digest, parse_acl, parse_probes


def validate(baseline, candidate, expected):
    before = parse_acl(baseline)
    after = parse_acl(candidate)
    probes = parse_probes(expected)
    results = []
    for probe in probes:
        baseline_action = before.evaluate(probe.src, probe.dst)
        candidate_action = after.evaluate(probe.src, probe.dst)
        results.append({
            "id": probe.id, "expected": probe.expected,
            "baseline": baseline_action, "candidate": candidate_action,
            "baseline_assertion_passed": baseline_action == probe.expected,
            "candidate_assertion_passed": candidate_action == probe.expected,
            "behavior_preserved": baseline_action == candidate_action,
        })
    passed = all(r["baseline_assertion_passed"] and r["candidate_assertion_passed"]
                 and r["behavior_preserved"] for r in results)
    return {
        "schema_version": 1,
        "baseline_digest": digest(baseline), "candidate_digest": digest(candidate),
        "expected_digest": digest(expected), "passed": passed, "probes": results,
        "scope": "finite IPv4 source/destination probes only; not full equivalence",
        "human_review_required": True, "device_authority": False,
    }
