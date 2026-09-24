"""One-shot evidence workflow. No network clients, secrets or device operations."""
from hashlib import sha256
from pathlib import Path

from .model import InputError, canonical, digest, load_json
from .proposal import apply_proposal
from .validation import validate


def run(baseline_path, proposal_path, expected_path, output):
    output = Path(output)
    # Refuse reuse even for an empty directory, symlink or protected fixture path.
    if output.exists() or output.is_symlink():
        raise InputError("output must be a NEW directory; existing paths are protected")
    if not output.parent.is_dir():
        raise InputError("output parent directory must already exist")
    baseline, baseline_raw = load_json(baseline_path)
    proposal, proposal_raw = load_json(proposal_path)
    expected, expected_raw = load_json(expected_path)
    candidate = apply_proposal(baseline, proposal)
    validation = validate(baseline, candidate, expected)
    validation["proposal_digest"] = digest(proposal)
    bindings = {
        "baseline_digest": digest(baseline), "candidate_digest": digest(candidate),
        "proposal_digest": digest(proposal), "expected_digest": digest(expected),
        "validation_digest": digest(validation),
    }
    passed = validation["passed"]
    status = "REVIEW_REQUIRED" if passed else "BLOCKED_VALIDATION_FAILED"
    plan = {
        "schema_version": 1, **bindings, "mode": "dry-run-only", "status": status,
        "device_authority": False, "human_review_required": True,
        "executable_commands": [],
        "proposed_change": {"remove_rule_ids": proposal["remove_rule_ids"]},
        "steps": ["Engineer reviews baseline freshness and intended scope",
                  "Independent reviewer inspects proposal and validation evidence",
                  "If operational work is desired, use a separately authorized system",
                  "Define rollback and collect post-change evidence outside this starter"],
    }
    recipe = {
        "schema_version": 1, "name": "remove-earlier-rule-duplicate",
        "governance_status": "candidate", "synthetic_validation_passed": passed,
        "validated_for_operational_reuse": False, "human_review_required": True,
        "device_authority": False, **bindings,
        "promotion_requirements": ["Independent engineer review",
                                   "Representative non-synthetic lab evidence",
                                   "Documented scope, limitations and rollback",
                                   "Named owner and external change-governance decision"],
    }
    review = (
        f"# Human review required\n\nStatus: **{status}**\n\n"
        "This artifact is documentary only. It is NOT approval and grants no device authority.\n"
        "No device has been contacted or changed. No live approval enforcement exists.\n\n"
        "## Evidence bindings (canonical JSON SHA-256)\n\n"
        + "".join(f"- {key}: `{value}`\n" for key, value in bindings.items())
        + "\n## Reviewer checklist\n\n"
        "- [ ] Confirm human intent, ownership and baseline freshness.\n"
        "- [ ] Inspect ordered rules and both positive and negative expectations.\n"
        "- [ ] Inspect all failed assertions and drift; stop if any failed.\n"
        "- [ ] Review finite-probe limits and require appropriate external analysis.\n"
        "- [ ] Keep the recipe a candidate until separate governance review.\n\n"
        "Reviewer / decision / date / external ticket: NOT RECORDED.\n"
        "Editing this document does not enable any operation.\n"
    )
    report = (
        f"# Offline verification report\n\nStatus: **{status}**\n\n"
        f"Synthetic probes: {len(validation['probes'])}; validation passed: {passed}.\n"
        f"Rules: {len(baseline['rules'])} baseline -> {len(candidate['rules'])} candidate.\n\n"
        "Verification means offline assertions only, NOT post-deployment verification.\n"
        "First-match IPv4 source/destination ACL; implicit deny. No NAT, state, logging,\n"
        "protocol/port matching, IPv6, routing, vendor semantics or full equivalence proof.\n"
        "Human review remains required even after success; recipe remains a candidate.\n"
        "See validation.json for every assertion and REVIEW.md for evidence bindings.\n"
    )
    artifacts = {
        "baseline.json": canonical(baseline), "proposal.json": canonical(proposal),
        "expected.json": canonical(expected), "candidate.json": canonical(candidate),
        "validation.json": canonical(validation), "dry-run-plan.json": canonical(plan),
        "recipe-candidate.json": canonical(recipe), "REVIEW.md": review.encode(),
        "report.md": report.encode(),
    }
    manifest = {
        "schema_version": 1, "workflow_version": "0.1.0", "status": status, **bindings,
        "input_raw_sha256": {"baseline": baseline_raw, "proposal": proposal_raw,
                             "expected": expected_raw},
        "artifacts_sha256": {name: sha256(data).hexdigest()
                             for name, data in artifacts.items()},
        "hash_notice": "integrity bindings only; not signatures or trusted approval",
        "human_review_required": True, "device_authority": False,
    }
    artifacts["manifest.json"] = canonical(manifest)
    # Exclusive mkdir and file creates: no input mutation and no overwrite-on-retry.
    # manifest is written last; a failed I/O run may leave an incomplete directory.
    output.mkdir()
    for name, data in artifacts.items():
        with (output / name).open("xb") as stream:
            stream.write(data)
    return validation
