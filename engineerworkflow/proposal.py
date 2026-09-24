"""Bounded proposal interpreter, not a network configuration generator."""
from copy import deepcopy

from .model import (InputError, MAX_REMOVALS, bounded_list, digest, fields,
                    identifier, parse_acl, text, version)


def apply_proposal(baseline, proposal):
    acl = parse_acl(baseline)
    fields(proposal, ("schema_version", "intent", "baseline_digest", "remove_rule_ids"),
           "proposal")
    version(proposal["schema_version"])
    text(proposal["intent"], "intent")
    if proposal["baseline_digest"] != digest(baseline):
        raise InputError("proposal baseline digest mismatch")
    removals = proposal["remove_rule_ids"]
    bounded_list(removals, MAX_REMOVALS, "removals", minimum=1)
    for rid in removals:
        identifier(rid)
    if len(set(removals)) != len(removals):
        raise InputError("duplicate removal id")
    if not set(removals) <= {r.id for r in acl.rules}:
        raise InputError("unknown removal id")
    retained = []
    for rule in acl.rules:
        if rule.id in removals:
            if not any(r.signature == rule.signature for r in retained):
                raise InputError("only duplicates of earlier retained rules may be removed")
        else:
            retained.append(rule)
    candidate = deepcopy(baseline)
    candidate["rules"] = [r for r in candidate["rules"] if r["id"] not in removals]
    parse_acl(candidate)
    return candidate
