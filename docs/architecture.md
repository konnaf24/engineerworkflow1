# Architecture and extension boundaries

## Existing-solution preflight

[Batfish](https://batfish.org/) is an existing open-source network configuration analysis tool; its public site was checked during implementation. For real vendor configurations and reachability, use its supported analysis interfaces instead of extending this simplified ACL evaluator. The following are proposed integration boundaries, not installed/tested integrations or claims about current compatibility:

- [NetBox](https://netboxlabs.com/docs/netbox/): inventory/source-of-truth context. Export a reviewed, versioned snapshot with freshness and ownership metadata; do not assume intended inventory equals observed device state.
- [NAPALM](https://napalm.readthedocs.io/): separately managed read-only collection of observed configuration/state. Keep any write-capable functionality outside this package.
- [Nornir](https://nornir.readthedocs.io/) or [Ansible](https://docs.ansible.com/): orchestrate approved operational work externally. This starter must not become an authorization shortcut or carry credentials.
- Batfish: replace the toy validation stage with supported vendor parsing and appropriate analysis; preserve version, source configuration and result digests. Even a real analysis engine needs explicit scope and engineering review.

This small custom package teaches evidence flow only. No custom platform, MCP server, paid dependency or production network-analysis engine is needed. No adapters are implemented: these seams describe where to integrate mature tools after a separate design/review.

## Stage contracts

1. **Human intent and fixtures:** an engineer authors the proposal's bounded intent statement, baseline snapshot and expected positive/negative probes. These are inputs, not autonomously discovered facts.
2. **Baseline evidence:** `load_json` records the original bytes' SHA-256 and rejects ambiguous JSON. `parse_acl` creates frozen rule objects in an ordered tuple. Inputs are never opened for writing.
3. **Bounded proposal:** `apply_proposal` checks the baseline digest and removes only exact semantic duplicates of earlier retained rules, capped at 16. It copies rather than mutates the baseline. Unsupported operations stop before artifact creation.
4. **Independent offline validation stage:** `validate` accepts baseline, candidate and expected fixtures without trusting the proposal's redundancy claim. It reparses both ACLs and evaluates every probe, requiring baseline expectations, candidate expectations and observed behavior preservation. It shares the evaluator with the model: separation of stage is not independent implementation, formal equivalence or a human review.
5. **Review and plan:** `workflow.run` binds proposal, candidate, expectations and validation digests into documentary review and dry-run artifacts. Successful probes produce `REVIEW_REQUIRED`, never `APPROVED`. Failures produce `BLOCKED_VALIDATION_FAILED` and an inert plan.
6. **Verification and reporting:** report the offline comparison only. Post-change telemetry does not exist here because deployment does not exist here.
7. **Recipe candidate:** attach evidence and promotion requirements; keep `governance_status=candidate` and `validated_for_operational_reuse=false`. A separate engineering process may later establish validated scope; this CLI cannot promote it.

## Digest graph

```text
baseline + proposal + expected --proposal interpreter--> candidate
baseline + candidate + expected -----------------------> validation
proposal digest --------------------------------------> validation metadata
all four inputs + validation digests ------------------> plan / review / recipe
original byte hashes + all emitted artifact hashes ----> manifest (written last)
```

Hashes are deterministic and content-bound. They are not signatures, remote attestations, confidentiality protection or a chain of trusted approval. The manifest does not hash itself. No timestamps or machine paths enter artifacts, so identical inputs produce byte-identical bundles. Operational extensions must introduce explicit collector/tool versions, acquisition times, provenance and freshness policy; they must not infer these from synthetic fixtures.

## Proposal reasoning and limits

For this pure action-only model, a later exact duplicate cannot be the first matching rule for any packet that also matches the retained earlier rule. Removing the later rule is therefore a narrow, understandable transformation. That reasoning does **not** transfer to vendor policies with counters, logging, side effects, state, NAT, object references or other match dimensions. The executable validator reports only the finite probes it actually checked and never claims full equivalence.

## Extension acceptance criteria

A future adapter should return a versioned, bounded, sanitized snapshot/result and an explicit coverage statement. Test it with offline fixtures first; document unsupported syntax and fail closed rather than guessing. Inventory acquisition, real analysis and deployment each need a distinct interface and privilege boundary. An external deployment service would need independently verified review/authorization, provenance, rollback, scoped credentials and post-change checks. A text approval artifact from this project cannot satisfy that service's authorization contract.
