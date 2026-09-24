# Safety, ownership and stop criteria

## Defaults and non-goals

- Offline/read-only with respect to inputs and networks; the only writes are the explicitly requested new local evidence directory.
- No sockets, subprocess network clients, credentials, SSH, device APIs, live discovery or production writes in package code.
- No approval flag, approval service, deploy command or automatic recipe promotion. All review text is documentary and **cannot grant device authority**.
- No vendor syntax interpretation, NAT, state, logging, IPv6, ports/protocols, routing or live post-deployment verification.
- No learning from failed probes by editing the expected fixture. Repairing an expectation is a separate, reviewed change; do not change it merely to get a pass.

## Engineer responsibilities

| Role | Responsibility |
| --- | --- |
| Intent owner/network engineer | Define scope, intended behavior, positive/negative expectations, topology assumptions and baseline freshness. |
| Proposal author | Explain the bounded change, inspect the diff, preserve source evidence and disclose unsupported behavior. |
| Independent reviewer | Challenge coverage, inspect digest-bound artifacts and check that reported evidence answers the intent. This role is human, not the validator function. |
| Change authority/operator | Separately authorize, schedule and execute any future real change using another system; define rollback and post-change checks. No authority is conferred here. |
| Recipe maintainer | Review evidence, ownership, scope and limitations; promote a recipe only through external governance with representative evidence. |

One person may fill several roles in a lab; document that limitation. Production separation of duties is an external organizational requirement, not an enforced property of this starter.

## Resource budgets and stopping

Actual limits: 1 MiB per input, 256 rules, 512 probes, 16 removals, one candidate and one validation pass. Parsing and evaluation are bounded by these limits; there is no agent loop, retry escalation or iterative optimizer. CI also has a job timeout. No wall-clock guarantee or OS-level isolation is claimed.

Stop before artifact creation on malformed schemas, unsupported versions/values, missing allow/deny coverage, stale baseline digest or invalid proposal. Stop with blocked artifacts if any baseline assertion, candidate assertion or behavior comparison fails. Stop on any output/I/O error. A successful run still stops at **human review required**. Never convert a failing report into authorization by editing an artifact.

## Output protection and integrity

The output must be a new directory under an existing parent. Existing files, directories (including empty ones), and symlinks at the output path are refused. Directory and artifact creation are exclusive; rerunning cannot overwrite a previous bundle or the baseline/expected fixtures. Missing parent directories are not implicitly created.

This assumes a trusted local filesystem and parent directory: it does not defend against a malicious concurrent writer swapping ancestor paths, filesystem corruption, special input files or tampering by the owner. Use ordinary local JSON files, not FIFOs/device files. Do not use world-writable shared directories for sensitive evidence. A write error may leave partial output; retain it for diagnosis and rerun only to a fresh directory. Check the exit code and final manifest rather than assuming that a directory means success.

Evidence is application-immutable, not WORM storage. Owners can edit files; digests expose changes only relative to a trusted retained manifest. Recomputing all hashes can conceal tampering, so operational use needs an external trusted evidence store/signature system. The output includes baseline, proposal and probes: use synthetic/sanitized data and appropriate filesystem permissions. The package does not redact arbitrary real configs or secrets. Do not commit real environment evidence.

## Recipe lifecycle

`candidate` means a proposed reusable procedure with evidence, **not** a trusted operational recipe. A passing synthetic demo may establish that example tests pass, nothing more. External governance may use `validated` only with named reviewers, an explicit tested scope, representative non-synthetic lab evidence, known exclusions, rollback, expiry/revalidation triggers and an evidence-integrity decision. There is deliberately no built-in transition to `validated`, and even externally validated status never implies permission to change a device.
