# Recipe candidate: <bounded change class>

- Governance status: **candidate**
- Validated for operational reuse: **no**
- Owner: <engineer/team>
- Human review required: **yes**
- Device authority: **none; this document is not authorization**

## Intent and applicability

State the intended behavior, allowed transformation, supported model/vendor/version scope, preconditions and explicit exclusions. Distinguish a source-of-truth snapshot from observed state.

## Required evidence

Record baseline source/freshness, collector/analyzer versions, baseline/proposal/candidate/expectation digests, validation report digest and trusted manifest reference. Explain the trusted retention mechanism; hashes alone do not authenticate an author or reviewer. Label synthetic evidence explicitly.

## Procedure

1. Acquire and retain baseline evidence through a separately reviewed read-only process; verify scope and freshness.
2. Author a bounded proposal and independent positive/negative expectations; bind the proposal to the baseline digest.
3. Generate the candidate without altering source evidence; stop on unsupported operations or exhausted budgets.
4. Validate baseline assertions, candidate assertions and comparisons; stop on any mismatch and preserve the failures.
5. Obtain independent human review of the bound evidence; document unresolved risks and coverage gaps.
6. Produce a dry-run plan, rollback requirements and post-change verification criteria; leave real authorization/execution to an external system.
7. Attach the offline report as candidate evidence; do not claim post-deployment verification without actual observed data.

## Budgets and stop conditions

Specify maximum input size, change count, validation work and elapsed time appropriate to the tool. For the starter, inherit the documented fixed limits and one-pass stop behavior. Stop for uncertainty outside tested scope, failed assertions, drift, stale inputs, or missing required review.

## Review record (documentary only)

- Reviewer / independence: <not recorded>
- Decision and rationale: <pending>
- Evidence bindings reviewed: <not recorded>
- External change-governance reference: <none>
- Rollback and verification owner: <not recorded>

## Promotion gate: candidate -> externally validated

Do not change this status based solely on synthetic tests. Require representative non-synthetic lab results, named engineering review, documented applicability/limitations, rollback, ownership, expiry/revalidation triggers and an external governance decision. Record the exact evidence and tested scope. The starter never promotes recipes; external `validated` status is not device authorization.
