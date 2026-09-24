# Network engineering workflow starter

A runnable **Python 3.11+**, standard-library-only offline example of an engineer-led change workflow. No accounts, services, credentials, network access or device writes are needed at runtime. This is not a firewall manager or a production deployment tool.

```text
Human intent -> baseline evidence -> bounded proposal -> offline validation
             -> human review artifact -> dry-run plan -> offline report
             -> recipe candidate (separate review required)
```

The example removes a duplicate rule from a simplified **ordered, first-match IPv4 source/destination ACL with implicit deny**. A deny rule precedes a broader allow rule: rule order matters. Four synthetic probes cover allowed clients, explicitly denied clients, an unmatched source and an unmatched destination. All sample addresses use documentation ranges.

## Run without installing anything

From the repository root, with Python 3.11 or later:

```sh
python3 -m unittest discover -s tests -v

# --output must name a NEW directory; its parent must already exist.
python3 -m engineerworkflow \
  --baseline examples/baseline.json \
  --proposal examples/proposal.json \
  --expected examples/expected.json \
  --output ./demo-output
```

Success prints `HUMAN REVIEW REQUIRED`. Reusing `./demo-output` fails rather than overwriting evidence. Use a new path for subsequent runs. No installation is required; optional installation is `python3 -m pip install .` (build tooling may need downloading). The installed command is `engineerworkflow`, with the same arguments.

### Failure examples

```sh
# Exit 1: baseline and candidate agree, but a required assertion is wrong.
python3 -m engineerworkflow \
  --baseline examples/baseline.json \
  --proposal examples/proposal.json \
  --expected examples/wrong-expected.json \
  --output ./failed-output

# Exit 2: attempting to remove a nonduplicate deny rule is forbidden.
python3 -m engineerworkflow \
  --baseline examples/baseline.json \
  --proposal examples/invalid-proposal.json \
  --expected examples/expected.json \
  --output ./invalid-output
```

`examples/broken-candidate.json` removes the deny rule and changes behavior. The independent validation stage rejects it in the tests. The CLI deliberately has **no arbitrary candidate input**; it derives a candidate only through the bounded proposal interpreter.

| Exit | Meaning |
| --- | --- |
| 0 | Offline probe assertions pass; human review still required. NOT approval. |
| 1 | Assertions or probe behavior comparison failed; blocked evidence is written. |
| 2 | Invalid input/proposal, missing file, protected output, or I/O error. Stop. |

Malformed inputs and invalid proposals create no output directory. An I/O failure during output writing can leave a partial directory; do not treat it as complete evidence. A complete successful CLI run and a matching final manifest are required for an intact bundle, not for authorization.

## Evidence bundle

- `baseline.json`, `proposal.json`, `expected.json`: canonical snapshots; original inputs remain untouched.
- `candidate.json`: derived candidate, never applied to anything.
- `validation.json`: per-probe baseline/candidate assertions, drift comparison and input digests.
- `REVIEW.md`: visibly pending review checklist, documentary only.
- `dry-run-plan.json`: bound proposal and validation digests; **no executable commands** or device authority.
- `report.md`: offline verification summary, not post-deployment verification.
- `recipe-candidate.json`: candidate governance status, even after synthetic validation passes.
- `manifest.json`: artifact byte digests, original input byte digests and semantic bindings; written last.

Canonical JSON uses sorted object keys, compact separators, ASCII escaping and a trailing newline; list order is preserved. SHA-256 binds content, not identity or authorization. A snapshot is immutable by application convention (no overwrites), not a filesystem/WORM guarantee. Original byte hashes record provenance; snapshot hashes bind normalized evidence.

## Input contracts and bounds

See the checked-in JSON examples and strict parsers in `engineerworkflow/model.py`. Unknown/missing fields, duplicate JSON keys or IDs, non-finite JSON constants, non-IPv4 values, networks with host bits, unsupported versions/types, and invalid proposals are rejected. Rule IDs are 1–64 ASCII letters/digits/underscore/hyphen. Both `allow` and `deny` expectations are required. Each input is capped at 1 MiB, with at most 256 rules, 512 probes and 16 removals. One candidate and one validation pass; no retries, discovery, inference, autonomous loop or expected-fixture updates.

The proposal includes human `intent`, an exact canonical `baseline_digest` and rule IDs to remove. Every removed rule must duplicate the action/source/destination of an earlier **retained** rule. No additions, reordering, arbitrary edits or removal of unique rules are accepted. Intent is documentary; software checks the explicit proposal and probes, not natural-language meaning.

## Scope and reuse

**Finite probes are not full equivalence.** This model has no NAT, connection state, logging, IPv6, protocols, ports, vendor firewall semantics, routing or physical device behavior. The validator is separate from proposal construction but shares the same ACL evaluator; it is not a separate formal implementation or an independent engineer.

Use established tools for real analysis and operations rather than expanding this toy into a vendor engine. See [architecture and integration boundaries](docs/architecture.md), [safety and engineer roles](docs/safety.md), and the [reusable recipe review template](recipes/TEMPLATE.md). Synthetic evidence alone never promotes a recipe to operationally validated status.

## Layout

```text
engineerworkflow/   strict model, proposal interpreter, validator, artifacts, CLI
examples/          synthetic baseline, proposal, probes and negative fixtures
tests/             offline unittest suite including subprocess CLI tests
recipes/           review-governed reusable recipe template
docs/              architecture, integrations, safety and roles
.github/workflows/ Python 3.11/3.12/3.13 test and demo CI
```
