# Public Intel Factory

Turns **public** reports into candidate detections for a human to review. It runs outside the
SOC, holds no SOC data, and cannot produce a rule.

```bash
python3 -m puakiller_intel run --family OneStart --seed onestart   # PYTHONPATH=src
python3 -m puakiller_intel policy --mode collect
python3 -m puakiller_intel fixtures
```

Exit code `0` = a candidate was routed, `1` = it was refused (a normal outcome), `2` = the run
could not proceed.

## What it will not do

These are enforced in code and asserted by tests, not left to review discipline:

- **It cannot emit a rule, a regex, or a command.** `Candidate` has no field for a pattern, and
  `requires_human_review` is `True` by construction — the constructor rejects any other value.
- **It cannot upload a sample.** No provider has a submit, upload or detonate method, and a
  test fails if one ever appears.
- **It cannot accept SOC data.** Windows user paths, UNC shares, private IPs, internal domains,
  email addresses, ticket ids, EDR/SIEM references and labelled hostnames are refused at the
  door. Refusal names the *class* of data, never the value.
- **It cannot be talked into anything.** The scout sends facts, not prose, and accepts back only
  values that were already collected. A fabricated indicator does not match a known fact and is
  dropped; forged provenance falls back to the real provenance; the family name comes from the
  seed, never from the model.
- **It cannot reach the network in its default mode.** `policy --mode fixture` prints the
  destination list, which is empty.

## The pipeline

```
collect -> normalize -> scout -> critic -> validate -> report
```

| Stage | What it is for |
|---|---|
| `providers.py` | Public evidence. `FixtureProvider` replays recorded reports: no key, no network, no cost. |
| `normalize.py` | Canonical values, deduplication that preserves every source id, and a second forbidden-data screen. |
| `scout.py` | Extraction, with an allowlist built from what was actually collected. |
| `critic.py` | Adversarial review: benign collisions, generic names, short names, single-source claims. Deterministic Python, not a model. |
| `validate.py` | The final gate. No network, no LLM, no secrets. Explains every point it awards. |
| `pipeline.py` | Wiring and the report a reviewer actually reads. |

Publication is **not** here. Opening an Issue or a Draft PR is a later phase, and that component
must not receive raw documents or provider keys.

## Why the critic is not a model

Every objection is written in Python and can be read, tested and argued with. An objection a
model invented would be as unaccountable as an indicator a model invented — and this is the
component whose objections stop a deletion.

The benign corpus comes from `rules/benign.json`, the same one the PowerShell suite uses.
`tests/Test-RuleCatalog.ps1` fails if the two drift apart.

## A vetoed indicator is dropped, not the whole candidate

An early version rejected an entire family because one of its nine indicators was weak. That is
the wrong incentive: it pushes reviewers toward loosening the critic. Now the weak indicator is
removed, the rest is scored on its own merits, and the removal is recorded in the report.

## Running the container

```bash
docker compose run --rm intel        # network_mode: none, read-only, non-root, no secrets
```

The image bakes in no credentials and needs none. Grant network access only after reading
`policy --mode <mode>` for the mode you intend to run.

## Tests

```bash
python3 tests/test_intel_factory.py
```

45 tests. The ones worth reading first are `TestForbiddenData`, `TestPromptInjection` and
`TestBenignCollisions` — they describe the attacks this package exists to survive.
