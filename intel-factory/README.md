# Public Intel Factory

Turns **public** reports into candidate detections for a human to review. It runs outside the
SOC, holds no SOC data, and cannot produce a rule.

```bash
python3 -m puakiller_intel run --family OneStart --seed onestart          # PYTHONPATH=src
python3 -m puakiller_intel run --mode collect --dry-run --family X --seed <sha256>
python3 -m puakiller_intel policy --mode collect
python3 -m puakiller_intel cache --purge-older-than 30
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

## Hybrid Analysis: read-only, and only GET

`collect` mode reads Hybrid Analysis. It refuses to start without a key rather than returning
an empty result set — an empty collector is indistinguishable from a collector that found
nothing, and that difference matters when the output feeds removal rules.

**Only GET endpoints are used, and that has a real cost worth stating.** Hybrid Analysis
exposes full-text search as `POST /search/terms`. Supporting it would mean giving the transport
the ability to send a request body — and a transport that can send a body can upload a file.
The read-only guarantee would drop from *impossible* to *nobody wrote that call yet*.

So search is absent, and seeds are public SHA-256 digests and public report ids instead of free
text. Discovery by family name comes from public reports, which is what the fixture provider
models. Endpoints used: `/key/current`, `/overview/{sha256}`, `/report/{job_id}/summary`.

Only a short allowlist of response fields is read at all — `submit_name`, `certificates[]`,
`processes[].name`, `sha256`. Sandbox reports are full of command lines, dropped-file paths and
network captures; none of it is touched. **A field nobody reads cannot leak.**

### The key

Lives in `Secret`, which refuses to print itself: `repr`, `str` and f-strings all produce a
mask, and `.reveal()` is called at exactly one place in the package. A test fails if a second
call site appears. The key travels in a header, never in a URL, and the response cache is keyed
on the URL alone — so no cache file can identify who fetched it.

### Being a polite guest

Timeouts on every call. Exponential backoff *with jitter* — without it, every retrying client
in a fleet wakes at the same instant and recreates the outage it is backing off from. `429` and
`503` are retried and `Retry-After` is honoured (capped at 120s: a server asking for an hour is
telling us to stop). `401` is **not** retried — retrying a bad credential just burns quota. A
minimum interval between requests, an on-disk cache with a TTL, and `cache --purge-older-than`
so retention actually happens.

### Reviewing before you connect

```bash
python3 -m puakiller_intel run --mode collect --dry-run --family X --seed <sha256>
```

A dry run performs the policy check, builds every URL, and then refuses to send. It prints the
exact destination list — the thing you want in front of you before granting the container
network access.

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
