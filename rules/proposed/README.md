# rules/proposed/

Machine-generated proposals wait here. **Nothing in this directory affects detection.**

No compiler reads these files, no test derives a rule from one, and neither
`hosted-removal.ps1` nor `PUAKILLER-LOCAL.ps1` changes when a file appears. A proposal becomes
a rule only when a maintainer runs `scripts/promote-proposal.py`, and that script refuses until
a person has written two fields by hand:

| Field | Why the factory leaves it empty |
|---|---|
| `Name` | Drives an **unconditional** folder sweep across LOCALAPPDATA, APPDATA, Programs, Start Menu, ProgramFiles(x86) and ProgramData. Folder indicators are proposed as `Aliases` instead, which are removed only when static on-disk evidence is found inside them. |
| `Rx` | Patterns are written by people. The mandate forbids the model from producing one, and a generated pattern is exactly the false-positive risk this project exists to avoid. |

## Reviewing a proposal

Everything a reviewer needs is in the pull request body: the indicators, the score and how it
was reached, the critic's findings, the benign collisions that were tested, the public sources,
and the prompt versions and config hash that make the run reproducible.

The proposal file itself adds one thing the body does not: `indicator_sources`, mapping every
proposed value to the evidence ids supporting it. A value with no entry there is refused by
`scripts/verify-proposals.py`, which runs on every pull request.

## Promoting one

```bash
# 1. Edit the file: write Rx, and decide whether any alias may become Name.
# 2. Check it still passes the gate.
python3 scripts/verify-proposals.py rules/proposed/<id>.json

# 3. See the catalog entry it would add.
python3 scripts/promote-proposal.py rules/proposed/<id>.json

# 4. Write it, then regenerate and re-verify the scripts.
python3 scripts/promote-proposal.py rules/proposed/<id>.json --write
python3 scripts/apply-generated.py --write
python3 scripts/verify-generated.py
```

Then delete the proposal file. It has served its purpose, and leaving it behind would suggest a
rule is still pending when it is not.

## Rejecting one

Close the pull request and delete the branch. Nothing else has to be undone, which is the
reason this directory exists rather than proposals being written straight into
`rules/catalog.json`.
