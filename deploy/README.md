# Deploying the public intel factory

This directory runs the factory on a Linux host **outside the SOC**. Nothing here belongs on a
SOC machine, and nothing here ever receives a sample, a locally observed hash, an internal IOC,
a hostname, a path, or a ticket.

The host does two things: it collects public evidence and it evaluates it. It does **not**
publish. Publication happens in GitHub Actions, or from an operator's own checkout, so the
machine holding the provider keys never holds a write credential for the repository.

---

## Staged bring-up

Do not skip a stage. Each one answers a question the next depends on.

### 1. Fixture — no network, no key, no cost

```bash
cd deploy
cp .env.example .env && chmod 600 .env        # every value still empty
docker compose run --rm intel policy --mode fixture
```

Expected: `mode=fixture outbound=none`. The container also has `network_mode: none`, so the
claim is enforced by the host rather than trusted from the program.

```bash
./run-cycle.sh OneStart
cat data/out/report.md
docker compose run --rm intel health --state /data/state/last-run.json
```

You now have a report produced with no key, no network and no model call. If this stage does
not work, no later stage will either — and it will fail in a way that costs money.

### 2. `collect --dry-run` — still no network

```bash
docker compose --profile online run --rm intel-online \
    run --mode collect --dry-run --family OneStart --seed <sha256>
```

This prints **the exact list of URLs a real run would GET**, and sends nothing. Read it. It is
the list you are about to grant this container permission to reach.

Note what it cannot contain: no `POST`, because the transport has no request body. "Hybrid
Analysis is read-only for this project" is a property of the code rather than a promise in a
document, and this is where you can see it.

### 3. Live collection

Only now:

1. Put the vetted key in `.env` (`HYBRID_ANALYSIS_API_KEY=`).
2. Run the `online` profile explicitly. `intel-online` does not set `network_mode: none`, so it
   gets the default bridge; `intel` never does.
3. Run one family by hand before enabling the timer.

```bash
MODE=collect ./run-cycle.sh OneStart <sha256>
```

### 4. Schedule it

```bash
./install-systemd.sh                    # prints the units, writes nothing
sudo ./install-systemd.sh --write
systemctl list-timers 'puakiller-intel*'
```

---

## What protects what

| Control | Where | What it stops |
|---|---|---|
| `network_mode: none` | `compose.yaml`, service `intel` | The default service reaching anything at all |
| `profiles: ["online"]` | service `intel-online` | The networked service starting by accident |
| `read_only: true` | both | The container writing to its own code |
| `user: "10001:10001"`, `cap_drop: ALL`, `no-new-privileges` | both | Privilege escalation from hostile web content |
| `mem_limit`, `cpus`, `pids_limit` | both | One bad report costing the host |
| `env_file` | both | Secrets ending up in the image or the repository |
| `--lock` | inside the container | Two cycles overlapping and doubling the request rate |
| `--state` + `health` | inside the container | A scheduler that stopped firing going unnoticed |
| `logging: max-size/max-file` + `rotate_log` | compose / `run-cycle.sh` | A month of logs filling the disk |
| `backup-catalog.sh` | before every cycle | Losing the one file whose corruption would matter |

## Health is a property of the schedule, not of a container

There is deliberately no compose `healthcheck:` block. These containers are batch jobs: they
start, write, and exit. A healthcheck on a container that exits by design reports on nothing.

What can actually be wrong is that **cycles stopped happening**, and that produces no error and
no log line — it produces silence, which looks exactly like a quiet week. So the check reads
the last-run record instead:

```bash
docker compose run --rm intel health --state /data/state/last-run.json --max-age 90000
```

Exit 0 healthy, exit 1 unhealthy with the reason. `puakiller-intel-health.timer` runs it hourly.

**Exit 1 from a *cycle* is not unhealthy.** It means the candidate was refused, which is the
normal outcome — a healthy factory refuses most of what it looks at. Only exit 2 and above are
errors, and `SuccessExitStatus=0 1` in the unit says so.

## Anti-overlap

Two independent mechanisms, on purpose:

- **systemd** will not start `puakiller-intel.service` while an instance is running.
- **`--lock /data/state/run.lock`** stops a hand-run cycle colliding with a scheduled one.

A tick that finds the lock held **skips**; it does not queue. Queueing behind a slow run turns
one slow run into a backlog. A lock older than an hour is presumed dead, taken over, and the
takeover is reported to stderr — a stolen lock means a previous run died without cleaning up,
which is worth investigating even though the schedule recovered by itself.

## Files

```
deploy/
  compose.yaml         two services, one image, one difference: the network
  .env.example         every value empty; copy to .env on the server only
  run-cycle.sh         one cycle: backup, run, prune, rotate
  backup-catalog.sh    timestamped, JSON-validated, checksummed, pruned
  install-systemd.sh   two timers; dry run by default
  data/                out/, state/, logs/, backups/   -- not in git
```

## Restoring the catalog

```bash
ls deploy/data/backups
cd deploy/data/backups/<stamp> && sha256sum -c SHA256SUMS
cp rules/catalog.json ../../../../rules/catalog.json
cd - && python3 scripts/verify-generated.py
```

`verify-generated.py` is the check that matters: it proves the restored catalog still compiles
to exactly the rule region both removal scripts carry.
