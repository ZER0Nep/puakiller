#!/usr/bin/env bash
# Install the scheduler. Prints the units by default; writes them only with --write.
#
#   deploy/install-systemd.sh            # show what would be installed
#   sudo deploy/install-systemd.sh --write
#
# Two timers, because they answer different questions:
#
#   puakiller-intel.timer         runs a cycle
#   puakiller-intel-health.timer  asks whether cycles are still happening
#
# The second exists because the first failing silently is the realistic failure. A scheduler
# that stops firing produces no error, no log line and no alert -- it produces nothing, which
# looks exactly like a quiet week.
#
# systemd will not start a second cycle while one is running, and neither will the lock inside
# the container. That is deliberate duplication: the lock is what the tests can reach, and the
# unit is what survives someone running the script by hand at the same time.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
RUN_AS="${RUN_AS:-$(id -un)}"
ON_CALENDAR="${ON_CALENDAR:-daily}"
WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

read -r -d '' CYCLE_SERVICE <<UNIT || true
[Unit]
Description=PUAKILLER public intel factory - one cycle
Documentation=file://${HERE}/README.md
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
User=${RUN_AS}
WorkingDirectory=${HERE}
ExecStart=${HERE}/run-cycle.sh
# Exit 1 means the candidate was refused. That is a verdict, not a failure, and marking the
# unit failed for it would train the operator to ignore a red unit.
SuccessExitStatus=0 1
TimeoutStartSec=1800
# The container is already unprivileged and read-only; these harden the host side of the job.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${HERE}/data
UNIT

read -r -d '' CYCLE_TIMER <<UNIT || true
[Unit]
Description=PUAKILLER public intel factory - schedule

[Timer]
OnCalendar=${ON_CALENDAR}
# Spread the load, rather than every host on earth hitting the provider at midnight.
RandomizedDelaySec=1800
Persistent=true
Unit=puakiller-intel.service

[Install]
WantedBy=timers.target
UNIT

read -r -d '' HEALTH_SERVICE <<UNIT || true
[Unit]
Description=PUAKILLER public intel factory - is the schedule still alive?

[Service]
Type=oneshot
User=${RUN_AS}
WorkingDirectory=${HERE}
# Reads one file. No network, no key, no provider.
ExecStart=/usr/bin/docker compose -f ${HERE}/compose.yaml run --rm intel health --state /data/state/last-run.json --max-age 90000
NoNewPrivileges=true
PrivateTmp=true
UNIT

read -r -d '' HEALTH_TIMER <<UNIT || true
[Unit]
Description=PUAKILLER public intel factory - health schedule

[Timer]
OnCalendar=hourly
Persistent=true
Unit=puakiller-intel-health.service

[Install]
WantedBy=timers.target
UNIT

emit() {
    local name="$1" body="$2"
    if [ "$WRITE" -eq 1 ]; then
        printf '%s\n' "$body" > "${UNIT_DIR}/${name}"
        echo "wrote ${UNIT_DIR}/${name}"
    else
        echo "=== ${UNIT_DIR}/${name} ==="
        printf '%s\n\n' "$body"
    fi
}

emit puakiller-intel.service "$CYCLE_SERVICE"
emit puakiller-intel.timer "$CYCLE_TIMER"
emit puakiller-intel-health.service "$HEALTH_SERVICE"
emit puakiller-intel-health.timer "$HEALTH_TIMER"

if [ "$WRITE" -eq 0 ]; then
    echo "DRY RUN -- nothing was written. Re-run with --write (as root) to install."
    exit 0
fi

systemctl daemon-reload
systemctl enable --now puakiller-intel.timer puakiller-intel-health.timer
systemctl list-timers 'puakiller-intel*' --no-pager

cat <<'NEXT'

Installed. Before trusting the schedule, walk the staged bring-up in deploy/README.md:
  1. fixture, no network, no key
  2. collect --dry-run, still no network -- read the destination list
  3. only then give the online profile a network
NEXT
