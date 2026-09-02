#!/usr/bin/env bash
# One scheduled cycle of the public intel factory.
#
#   deploy/run-cycle.sh                 # fixture: reaches nothing, needs no key
#   deploy/run-cycle.sh OneStart        # fixture, that family
#   MODE=collect deploy/run-cycle.sh OneStart <sha256>...
#   MODE=collect TRIAGE=true deploy/run-cycle.sh OneStart
#
# The anti-overlap lock lives inside the container (puakiller-intel run --lock), because that
# is where it can be tested. This script adds the things a lock cannot do: it keeps the host
# log bounded, it backs up the catalog before anything else runs, and it prunes the response
# cache so a machine left alone for a month does not fill its disk with public reports.
#
# Exit codes are the CLI's own: 0 a candidate was produced, 1 the candidate was refused, 2
# something went wrong. 1 is a normal outcome and must not page anyone -- a healthy factory
# refuses most of what it looks at.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "${HERE}/compose.yaml")

MODE="${MODE:-fixture}"
# Triage stays an environment switch rather than a positional flag, so it reads the same way as
# MODE and cannot be mistaken for a family name. The CLI still refuses unless TRIAGE_ENABLED is
# also set in .env: one switch alone does not turn an optional provider on.
TRIAGE="${TRIAGE:-false}"
FAMILY="${1:-OneStart}"
shift || true
SEEDS=("$@")

DATA="${HERE}/data"
LOG_DIR="${DATA}/logs"
LOG="${LOG_DIR}/run-cycle.log"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-10485760}"   # 10 MiB
LOG_KEEP="${LOG_KEEP:-5}"

mkdir -p "${DATA}/out" "${DATA}/state" "${LOG_DIR}" "${DATA}/backups"

# --- log rotation ------------------------------------------------------------
# Docker rotates the container's own stdout (json-file, 10m x 5). This rotates the host-side
# transcript, which docker does not touch, and which is the one an operator actually reads.
rotate_log() {
    [ -f "$LOG" ] || return 0
    local size
    size=$(wc -c < "$LOG")
    [ "$size" -lt "$MAX_LOG_BYTES" ] && return 0
    local i
    for (( i = LOG_KEEP - 1; i >= 1; i-- )); do
        [ -f "${LOG}.${i}" ] && mv "${LOG}.${i}" "${LOG}.$((i + 1))"
    done
    mv "$LOG" "${LOG}.1"
    # Anything past LOG_KEEP is gone. A log nobody has read in five rotations is not evidence,
    # it is disk usage.
    rm -f "${LOG}.$((LOG_KEEP + 1))"
}

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }

rotate_log

log "cycle start mode=${MODE} family=${FAMILY} seeds=${#SEEDS[@]} triage=${TRIAGE}"

# --- catalog backup ----------------------------------------------------------
# Before, not after. The catalog is the thing a bad day could damage, and a backup taken after
# the damage is a copy of the damage.
"${HERE}/backup-catalog.sh" >> "$LOG" 2>&1 || log "warning: catalog backup failed"

# --- the run -----------------------------------------------------------------
seed_args=()
for seed in "${SEEDS[@]:-}"; do
    [ -n "$seed" ] && seed_args+=("--seed=${seed}")
done
[ ${#seed_args[@]} -eq 0 ] && seed_args+=("--seed=${FAMILY}")

if [ "$MODE" = "fixture" ]; then
    service=intel
    profile=()
else
    # The online service is behind a compose profile so it cannot start by accident.
    service=intel-online
    profile=(--profile online)
fi

triage_args=()
[ "$TRIAGE" = "true" ] && triage_args+=("--triage")

set +e
"${COMPOSE[@]}" "${profile[@]}" run --rm "$service" \
    run \
    "--mode=${MODE}" \
    "--family=${FAMILY}" \
    "${seed_args[@]}" \
    "${triage_args[@]}" \
    --benign=/repo/rules/benign.json \
    --out=/data/out \
    --lock=/data/state/run.lock \
    --state=/data/state/last-run.json \
    >> "$LOG" 2>&1
status=$?
set -e

case "$status" in
    0) log "cycle end: a candidate was produced (see data/out/report.md)" ;;
    1) log "cycle end: the candidate was refused -- a normal outcome, nothing to do" ;;
    *) log "cycle end: FAILED with exit ${status}" ;;
esac

# --- cache pruning -----------------------------------------------------------
# Cheap, and it keeps a long-running host from accumulating public reports indefinitely.
"${COMPOSE[@]}" run --rm intel cache --purge-older-than "${RAW_PUBLIC_RETENTION_DAYS:-30}" \
    >> "$LOG" 2>&1 || log "warning: cache prune failed"

exit "$status"
