#!/usr/bin/env bash
# Back up the rule catalog before a cycle runs.
#
#   deploy/backup-catalog.sh            # one timestamped copy, prunes old ones
#   BACKUP_KEEP=30 deploy/backup-catalog.sh
#
# The catalog decides what gets deleted from user machines. It is small, it changes rarely, and
# it is the one file here whose loss or corruption would matter, so a copy costs nothing and is
# taken every cycle rather than on a schedule of its own.
#
# Each copy is validated as JSON before it is kept. A backup of a corrupt file is worse than no
# backup: it looks like a restore point.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/.." && pwd)"
DEST="${HERE}/data/backups"
KEEP="${BACKUP_KEEP:-14}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${DEST}/${STAMP}"

mkdir -p "$TARGET"

copied=0
for file in rules/catalog.json rules/benign.json rules/schema/catalog.schema.json \
            rules/schema/benign.schema.json rules/schema/proposal.schema.json; do
    src="${REPO}/${file}"
    [ -f "$src" ] || continue
    if ! python3 -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" "$src"; then
        echo "REFUSING to back up ${file}: it is not valid JSON" >&2
        rm -rf "$TARGET"
        exit 1
    fi
    mkdir -p "$(dirname "${TARGET}/${file}")"
    cp -p "$src" "${TARGET}/${file}"
    copied=$((copied + 1))
done

if [ "$copied" -eq 0 ]; then
    echo "nothing to back up: no catalog found under ${REPO}/rules" >&2
    rmdir "$TARGET" 2>/dev/null || true
    exit 1
fi

# A checksum file, so a restore can be checked rather than assumed.
( cd "$TARGET" && find . -type f -name '*.json' -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS )

echo "backed up ${copied} file(s) to ${TARGET}"

# Prune oldest. Sorted by name, which is sorted by time because the stamp is ISO-8601.
mapfile -t existing < <(find "$DEST" -mindepth 1 -maxdepth 1 -type d | sort)
count=${#existing[@]}
if [ "$count" -gt "$KEEP" ]; then
    for (( i = 0; i < count - KEEP; i++ )); do
        rm -rf "${existing[$i]}"
        echo "pruned $(basename "${existing[$i]}")"
    done
fi
