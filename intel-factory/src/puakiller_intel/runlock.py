"""Operational state on disk: an anti-overlap lock, and a record of the last run.

A scheduled job needs two things a batch script does not. It must not start while the previous
run is still going -- a second collector against the same provider doubles the request rate and
halves the quota, and two publishers can open the same proposal twice. And it must leave enough
behind that a healthcheck can tell "finished successfully an hour ago" from "has not run since
Tuesday", because a scheduler that silently stops is the failure mode nobody notices.

Both are deliberately small and file-based. There is no daemon, no database and no port: the
container is a batch job that starts, writes, and exits, and adding a service to hold a lock
would add a thing that can fail while doing nothing the filesystem cannot.

What these files never contain: a hostname, a username, a path outside the data directory, or
anything read from a public source. The forbidden-data rules apply to the factory's own
operational files too -- a lock file is exactly the sort of artifact that gets pasted into an
issue when something goes wrong.

Standard library only.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

# A run that has held the lock for longer than this is presumed dead. Chosen well above a
# realistic run (minutes) and well below a scheduling interval that would let two real runs
# overlap. A crashed container leaves its lock behind; with no stale timeout the scheduler
# would then be wedged forever, which is a worse failure than one overlap.
DEFAULT_STALE_AFTER = 3600

LOCK_NAME = "run.lock"
STATE_NAME = "last-run.json"


class LockBusy(RuntimeError):
    """Raised when another run holds the lock and it is not stale."""


class RunLock:
    """An exclusive, crash-tolerant lock built on O_EXCL.

    ``O_CREAT | O_EXCL`` is atomic on every filesystem this runs on, so two containers racing
    cannot both win. The loser does not wait: a scheduled job that queues behind the previous
    one turns a slow run into a backlog, and skipping this tick is the right answer.
    """

    def __init__(
        self,
        path,
        *,
        stale_after_seconds: int = DEFAULT_STALE_AFTER,
        now=time.time,
        label: str = "",
    ) -> None:
        self.path = Path(path)
        self.stale_after_seconds = stale_after_seconds
        self._now = now
        self.label = label
        self.acquired = False
        self.stole_stale_lock = False

    # -- internals ---------------------------------------------------------

    def _payload(self) -> str:
        return json.dumps(
            {"pid": os.getpid(), "started_at": int(self._now()), "label": self.label},
            sort_keys=True,
        )

    def _read_existing(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # An unreadable lock is treated as held, not as absent. Guessing that a corrupt
            # file means "free" is how two runs start at once.
            return {}
        return data if isinstance(data, dict) else {}

    def _age_of(self, existing: dict) -> float:
        started = existing.get("started_at")
        if not isinstance(started, (int, float)) or isinstance(started, bool):
            return -1.0  # unknown age: never considered stale
        return self._now() - started

    # -- api ---------------------------------------------------------------

    def acquire(self) -> "RunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            existing = self._read_existing()
            age = self._age_of(existing)
            if age < 0 or age <= self.stale_after_seconds:
                held = f"{int(age)}s" if age >= 0 else "an unknown time"
                raise LockBusy(
                    f"another run holds {self.path.name} (pid {existing.get('pid', '?')}, "
                    f"held {held}). Skipping this tick rather than queueing behind it."
                ) from None
            # Stale: the holder is presumed dead. Recorded loudly -- a stolen lock means a run
            # died without cleaning up, and that is worth investigating even though the
            # schedule recovered on its own.
            self.stole_stale_lock = True
            self.path.unlink(missing_ok=True)
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(self._payload())
        self.acquired = True
        return self

    def release(self) -> None:
        if self.acquired:
            self.path.unlink(missing_ok=True)
            self.acquired = False

    def __enter__(self) -> "RunLock":
        return self.acquire()

    def __exit__(self, *exc) -> bool:
        self.release()
        return False


# ---------------------------------------------------------------------------
#  Last-run record
# ---------------------------------------------------------------------------

# The closed set of keys the record may carry. Same reasoning as the publication bundle: an
# operational file that accepts anything eventually carries something it should not.
STATE_KEYS = ("finished_at", "mode", "family", "route", "exit_code", "tool_version")


def record_run(
    state_path,
    *,
    mode: str,
    family: str,
    route: str,
    exit_code: int,
    tool_version: str,
    now=time.time,
) -> Path:
    """Write the last-run record. Never contains a hostname, a user, or evidence."""
    path = Path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "finished_at": int(now()),
        "mode": mode,
        # The family name is a public malware family, not an observation about a machine.
        "family": family,
        "route": route,
        "exit_code": int(exit_code),
        "tool_version": tool_version,
    }
    if set(payload) != set(STATE_KEYS):  # a typo here would silently break the healthcheck
        raise ValueError(f"last-run record keys drifted: {sorted(set(payload) ^ set(STATE_KEYS))}")
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_run(state_path) -> dict:
    """Read the last-run record, or an empty dict when there is none."""
    try:
        data = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def health(state_path, *, max_age_seconds: int, now=time.time) -> tuple:
    """Return (healthy, reason). The whole of the container healthcheck.

    Unhealthy means one of three things, and the reason says which: nothing has run at all, the
    last run is older than the schedule should allow, or the last run failed for a reason other
    than a refused candidate. Exit code 1 is a refusal, which is a normal outcome -- a healthy
    factory refuses most of what it looks at.
    """
    record = read_run(state_path)
    if not record:
        return False, f"no run recorded at {Path(state_path).name}; the scheduler has never fired"

    finished = record.get("finished_at")
    if not isinstance(finished, (int, float)) or isinstance(finished, bool):
        return False, "the last-run record has no usable timestamp"

    age = int(now() - finished)
    if age > max_age_seconds:
        return False, f"the last run finished {age}s ago, over the {max_age_seconds}s limit"

    exit_code = record.get("exit_code")
    if exit_code not in (0, 1):
        return False, f"the last run exited {exit_code}, which is an error rather than a verdict"

    verdict = "produced a candidate" if exit_code == 0 else "refused the candidate"
    return True, f"last run {verdict} {age}s ago (mode {record.get('mode', '?')})"


__all__ = [
    "DEFAULT_STALE_AFTER",
    "LOCK_NAME",
    "STATE_KEYS",
    "STATE_NAME",
    "LockBusy",
    "RunLock",
    "health",
    "read_run",
    "record_run",
]
