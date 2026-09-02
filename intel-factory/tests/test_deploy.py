#!/usr/bin/env python3
"""Tests for the deployed factory: the lock, the health signal, and the container's shape.

A deployment is mostly configuration, and configuration is where a safety property quietly
stops being true. These assert the ones that matter against the actual files:

    TestRunLock            two cycles cannot overlap; a dead one cannot wedge the schedule
    TestLastRunRecord      the record is closed, and carries nothing about the machine
    TestHealth             silence is unhealthy; a refused candidate is not
    TestContainerShape     non-root, read-only, capped, and reaching nothing by default
    TestNoSecretsInRepo    the example env file holds nothing real
    TestShellScripts       the operational scripts fail loudly rather than half-run

    python3 intel-factory/tests/test_deploy.py
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

INTEL_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = INTEL_ROOT.parent
sys.path.insert(0, str(INTEL_ROOT / "src"))

from puakiller_intel.runlock import (  # noqa: E402
    STATE_KEYS,
    LockBusy,
    RunLock,
    health,
    read_run,
    record_run,
)

DEPLOY = REPO_ROOT / "deploy"
COMPOSE = DEPLOY / "compose.yaml"
ENV_EXAMPLE = DEPLOY / ".env.example"
DOCKERFILE = INTEL_ROOT / "Dockerfile"

try:
    import yaml  # type: ignore

    HAVE_YAML = True
except ImportError:  # pragma: no cover - exercised on hosts without pyyaml
    HAVE_YAML = False


def load_compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


class Clock:
    """A hand-cranked clock. Sleeping in a test to age a lock would be slow and flaky."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestRunLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "run.lock"

    def tearDown(self):
        self.tmp.cleanup()

    def test_acquiring_writes_a_lock_and_releasing_removes_it(self):
        with RunLock(self.path) as lock:
            self.assertTrue(self.path.is_file())
            self.assertTrue(lock.acquired)
        self.assertFalse(self.path.exists())

    def test_a_second_run_is_refused_rather_than_queued(self):
        with RunLock(self.path):
            with self.assertRaises(LockBusy):
                RunLock(self.path).acquire()

    def test_the_lock_survives_a_crash_and_is_taken_over_once_stale(self):
        clock = Clock()
        RunLock(self.path, now=clock).acquire()  # deliberately never released: a crash
        clock.advance(30)
        with self.assertRaises(LockBusy):
            RunLock(self.path, now=clock, stale_after_seconds=3600).acquire()

        clock.advance(4000)
        taken = RunLock(self.path, now=clock, stale_after_seconds=3600).acquire()
        self.assertTrue(taken.acquired)
        # Reported, not silent: a stolen lock means a run died without cleaning up.
        self.assertTrue(taken.stole_stale_lock)

    def test_a_corrupt_lock_is_treated_as_held_not_as_absent(self):
        """Guessing that an unreadable lock means 'free' is how two runs start at once."""
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(LockBusy):
            RunLock(self.path).acquire()

    def test_the_lock_file_says_nothing_about_the_machine(self):
        with RunLock(self.path, label="OneStart"):
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(sorted(payload), ["label", "pid", "started_at"])
        blob = json.dumps(payload).lower()
        for forbidden in ("hostname", "user", "home", "computername"):
            self.assertNotIn(forbidden, blob)

    def test_releasing_a_lock_never_acquired_is_harmless(self):
        RunLock(self.path).release()
        self.assertFalse(self.path.exists())


class TestLastRunRecord(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state" / "last-run.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, **overrides):
        payload = {
            "mode": "fixture",
            "family": "OneStart",
            "route": "draft-pr",
            "exit_code": 0,
            "tool_version": "0.1.0",
        }
        payload.update(overrides)
        return record_run(self.path, **payload)

    def test_the_record_has_a_closed_key_set(self):
        self._write()
        self.assertEqual(sorted(read_run(self.path)), sorted(STATE_KEYS))

    def test_the_record_says_nothing_about_the_machine_or_the_evidence(self):
        self._write()
        blob = self.path.read_text(encoding="utf-8").lower()
        for forbidden in ("hostname", "username", "c:\\", "/home/", "sha256", "http"):
            self.assertNotIn(forbidden, blob)

    def test_a_missing_record_reads_as_empty_rather_than_raising(self):
        self.assertEqual(read_run(self.path.parent / "nope.json"), {})


class TestHealth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "last-run.json"
        self.clock = Clock()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, exit_code=0):
        record_run(
            self.path,
            mode="fixture",
            family="OneStart",
            route="draft-pr",
            exit_code=exit_code,
            tool_version="0.1.0",
            now=self.clock,
        )

    def test_silence_is_unhealthy(self):
        healthy, reason = health(self.path, max_age_seconds=3600, now=self.clock)
        self.assertFalse(healthy)
        self.assertIn("never fired", reason)

    def test_a_recent_successful_run_is_healthy(self):
        self._write(exit_code=0)
        healthy, _ = health(self.path, max_age_seconds=3600, now=self.clock)
        self.assertTrue(healthy)

    def test_a_refused_candidate_is_still_healthy(self):
        """Exit 1 is a verdict. A healthy factory refuses most of what it looks at."""
        self._write(exit_code=1)
        healthy, reason = health(self.path, max_age_seconds=3600, now=self.clock)
        self.assertTrue(healthy)
        self.assertIn("refused", reason)

    def test_a_real_error_is_unhealthy(self):
        self._write(exit_code=2)
        healthy, reason = health(self.path, max_age_seconds=3600, now=self.clock)
        self.assertFalse(healthy)
        self.assertIn("error rather than a verdict", reason)

    def test_a_schedule_that_stopped_firing_is_unhealthy(self):
        self._write(exit_code=0)
        self.clock.advance(100_000)
        healthy, reason = health(self.path, max_age_seconds=90_000, now=self.clock)
        self.assertFalse(healthy)
        self.assertIn("over the", reason)

    def test_a_record_without_a_timestamp_is_unhealthy(self):
        self.path.write_text(json.dumps({"exit_code": 0}), encoding="utf-8")
        healthy, _ = health(self.path, max_age_seconds=3600, now=self.clock)
        self.assertFalse(healthy)


@unittest.skipUnless(HAVE_YAML, "pyyaml is not installed")
class TestContainerShape(unittest.TestCase):
    """The safety properties of the deployment, asserted against compose.yaml itself."""

    def setUp(self):
        self.services = load_compose()["services"]

    def test_the_default_service_reaches_nothing(self):
        self.assertEqual(self.services["intel"]["network_mode"], "none")

    def test_the_networked_service_cannot_start_by_accident(self):
        self.assertIn("online", self.services["intel-online"]["profiles"])

    def test_no_service_runs_as_root_or_writable(self):
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertTrue(service["read_only"], name)
                self.assertEqual(service["cap_drop"], ["ALL"])
                self.assertIn("no-new-privileges:true", service["security_opt"])

    def test_the_uid_follows_the_operator_and_falls_back_unprivileged(self):
        """Hardcoding a uid made every operator chown ./data before the first run.

        Substitution has a hole a plain literal did not: an empty or hostile HOST_UID. The
        fallback has to be the image's own unprivileged user, and it has to be non-zero.
        """
        pattern = re.compile(r"^\$\{HOST_UID:-(\d+)\}:\$\{HOST_GID:-(\d+)\}$")
        for name, service in self.services.items():
            with self.subTest(service=name):
                match = pattern.match(service["user"])
                self.assertIsNotNone(match, f"{name} user is {service['user']!r}")
                self.assertNotEqual(match.group(1), "0", "the uid fallback must not be root")
                self.assertNotEqual(match.group(2), "0", "the gid fallback must not be root")

    def test_every_service_is_capped(self):
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertIn("mem_limit", service)
                self.assertIn("cpus", service)
                self.assertIn("pids_limit", service)

    def test_logs_are_rotated(self):
        for name, service in self.services.items():
            with self.subTest(service=name):
                options = service["logging"]["options"]
                self.assertIn("max-size", options)
                self.assertIn("max-file", options)

    def test_secrets_arrive_at_run_time_and_are_never_inline(self):
        blob = COMPOSE.read_text(encoding="utf-8")
        for service in self.services.values():
            self.assertIn(".env", service["env_file"])
        for forbidden in ("HYBRID_ANALYSIS_API_KEY:", "LLM_API_KEY:", "TRIAGE_API_KEY:"):
            self.assertNotIn(forbidden, blob)

    def test_no_github_token_lives_on_the_collection_host(self):
        """The machine holding provider keys must not also hold a write credential."""
        self.assertNotIn("GITHUB_TOKEN=", COMPOSE.read_text(encoding="utf-8"))
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            if not line.strip().startswith("#"):
                self.assertNotIn("GITHUB_TOKEN", line)

    def test_the_repository_is_mounted_read_only(self):
        for name, service in self.services.items():
            with self.subTest(service=name):
                mounts = [m for m in service["volumes"] if "/repo/" in m]
                self.assertTrue(mounts, name)
                for mount in mounts:
                    self.assertTrue(mount.endswith(":ro"), mount)

    def test_the_dockerfile_drops_to_an_unprivileged_user(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("USER intel", source)
        # The last USER wins; make sure nothing switches back.
        self.assertEqual(source.count("USER root"), 0)


class TestNoSecretsInRepo(unittest.TestCase):
    def test_the_example_env_file_holds_no_value_that_could_be_real(self):
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            with self.subTest(key=key):
                if key.endswith("_API_KEY"):
                    self.assertEqual(value, "", f"{key} must be empty in the example file")
                self.assertNotIn("sk-", value)
                self.assertNotIn("ghp_", value)

    def test_triage_is_off_in_the_example(self):
        """Triage is optional, and the pipeline is specified to work entirely without it."""
        self.assertIn("TRIAGE_ENABLED=false", ENV_EXAMPLE.read_text(encoding="utf-8"))

    def test_the_filled_env_file_is_ignored_by_git(self):
        ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("deploy/.env", ignore)
        self.assertIn("deploy/data/", ignore)
        self.assertIn("!deploy/.env.example", ignore)


class TestShellScripts(unittest.TestCase):
    SCRIPTS = ("run-cycle.sh", "backup-catalog.sh", "install-systemd.sh")

    def test_every_script_fails_loudly(self):
        for name in self.SCRIPTS:
            with self.subTest(script=name):
                source = (DEPLOY / name).read_text(encoding="utf-8")
                self.assertIn("set -euo pipefail", source)

    def test_the_installer_does_nothing_without_an_explicit_flag(self):
        source = (DEPLOY / "install-systemd.sh").read_text(encoding="utf-8")
        self.assertIn("--write", source)
        self.assertIn("DRY RUN", source)

    def test_a_refused_candidate_does_not_fail_the_unit(self):
        source = (DEPLOY / "install-systemd.sh").read_text(encoding="utf-8")
        self.assertIn("SuccessExitStatus=0 1", source)

    def test_the_cycle_refuses_to_run_as_root(self):
        """Under root the container would inherit uid 0, and every other control with it."""
        source = (DEPLOY / "run-cycle.sh").read_text(encoding="utf-8")
        self.assertIn('if [ "$(id -u)" -eq 0 ]; then', source)
        self.assertIn("refusing to run as root", source)

    def test_the_cycle_exports_the_operators_ids(self):
        source = (DEPLOY / "run-cycle.sh").read_text(encoding="utf-8")
        self.assertIn('export HOST_UID="$(id -u)"', source)
        self.assertIn('export HOST_GID="$(id -g)"', source)
        # Exported before the first docker invocation, or the substitution happens too late.
        self.assertLess(source.index("export HOST_UID"), source.index("COMPOSE[@]"))

    def test_the_backup_runs_before_the_cycle_not_after(self):
        """A backup taken after the damage is a copy of the damage."""
        source = (DEPLOY / "run-cycle.sh").read_text(encoding="utf-8")
        self.assertLess(source.index("backup-catalog.sh"), source.index("--lock="))


if __name__ == "__main__":
    unittest.main(verbosity=2)
