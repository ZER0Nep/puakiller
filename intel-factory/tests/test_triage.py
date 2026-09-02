#!/usr/bin/env python3
"""Tests for the optional Triage adapter.

The mandate is one sentence: "Triage est optionnel et desactive par defaut. Le systeme doit
fonctionner sans Triage." Most of what follows tests the *absence* of Triage rather than its
presence, because an optional dependency that quietly becomes required is the failure worth
preventing.

    TestOffByDefault       nothing reaches tria.ge unless two switches are both on
    TestReadOnly           no submission surface exists, and nothing can send a body
    TestFieldAllowlist     two kinds wide; a poisoned overview cannot widen it
    TestCassetteContract   the documented response shape maps to the expected evidence
    TestComposite          the required source's failure propagates, the optional one's does not
    TestDryRunPlan         the destination list is printable before anything is sent

Every test here is offline. The cassette is hand-written from the documented response shape --
this project has no Triage access, and pretending a synthetic file is a recording would be the
kind of claim the rest of the codebase exists to avoid.

    python3 intel-factory/tests/test_triage.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

INTEL_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = INTEL_ROOT.parent
sys.path.insert(0, str(INTEL_ROOT / "src"))

from puakiller_intel.config import Config, ConfigError, Secret  # noqa: E402
from puakiller_intel.providers import CompositeProvider, ProviderError  # noqa: E402
from puakiller_intel.security import (  # noqa: E402
    ALLOWED_HOSTS_BY_MODE,
    FORBIDDEN_FOR_SOC,
    OutboundPolicy,
    OutboundPolicyError,
)
from puakiller_intel.transport import CassettePlayer, ReadOnlyHttpClient  # noqa: E402
from puakiller_intel.triage import (  # noqa: E402
    ALLOWED_FACT_KINDS,
    TRIAGE_HOST,
    TriageError,
    TriageProvider,
    plan_requests,
)

CASSETTES = INTEL_ROOT / "fixtures" / "cassettes"
SRC = INTEL_ROOT / "src" / "puakiller_intel"

FAKE_KEY = "triage-not-a-real-key-for-tests"
CLEAN_SAMPLE = "260901-abcde12345"
POISONED_SAMPLE = "260901-poison9999"


def triage_config(**overrides) -> Config:
    # A Hybrid Analysis key is supplied because collect mode requires one and validates it
    # first. That ordering is correct -- Hybrid Analysis is the required source and Triage the
    # optional one -- so a test about Triage has to get past it to reach the check it means.
    return Config(
        mode="collect",
        hybrid_analysis_key=overrides.pop("hybrid_analysis_key", Secret("ha-not-a-real-key")),
        triage_enabled=overrides.pop("triage_enabled", True),
        triage_key=overrides.pop("triage_key", Secret(FAKE_KEY)),
        **overrides,
    )


class CassetteClient:
    """A ReadOnlyHttpClient stand-in backed by recorded responses."""

    def __init__(self):
        self.player = CassettePlayer(CASSETTES)
        self.headers_seen = []

    def build_url(self, base, path, params=None):
        return ReadOnlyHttpClient.build_url(self, base, path, params)

    def get_json(self, url, headers=None):
        self.headers_seen.append(headers or {})
        return self.player.get_json(url)


def facts_of(evidence_list) -> set:
    return {(f.kind, f.value) for e in evidence_list for f in e.facts}


class TestOffByDefault(unittest.TestCase):
    """Two switches, and both must be on. Either one alone leaves Triage off."""

    def test_config_defaults_to_disabled(self):
        self.assertFalse(Config().triage_enabled)

    def test_a_disabled_provider_refuses_to_be_constructed(self):
        """Constructing one would be a silent way to end up making requests nobody asked for."""
        with self.assertRaises(TriageError) as ctx:
            TriageProvider(CassetteClient(), triage_config(triage_enabled=False))
        self.assertIn("off by default", str(ctx.exception))

    def test_enabling_without_a_key_is_refused_rather_than_degraded(self):
        with self.assertRaises(ConfigError) as ctx:
            triage_config(triage_key=Secret("")).validate()
        self.assertIn("works entirely without it", str(ctx.exception))

    def test_no_mode_reaches_triage_unless_it_is_switched_on(self):
        for mode in ALLOWED_HOSTS_BY_MODE:
            with self.subTest(mode=mode):
                self.assertNotIn(TRIAGE_HOST, OutboundPolicy(mode=mode).allowed_hosts)

    def test_only_collect_can_reach_triage_even_when_enabled(self):
        """Enabling Triage must not open a host for a mode with no business collecting."""
        for mode in ("fixture", "evaluate", "propose"):
            with self.subTest(mode=mode):
                policy = OutboundPolicy(mode=mode, triage_enabled=True)
                self.assertNotIn(TRIAGE_HOST, policy.allowed_hosts)

        self.assertIn(TRIAGE_HOST, OutboundPolicy(mode="collect", triage_enabled=True).allowed_hosts)

    def test_the_policy_refuses_a_triage_url_when_triage_is_off(self):
        with self.assertRaises(OutboundPolicyError):
            OutboundPolicy(mode="collect").check(f"https://{TRIAGE_HOST}/api/v0/search")

    def test_the_soc_may_never_contact_triage(self):
        self.assertIn(TRIAGE_HOST, FORBIDDEN_FOR_SOC)


class TestReadOnly(unittest.TestCase):
    def test_the_adapter_has_no_submission_surface(self):
        for attribute in dir(TriageProvider):
            self.assertFalse(
                any(w in attribute.lower() for w in ("submit", "upload", "detonate", "post")),
                f"TriageProvider.{attribute} looks like a submission surface",
            )

    def test_the_module_names_no_write_endpoint(self):
        source = (SRC / "triage.py").read_text(encoding="utf-8")
        for forbidden in ("requests.post", "client.post", 'method="POST"', "data=payload"):
            self.assertNotIn(forbidden, source)

    def test_the_transport_it_is_handed_cannot_send_a_body(self):
        """The same property phase 3 relies on: no body, so no upload."""
        for attribute in dir(ReadOnlyHttpClient):
            self.assertFalse(
                any(w in attribute.lower() for w in ("post", "put", "upload", "submit")),
                f"ReadOnlyHttpClient.{attribute} could carry a body",
            )


class TestFieldAllowlist(unittest.TestCase):
    def setUp(self):
        self.provider = TriageProvider(CassetteClient(), triage_config())

    def test_the_allowlist_is_two_kinds_wide(self):
        """Triage corroborates; it does not originate. Widening this is a design change."""
        self.assertEqual(ALLOWED_FACT_KINDS, ("sha256", "filename"))

    def test_only_allowlisted_kinds_are_ever_emitted(self):
        evidence = self.provider.collect_public("onestart")
        self.assertTrue(evidence)
        for kind, _ in facts_of(evidence):
            self.assertIn(kind, ALLOWED_FACT_KINDS)

    def test_signatures_configs_and_command_lines_are_not_read(self):
        values = {value for _, value in facts_of(self.provider.collect_public("onestart"))}
        blob = " ".join(values).lower()
        for unread in ("ignore all previous", "beacon", "whoami", "botnet", "drops a file"):
            self.assertNotIn(unread, blob)

    def test_a_c2_url_never_becomes_a_fact(self):
        for kind, value in facts_of(self.provider.collect_public("onestart")):
            self.assertNotIn("http", value.lower(), f"{kind}={value}")

    def test_a_user_profile_path_is_reduced_to_a_bare_filename(self):
        """The path identifies a person; the filename does not. Only the filename survives."""
        values = {value for _, value in facts_of(self.provider.collect_public("onestart"))}
        self.assertIn("dropper.exe", values)
        for value in values:
            self.assertNotIn("jdoe", value.lower())
            self.assertNotIn("users", value.lower())

    def test_a_filename_that_is_itself_forbidden_data_is_dropped(self):
        values = {value for _, value in facts_of(self.provider.collect_public("onestart"))}
        for value in values:
            self.assertNotIn("@corp.example", value)

    def test_a_malformed_digest_is_dropped_rather_than_repaired(self):
        digests = {
            v for k, v in facts_of(self.provider.collect_public("onestart")) if k == "sha256"
        }
        for digest in digests:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotIn("not-a-digest", digests)


class TestCassetteContract(unittest.TestCase):
    def setUp(self):
        self.client = CassetteClient()
        self.provider = TriageProvider(self.client, triage_config())

    def test_a_family_name_seeds_a_search(self):
        """The case Hybrid Analysis cannot serve over GET, and the reason Triage exists here."""
        self.provider.collect_public("onestart")
        self.assertIn(
            "https://tria.ge/api/v0/search?limit=10&query=family%3Aonestart",
            self.client.player.requested,
        )

    def test_a_digest_seeds_a_digest_search(self):
        digest = "246e8d6a000000000000000000000000000000000000000000000000f7c9c012"
        self.provider.collect_public(digest.upper())
        self.assertTrue(
            any("sha256%3A" + digest in url for url in self.client.player.requested),
            self.client.player.requested,
        )

    def test_evidence_cites_a_public_triage_url(self):
        for evidence in self.provider.collect_public("onestart"):
            self.assertTrue(evidence.public_reference.startswith(f"https://{TRIAGE_HOST}/"))
            self.assertEqual(evidence.provider, "triage")

    def test_an_unreadable_sample_does_not_lose_the_ones_that_worked(self):
        """The cassette's search returns an id with no recorded overview, on purpose."""
        ids = {e.id for e in self.provider.collect_public("onestart")}
        self.assertIn(f"triage-{CLEAN_SAMPLE}", ids)
        self.assertIn(f"triage-{POISONED_SAMPLE}", ids)

    def test_the_key_is_sent_as_a_bearer_token(self):
        self.provider.check_key()
        self.assertEqual(self.client.headers_seen[-1]["Authorization"], f"Bearer {FAKE_KEY}")

    def test_a_bad_sample_id_is_refused_before_it_reaches_a_url(self):
        with self.assertRaises(TriageError):
            self.provider._collect_for_sample("../../etc/passwd")


class TestComposite(unittest.TestCase):
    """A required source and an optional one are not treated alike, on purpose."""

    class Working:
        name = "required"

        def collect_public(self, seed):
            return ["evidence"]

    class Broken:
        name = "optional"

        def collect_public(self, seed):
            raise RuntimeError("service unavailable")

    def test_the_optional_source_failing_does_not_fail_the_run(self):
        composite = CompositeProvider(self.Working(), [self.Broken()])
        self.assertEqual(composite.collect_public("x"), ["evidence"])
        self.assertEqual(len(composite.skipped), 1)
        self.assertIn("optional", composite.skipped[0])

    def test_the_required_source_failing_does_fail_the_run(self):
        """A collector that quietly returns nothing looks exactly like one that found nothing."""
        composite = CompositeProvider(self.Broken(), [self.Working()])
        with self.assertRaises(RuntimeError):
            composite.collect_public("x")

    def test_the_composite_names_both_sources(self):
        composite = CompositeProvider(self.Working(), [self.Broken()])
        self.assertEqual(composite.name, "required+optional")


class TestDryRunPlan(unittest.TestCase):
    def test_the_plan_is_printable_without_sending_anything(self):
        provider = TriageProvider(CassetteClient(), triage_config(dry_run=True))
        planned = plan_requests(provider, ["onestart"])
        self.assertTrue(planned)
        for line in planned:
            self.assertTrue(line.startswith("https://tria.ge/api/v0/"))

    def test_every_planned_request_is_bounded(self):
        provider = TriageProvider(CassetteClient(), triage_config(dry_run=True))
        self.assertIn("limit=10", " ".join(plan_requests(provider, ["onestart"])))

    def test_a_sample_id_seed_needs_no_search(self):
        provider = TriageProvider(CassetteClient(), triage_config(dry_run=True))
        self.assertEqual(
            plan_requests(provider, [CLEAN_SAMPLE]),
            [f"https://tria.ge/api/v0/samples/{CLEAN_SAMPLE}/overview.json"],
        )


class TestCliRefusesHalfConfiguredTriage(unittest.TestCase):
    def test_the_error_names_both_switches(self):
        """--triage alone must not silently run without Triage, nor turn it on by itself."""
        from puakiller_intel.cli import build_parser

        self.assertTrue(build_parser().parse_args(["run", "--family", "X", "--triage"]).triage)
        # The refusal itself lives in _build_provider and needs an environment; asserting the
        # message here keeps both switches named in one place a reader will find.
        source = (SRC / "cli.py").read_text(encoding="utf-8")
        self.assertIn("TRIAGE_ENABLED is not set", source)
        self.assertIn("set both, or neither", source)

    def test_triage_is_off_in_the_default_parse(self):
        from puakiller_intel.cli import build_parser

        self.assertFalse(build_parser().parse_args(["run", "--family", "X"]).triage)


class TestProviderErrorIsImportable(unittest.TestCase):
    def test_provider_error_still_covers_the_composite(self):
        self.assertTrue(issubclass(ProviderError, RuntimeError))


if __name__ == "__main__":
    unittest.main(verbosity=2)
