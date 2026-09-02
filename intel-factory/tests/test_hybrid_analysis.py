#!/usr/bin/env python3
"""Contract tests for the Hybrid Analysis adapter, its transport, and its configuration.

Every test here is offline. The recorded cassettes in fixtures/cassettes/ carry synthetic
values, so the suite needs no key, no network and no quota, and it stays deterministic.

The live tests at the bottom are explicitly separated and skipped unless
PUAKILLER_INTEL_LIVE_TESTS=1 is set *and* a key is present. That separation is the point: a
suite that silently reaches the internet whenever a key happens to be in the environment is a
suite nobody can trust to be offline.

Grouped by what they defend:

    TestReadOnlyGuarantee   nothing here can submit, upload, or send a body
    TestSecretHandling      a key cannot reach a log, a repr, or an exception
    TestConfigRefusal       a live mode that cannot work says so instead of returning nothing
    TestTransport           timeouts, retries, backoff, rate limiting, caching, retention
    TestFieldAllowlist      only allowlisted fields are read; the rest cannot leak
    TestContract            recorded responses map to the evidence the pipeline expects
    TestDryRun              a dry run plans everything and sends nothing
    TestLive                skipped unless explicitly enabled

    python3 intel-factory/tests/test_hybrid_analysis.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

INTEL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(INTEL_ROOT / "src"))

from puakiller_intel import hybrid_analysis, transport  # noqa: E402
from puakiller_intel.config import Config, ConfigError, Secret  # noqa: E402
from puakiller_intel.hybrid_analysis import HybridAnalysisError, HybridAnalysisProvider  # noqa: E402
from puakiller_intel.security import OutboundPolicy, OutboundPolicyError  # noqa: E402
from puakiller_intel.transport import (  # noqa: E402
    CachedResponse,
    CassettePlayer,
    DryRunBlocked,
    RateLimiter,
    ReadOnlyHttpClient,
    ResponseCache,
    TransportError,
)

CASSETTES = INTEL_ROOT / "fixtures" / "cassettes"
BASE = "https://www.hybrid-analysis.com/api/v2"
DIGEST = "246e8d6a" + "0" * 48 + "f7c9c012"

# Obviously fake, and never sent anywhere: every test using it replays a cassette.
FAKE_KEY = "test-key-not-a-real-credential"


def offline_config(**overrides) -> Config:
    config = Config(
        mode="collect",
        hybrid_analysis_key=Secret(FAKE_KEY),
        min_request_interval=0.0,
        max_retries=2,
    )
    for name, value in overrides.items():
        setattr(config, name, value)
    return config


class CassetteClient:
    """A ReadOnlyHttpClient stand-in backed by recorded responses."""

    def __init__(self):
        self.player = CassettePlayer(CASSETTES)
        self.planned_requests = []
        self.headers_seen = []

    def build_url(self, base, path, params=None):
        return ReadOnlyHttpClient.build_url(self, base, path, params)

    def get_json(self, url, headers=None):
        self.headers_seen.append(headers or {})
        return self.player.get_json(url)


class TestReadOnlyGuarantee(unittest.TestCase):
    """Hybrid Analysis is read-only for this project, structurally."""

    def test_adapter_has_no_submission_method(self):
        for attribute in dir(HybridAnalysisProvider):
            self.assertFalse(
                any(w in attribute.lower() for w in ("submit", "upload", "detonate", "scan_file")),
                f"HybridAnalysisProvider.{attribute} looks like a submission surface",
            )

    def test_transport_has_no_body_capable_method(self):
        # A transport that can send a body can upload a sample. Keeping it GET-only is what
        # turns "we do not submit" from a promise into a property.
        for attribute in dir(ReadOnlyHttpClient):
            self.assertNotIn(attribute.lower(), ("post", "put", "patch", "upload", "send_body"))

    def test_transport_source_never_sets_a_request_body(self):
        source = (INTEL_ROOT / "src" / "puakiller_intel" / "transport.py").read_text(encoding="utf-8")
        code = "\n".join(l for l in source.splitlines() if not l.strip().startswith("#"))
        for forbidden in ('data=', 'method="POST"', "method='POST'", "add_data"):
            self.assertNotIn(forbidden, code, f"{forbidden!r} would give the transport a body")

    def test_free_text_search_is_refused_with_a_reason(self):
        provider = HybridAnalysisProvider(CassetteClient(), offline_config())
        with self.assertRaises(HybridAnalysisError) as ctx:
            provider.collect_public("OneStart")
        # The refusal has to explain itself: someone will hit this and needs to know it is a
        # deliberate limitation rather than a missing feature.
        self.assertIn("POST", str(ctx.exception))


class TestSecretHandling(unittest.TestCase):
    """A key must not reach a log, a repr, an f-string, or an exception."""

    def test_secret_never_prints_itself(self):
        secret = Secret("super-secret-value")
        for rendered in (repr(secret), str(secret), f"{secret}", "{}".format(secret)):
            self.assertNotIn("super-secret-value", rendered)
        self.assertEqual(secret.reveal(), "super-secret-value")

    def test_secret_length_is_not_a_hint(self):
        self.assertEqual(len(Secret("a" * 64)), len(Secret("b" * 8)))

    def test_config_describe_reports_presence_not_value(self):
        described = offline_config().describe()
        self.assertNotIn(FAKE_KEY, described)
        self.assertIn("hybrid_analysis_key=set", described)

    def test_dataclass_repr_does_not_leak(self):
        self.assertNotIn(FAKE_KEY, repr(offline_config()))

    def test_keys_are_revealed_only_where_they_must_be(self):
        # Two credentials, two call sites, and no others. hybrid_analysis.py holds the sandbox
        # key; llm.py holds the model key. They are separate secrets reaching separate services,
        # so they get separate, individually reviewable reveal points.
        package = INTEL_ROOT / "src" / "puakiller_intel"
        callers = sorted(
            path.name
            for path in package.glob("*.py")
            if ".reveal()" in path.read_text(encoding="utf-8") and path.name != "config.py"
        )
        self.assertEqual(
            callers,
            ["hybrid_analysis.py", "llm.py"],
            "a new .reveal() call site appeared; every one of them is a chance to leak a key",
        )


class TestConfigRefusal(unittest.TestCase):
    """A live mode that cannot work must refuse, not degrade silently."""

    def test_collect_without_a_key_refuses(self):
        with self.assertRaises(ConfigError) as ctx:
            Config(mode="collect").validate()
        self.assertIn("HYBRID_ANALYSIS_API_KEY", str(ctx.exception))

    def test_dry_run_needs_no_key(self):
        Config(mode="collect", dry_run=True).validate()  # must not raise

    def test_fixture_mode_needs_nothing(self):
        Config(mode="fixture").validate()  # must not raise

    def test_triage_enabled_without_a_key_refuses(self):
        with self.assertRaises(ConfigError):
            Config(mode="fixture", triage_enabled=True).validate()

    def test_base_url_must_be_https(self):
        with self.assertRaises(ConfigError):
            Config(hybrid_analysis_base_url="http://www.hybrid-analysis.com/api/v2").validate()

    def test_retention_must_be_positive(self):
        with self.assertRaises(ConfigError):
            Config(raw_retention_days=0).validate()


class TestTransport(unittest.TestCase):
    """Timeouts, retries, backoff, rate limiting, caching and retention."""

    def _client(self, opener, **overrides):
        slept = []
        config = offline_config(**overrides)
        client = ReadOnlyHttpClient(
            config, OutboundPolicy(mode="collect"), opener=opener, sleep=slept.append
        )
        return client, slept

    def test_policy_is_checked_before_anything_else(self):
        def opener(request, timeout=None):
            raise AssertionError("a request was made despite the policy")

        client, _ = self._client(opener)
        client.policy = OutboundPolicy(mode="fixture")  # allows nothing
        with self.assertRaises(OutboundPolicyError):
            client.get(f"{BASE}/key/current")

    def test_timeout_is_always_passed(self):
        seen = {}

        def opener(request, timeout=None):
            seen["timeout"] = timeout
            raise urllib.error.URLError("boom")

        client, _ = self._client(opener, timeout_seconds=7.5)
        with self.assertRaises(TransportError):
            client.get(f"{BASE}/key/current")
        self.assertEqual(seen["timeout"], 7.5)

    def test_429_is_retried_and_honours_retry_after(self):
        attempts = {"n": 0}

        def opener(request, timeout=None):
            attempts["n"] += 1
            raise urllib.error.HTTPError(
                request.full_url, 429, "Too Many Requests", {"Retry-After": "2"}, None
            )

        client, slept = self._client(opener)
        with self.assertRaises(TransportError):
            client.get(f"{BASE}/key/current")
        self.assertEqual(attempts["n"], 3, "one attempt then max_retries retries")
        self.assertIn(2.0, slept, "Retry-After must be honoured rather than guessed at")

    def test_401_is_not_retried(self):
        attempts = {"n": 0}

        def opener(request, timeout=None):
            attempts["n"] += 1
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

        client, _ = self._client(opener)
        with self.assertRaises(TransportError):
            client.get(f"{BASE}/key/current")
        # Retrying a bad credential just burns quota against a key that will never work.
        self.assertEqual(attempts["n"], 1)

    def test_retry_after_is_capped(self):
        # A server asking for an hour is telling us to stop, not to sleep through it.
        self.assertEqual(transport._parse_retry_after("3600"), 120.0)
        self.assertIsNone(transport._parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"))

    def test_backoff_has_jitter(self):
        client, _ = self._client(lambda *a, **k: None)
        delays = {round(client._backoff(3), 6) for _ in range(30)}
        self.assertGreater(len(delays), 1, "identical backoff across clients recreates the outage")

    def test_rate_limiter_enforces_a_floor(self):
        slept = []
        clock = {"t": 0.0}
        limiter = RateLimiter(min_interval=1.5)
        limiter.wait(sleep=slept.append, now=lambda: clock["t"])
        limiter.wait(sleep=slept.append, now=lambda: clock["t"])
        self.assertAlmostEqual(slept[-1], 1.5, places=3)

    def test_cache_hit_makes_no_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = {"n": 0}

            class Response:
                status = 200

                def read(self, n=-1):
                    return b'{"ok": true}'

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            def opener(request, timeout=None):
                calls["n"] += 1
                return Response()

            client, _ = self._client(opener, data_dir=Path(tmp))
            url = f"{BASE}/key/current"
            self.assertEqual(client.get_json(url), {"ok": True})
            self.assertEqual(client.get_json(url), {"ok": True})
            self.assertEqual(calls["n"], 1, "the second call should have come from the cache")

    def test_cache_key_does_not_depend_on_the_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = ResponseCache(Path(tmp), ttl_seconds=3600)
            path = cache._path(f"{BASE}/overview/{DIGEST}")
            self.assertEqual(path, cache._path(f"{BASE}/overview/{DIGEST}"))
            self.assertNotIn(FAKE_KEY, str(path))

    def test_corrupt_cache_entry_is_a_miss_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = ResponseCache(Path(tmp), ttl_seconds=3600)
            path = cache._path("https://example.invalid/x")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{ truncated", encoding="utf-8")
            self.assertIsNone(cache.get("https://example.invalid/x"))

    def test_expired_entry_is_a_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = ResponseCache(Path(tmp), ttl_seconds=10)
            cache.put(CachedResponse("https://example.invalid/x", 200, "{}", "2026-09-02T00:00:00Z"))
            self.assertIsNotNone(cache.get("https://example.invalid/x"))
            self.assertIsNone(cache.get("https://example.invalid/x", now=lambda: 10 ** 12))

    def test_retention_purges_old_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = ResponseCache(Path(tmp), ttl_seconds=0)
            cache.put(CachedResponse("https://example.invalid/x", 200, "{}", "2026-09-02T00:00:00Z"))
            self.assertEqual(cache.purge_older_than(30, now=lambda: 10 ** 12), 1)

    def test_network_error_message_is_redacted(self):
        def opener(request, timeout=None):
            raise urllib.error.URLError("proxy failed: token=ghp_abcdefghijklmnopqrstuvwx")

        client, _ = self._client(opener)
        with self.assertRaises(TransportError) as ctx:
            client.get(f"{BASE}/key/current")
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwx", str(ctx.exception))


class TestFieldAllowlist(unittest.TestCase):
    """Only allowlisted fields are read. A field nobody reads cannot leak."""

    def setUp(self):
        self.provider = HybridAnalysisProvider(CassetteClient(), offline_config())

    def test_unread_fields_never_become_facts(self):
        evidence = self.provider.collect_public(DIGEST)
        values = " ".join(f.value for item in evidence for f in item.facts)
        # All present in the cassette, all deliberately unread.
        for leaked in ("vmuser", "Temp", "10.0.2.15", "/silent"):
            self.assertNotIn(leaked, values, f"{leaked!r} came from a field that should not be read")

    def test_forbidden_fields_are_dropped_but_public_ones_survive(self):
        # The poisoned cassette's submit_name is a user profile path and its process name is an
        # email address; both are dropped. Its SHA-256 is a genuinely public digest, so it
        # stays. Discarding the whole report would throw away real, verifiable evidence because
        # a neighbouring field was bad -- the screen is there to remove non-public values, not
        # to punish the record that carried them.
        evidence = self.provider.collect_public("zzzz9999wwww")
        self.assertEqual(len(evidence), 1)
        kinds = {f.kind for f in evidence[0].facts}
        self.assertEqual(kinds, {"sha256"})
        rendered = " ".join(f.value for f in evidence[0].facts)
        self.assertNotIn("jdoe", rendered)
        self.assertNotIn("@", rendered)

    def test_process_paths_are_reduced_to_a_bare_name(self):
        evidence = self.provider.collect_public(DIGEST)
        processes = [f.value for item in evidence for f in item.facts if f.kind == "process"]
        self.assertIn("schtasks.exe", processes)
        self.assertTrue(all("\\" not in p for p in processes))


class TestContract(unittest.TestCase):
    """Recorded responses map to the evidence the rest of the pipeline expects."""

    def setUp(self):
        self.client = CassetteClient()
        self.provider = HybridAnalysisProvider(self.client, offline_config())

    def test_cassettes_are_present(self):
        self.assertGreaterEqual(len(CassettePlayer(CASSETTES)), 4)

    def test_hash_seed_produces_evidence(self):
        evidence = self.provider.collect_public(DIGEST)
        self.assertTrue(evidence)
        self.assertTrue(all(e.provider == "hybrid-analysis" for e in evidence))
        self.assertTrue(all(e.public_reference.startswith("https://") for e in evidence))

    def test_sha256_is_normalised_and_present(self):
        evidence = self.provider.collect_public(DIGEST.upper())
        digests = {f.value for e in evidence for f in e.facts if f.kind == "sha256"}
        self.assertEqual(digests, {DIGEST})

    def test_related_reports_are_followed_and_bounded(self):
        self.provider.collect_public(DIGEST)
        summaries = [u for u in self.client.player.requested if "/report/" in u]
        self.assertTrue(summaries, "related reports should be followed")
        self.assertLessEqual(len(summaries), hybrid_analysis.MAX_RELATED_REPORTS)

    def test_signer_and_filename_are_extracted(self):
        evidence = self.provider.collect_public(DIGEST)
        kinds = {f.kind for e in evidence for f in e.facts}
        self.assertIn("signer", kinds)
        self.assertIn("filename", kinds)

    def test_the_api_key_travels_in_a_header_only(self):
        self.provider.collect_public(DIGEST)
        self.assertTrue(self.client.headers_seen)
        for headers in self.client.headers_seen:
            self.assertEqual(headers.get("api-key"), FAKE_KEY)
        for url in self.client.player.requested:
            self.assertNotIn(FAKE_KEY, url, "a key in a URL ends up in server logs and caches")

    def test_evidence_flows_into_the_normalizer(self):
        from puakiller_intel.normalize import normalize

        normalized = normalize(self.provider.collect_public(DIGEST))
        self.assertTrue(normalized.facts)
        corroborated = [f for f in normalized.facts if f.source_count >= 2]
        self.assertTrue(corroborated, "the same artifact in two reports should merge with both ids")


class TestDryRun(unittest.TestCase):
    """A dry run plans everything and sends nothing."""

    def test_dry_run_blocks_before_sending(self):
        def opener(request, timeout=None):
            raise AssertionError("a dry run sent a request")

        config = offline_config(dry_run=True)
        client = ReadOnlyHttpClient(config, OutboundPolicy(mode="collect"), opener=opener)
        with self.assertRaises(DryRunBlocked):
            client.get(f"{BASE}/key/current")
        self.assertEqual(client.planned_requests, [f"{BASE}/key/current"])

    def test_dry_run_still_enforces_the_policy(self):
        config = offline_config(dry_run=True)
        client = ReadOnlyHttpClient(config, OutboundPolicy(mode="fixture"))
        with self.assertRaises(OutboundPolicyError):
            client.get(f"{BASE}/key/current")
        self.assertEqual(client.planned_requests, [], "a blocked host is not a planned request")

    def test_plan_lists_the_destinations(self):
        config = offline_config(dry_run=True)
        client = ReadOnlyHttpClient(config, OutboundPolicy(mode="collect"))
        provider = HybridAnalysisProvider(client, config)
        planned = hybrid_analysis.plan_requests(provider, [DIGEST])
        self.assertTrue(any(DIGEST in url for url in planned))


LIVE_ENABLED = os.environ.get("PUAKILLER_INTEL_LIVE_TESTS") == "1"
LIVE_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")


@unittest.skipUnless(
    LIVE_ENABLED and LIVE_KEY,
    "live tests need PUAKILLER_INTEL_LIVE_TESTS=1 and a key; they are never part of CI",
)
class TestLive(unittest.TestCase):
    """Reaches the real service. Never runs by accident, and never runs in CI.

    Deliberately minimal: it checks that the key works and that the contract shape still holds.
    A live suite that walked the corpus would burn quota and give different results every run,
    which is the opposite of what a test is for.
    """

    def test_key_is_accepted(self):
        config = Config.from_env(mode="collect")
        client = ReadOnlyHttpClient(config, OutboundPolicy(mode="collect"))
        payload = HybridAnalysisProvider(client, config).check_key()
        self.assertIsInstance(payload, dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
