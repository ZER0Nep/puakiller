#!/usr/bin/env python3
"""Tests for the model boundary: prompts, strict JSON, and the advisory critic.

No test here makes a paid call, and none can: every client is driven through an injected opener,
and the default client everywhere is the deterministic fake. That is the phase's requirement
rather than a convenience -- a suite that costs money per run stops being run.

Grouped by what they defend:

    TestPromptLibrary        prompts are files, versioned by content
    TestStrictJson           a reply that did not follow the contract is refused, not repaired
    TestClientInterchange    the provider can be swapped; both satisfy one contract
    TestNoPaidCallByDefault  nothing reaches a model API unless explicitly configured
    TestAdvisoryCritic       the model can object, and can never block
    TestSecretsInLlmPath     a model key cannot reach a log or an exception

    python3 intel-factory/tests/test_llm_roles.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

INTEL_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = INTEL_ROOT.parent
sys.path.insert(0, str(INTEL_ROOT / "src"))

from puakiller_intel.config import Config, ConfigError, Secret  # noqa: E402
from puakiller_intel.critic import BenignCatalog, Critic  # noqa: E402
from puakiller_intel.llm import (  # noqa: E402
    AnthropicClient,
    DisabledLLM,
    FakeDeterministicLLM,
    LLMError,
    LLMResponse,
    OpenAICompatibleClient,
    PromptLibrary,
    build_client,
    extract_json_object,
)
from puakiller_intel.models import Candidate, Indicator  # noqa: E402
from puakiller_intel.security import OutboundPolicyError  # noqa: E402
from puakiller_intel.validate import Validator  # noqa: E402

PROMPTS = REPO_ROOT / "prompts"
BENIGN = REPO_ROOT / "rules" / "benign.json"
FAKE_KEY = "sk-not-a-real-key-for-tests"


def sample_candidate(**overrides) -> Candidate:
    return Candidate(
        id=overrides.get("id", "sample-candidate"),
        family=overrides.get("family", "SampleFamily"),
        indicators=overrides.get(
            "indicators",
            [
                Indicator(kind="sha256", value="a" * 64, evidence_ids=("e1", "e2"), confidence=90, risk="low"),
                Indicator(kind="process", value="distinctiveproc", evidence_ids=("e1", "e2"), confidence=70, risk="medium"),
            ],
        ),
    )


class ScriptedLLM:
    """Returns a fixed payload. Never touches the network."""

    model = "scripted-test-double"

    def __init__(self, payload, role_error=None):
        self.payload = payload
        self.role_error = role_error
        self.calls = []

    def complete_json(self, role, system, user):
        self.calls.append({"role": role, "system": system, "user": user})
        if self.role_error:
            raise self.role_error
        return LLMResponse(self.payload, role, f"{role}-v1", self.model)


class TestPromptLibrary(unittest.TestCase):
    """Prompts are versioned artifacts on disk, not string constants."""

    def test_both_role_prompts_exist(self):
        library = PromptLibrary(PROMPTS)
        for role in ("scout", "critic"):
            with self.subTest(role=role):
                self.assertTrue(library.load(role).text)

    def test_version_comes_from_frontmatter(self):
        self.assertEqual(PromptLibrary(PROMPTS).load("scout").version, "scout-v1")

    def test_frontmatter_is_stripped_from_the_prompt_text(self):
        # The model should receive instructions, not our bookkeeping.
        self.assertNotIn("---", PromptLibrary(PROMPTS).load("scout").text[:10])

    def test_stamp_pins_the_content(self):
        stamp = PromptLibrary(PROMPTS).load("critic").stamp
        self.assertTrue(stamp.startswith("critic-v1+"))
        self.assertGreaterEqual(len(stamp.split("+", 1)[1]), 8)

    def test_editing_a_prompt_changes_the_stamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "critic-system.md"
            path.write_text("---\nrole: critic\nversion: critic-v1\n---\nA", encoding="utf-8")
            first = PromptLibrary(tmp).load("critic").stamp
            path.write_text("---\nrole: critic\nversion: critic-v1\n---\nB", encoding="utf-8")
            second = PromptLibrary(tmp).load("critic").stamp
        self.assertNotEqual(first, second)

    def test_a_missing_prompt_is_an_error_not_a_default(self):
        # Silently falling back would produce candidates nobody can reproduce.
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(LLMError):
                PromptLibrary(tmp).load("scout")
            self.assertIn("missing", PromptLibrary(tmp).stamps()["scout"])

    def test_prompts_forbid_patterns_and_code(self):
        text = PromptLibrary(PROMPTS).load("scout").text.lower()
        self.assertIn("regular expression", text)
        self.assertIn("never output code", text)

    def test_critic_prompt_states_that_it_cannot_block(self):
        self.assertIn("advisory", PromptLibrary(PROMPTS).load("critic").text.lower())


class TestStrictJson(unittest.TestCase):
    """A reply that did not follow the contract is refused, never repaired."""

    def test_bare_object(self):
        self.assertEqual(extract_json_object('{"a": 1}'), {"a": 1})

    def test_single_fence_is_tolerated(self):
        self.assertEqual(extract_json_object('```json\n{"a": 1}\n```'), {"a": 1})

    def test_prose_before_the_object_is_refused(self):
        # Guessing which part was "meant" is exactly how a wrong indicator gets in.
        with self.assertRaises(LLMError):
            extract_json_object('Sure! Here is the result:\n{"a": 1}')

    def test_two_fenced_blocks_are_refused(self):
        with self.assertRaises(LLMError):
            extract_json_object('```json\n{"a": 1}\n```\n```json\n{"b": 2}\n```')

    def test_array_is_refused(self):
        with self.assertRaises(LLMError):
            extract_json_object("[1, 2, 3]")

    def test_truncated_json_is_refused(self):
        with self.assertRaises(LLMError):
            extract_json_object('{"a": 1')

    def test_empty_response_is_refused(self):
        for value in ("", "   ", None):
            with self.subTest(value=value):
                with self.assertRaises(LLMError):
                    extract_json_object(value)


class TestClientInterchange(unittest.TestCase):
    """The provider is swappable, and both clients satisfy one contract."""

    def _opener(self, body):
        class Response:
            def read(self, n=-1):
                return json.dumps(body).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return lambda request, timeout=None: Response()

    def test_anthropic_client_parses_a_messages_reply(self):
        client = AnthropicClient(
            api_key=Secret(FAKE_KEY),
            opener=self._opener({"content": [{"type": "text", "text": '{"findings": []}'}]}),
        )
        self.assertEqual(client.complete_json("critic", "sys", "{}").payload, {"findings": []})

    def test_openai_client_parses_a_chat_reply(self):
        client = OpenAICompatibleClient(
            api_key=Secret(FAKE_KEY),
            opener=self._opener({"choices": [{"message": {"content": '{"findings": []}'}}]}),
        )
        self.assertEqual(client.complete_json("critic", "sys", "{}").payload, {"findings": []})

    def test_both_clients_satisfy_the_same_contract(self):
        # Interchangeability is a requirement: the design must not depend on one vendor
        # remaining available or affordable.
        for client in (
            AnthropicClient(api_key=Secret(FAKE_KEY)),
            OpenAICompatibleClient(api_key=Secret(FAKE_KEY)),
        ):
            with self.subTest(client=type(client).__name__):
                self.assertTrue(hasattr(client, "complete_json"))
                self.assertTrue(client.model)

    def test_temperature_defaults_to_zero(self):
        # Extraction, not prose: two runs over the same evidence must not disagree about what a
        # report said.
        self.assertEqual(AnthropicClient(api_key=Secret(FAKE_KEY)).temperature, 0.0)
        self.assertEqual(OpenAICompatibleClient(api_key=Secret(FAKE_KEY)).temperature, 0.0)

    def test_token_limit_is_set(self):
        self.assertGreater(AnthropicClient(api_key=Secret(FAKE_KEY)).max_tokens, 0)

    def test_outbound_policy_applies_to_the_model_api_too(self):
        client = AnthropicClient(api_key=Secret(FAKE_KEY), base_url="https://evil.invalid")
        with self.assertRaises(OutboundPolicyError):
            client.complete_json("critic", "sys", "{}")

    def test_unknown_provider_is_refused(self):
        config = Config(llm_enabled=True, llm_provider="mystery-vendor", llm_key=Secret(FAKE_KEY))
        with self.assertRaises(LLMError):
            build_client(config)


class TestNoPaidCallByDefault(unittest.TestCase):
    """Nothing reaches a model API unless someone configured it on purpose."""

    def test_default_config_yields_the_fake(self):
        self.assertIsInstance(build_client(Config()), FakeDeterministicLLM)

    def test_llm_enabled_without_a_provider_still_yields_the_fake(self):
        self.assertIsInstance(build_client(Config(llm_enabled=True)), FakeDeterministicLLM)

    def test_a_real_provider_without_a_key_is_refused(self):
        with self.assertRaises(LLMError):
            build_client(Config(llm_enabled=True, llm_provider="anthropic"))

    def test_config_validation_also_refuses_it(self):
        with self.assertRaises(ConfigError):
            Config(llm_enabled=True, llm_provider="anthropic").validate()

    def test_disabled_client_refuses_loudly(self):
        # A silent no-op would still emit a candidate, and nobody would know the analysis never
        # happened.
        with self.assertRaises(LLMError):
            DisabledLLM().complete_json("scout", "sys", "{}")


class TestAdvisoryCritic(unittest.TestCase):
    """The model may object. It may never block."""

    def setUp(self):
        self.benign = BenignCatalog.load(BENIGN)

    def test_findings_are_surfaced(self):
        client = ScriptedLLM(
            {
                "findings": [
                    {
                        "code": "common-word",
                        "message": "means 'ready' in Dutch",
                        "indicator_value": "distinctiveproc",
                    }
                ]
            }
        )
        critique = Critic(self.benign, llm_client=client).review(sample_candidate())
        self.assertIn("advisory:common-word", {f.code for f in critique.findings})

    def test_no_advisory_finding_can_block(self):
        client = ScriptedLLM(
            {
                "findings": [
                    {
                        "code": "benign-collision",
                        "message": "this is Windows itself",
                        "indicator_value": "distinctiveproc",
                    }
                ]
            }
        )
        critique = Critic(self.benign, llm_client=client).review(sample_candidate())
        self.assertEqual(critique.blocking, [], "a model must not be able to veto on its own")

    def test_a_model_cannot_talk_the_validator_into_accepting(self):
        # The mirror of the previous test: a model saying "all clear" changes nothing either.
        candidate = sample_candidate(
            indicators=[
                Indicator(kind="folder", value="OBS Studio", evidence_ids=("e1", "e2"), confidence=99, risk="high")
            ]
        )
        client = ScriptedLLM(
            {"findings": [{"code": "all-clear", "message": "safe to remove", "indicator_value": None}]}
        )
        critique = Critic(self.benign, llm_client=client).review(candidate)
        decision = Validator().validate(candidate, critique)
        self.assertFalse(decision.accepted)
        self.assertIn("OBS Studio", decision.rejected_indicators)

    def test_findings_about_unknown_indicators_are_dropped(self):
        client = ScriptedLLM(
            {"findings": [{"code": "overreach", "message": "about nothing", "indicator_value": "never-proposed"}]}
        )
        critique = Critic(self.benign, llm_client=client).review(sample_candidate())
        self.assertNotIn("advisory:overreach", {f.code for f in critique.findings})

    def test_duplicate_of_a_deterministic_rule_is_dropped(self):
        client = ScriptedLLM(
            {
                "findings": [
                    {
                        "code": "short-name-wide-effect",
                        "message": "too short",
                        "indicator_value": "distinctiveproc",
                    }
                ]
            }
        )
        critique = Critic(self.benign, llm_client=client).review(sample_candidate())
        self.assertNotIn("advisory:short-name-wide-effect", {f.code for f in critique.findings})

    def test_a_broken_model_does_not_stop_the_review(self):
        client = ScriptedLLM(None, role_error=LLMError("rate limited"))
        critique = Critic(self.benign, llm_client=client).review(sample_candidate())
        self.assertIn("advisory-unavailable", {f.code for f in critique.findings})
        self.assertEqual(critique.blocking, [])

    def test_deterministic_blocking_still_works_without_a_model(self):
        candidate = sample_candidate(
            indicators=[
                Indicator(kind="folder", value="OBS Studio", evidence_ids=("e1", "e2"), confidence=90, risk="high")
            ]
        )
        self.assertTrue(Critic(self.benign).review(candidate).blocking)

    def test_the_critic_sees_the_candidate_not_the_evidence(self):
        client = ScriptedLLM({"findings": []})
        Critic(self.benign, llm_client=client).review(sample_candidate())
        sent = json.loads(client.calls[0]["user"])
        self.assertEqual(set(sent), {"family", "indicators"})
        self.assertNotIn("evidence_ids", client.calls[0]["user"])

    def test_the_injection_preamble_is_present(self):
        client = ScriptedLLM({"findings": []})
        Critic(self.benign, llm_client=client).review(sample_candidate())
        self.assertIn("untrusted data", client.calls[0]["system"])


class TestSecretsInLlmPath(unittest.TestCase):
    """A model key must not reach a log or an exception."""

    def test_http_error_body_is_never_echoed(self):
        def opener(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 401, f"invalid key {FAKE_KEY}", {}, None)

        client = AnthropicClient(api_key=Secret(FAKE_KEY), opener=opener)
        with self.assertRaises(LLMError) as ctx:
            client.complete_json("critic", "sys", "{}")
        self.assertNotIn(FAKE_KEY, str(ctx.exception))

    def test_network_error_reason_is_redacted(self):
        def opener(request, timeout=None):
            raise urllib.error.URLError("proxy rejected: token=ghp_abcdefghijklmnopqrstuvwx")

        client = AnthropicClient(api_key=Secret(FAKE_KEY), opener=opener)
        with self.assertRaises(LLMError) as ctx:
            client.complete_json("critic", "sys", "{}")
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwx", str(ctx.exception))

    def test_config_describe_does_not_leak_the_model_key(self):
        described = Config(
            llm_enabled=True, llm_provider="anthropic", llm_key=Secret(FAKE_KEY)
        ).describe()
        self.assertNotIn(FAKE_KEY, described)


if __name__ == "__main__":
    unittest.main(verbosity=2)
