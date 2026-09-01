"""Command line entry point.

    python -m puakiller_intel run --family OneStart
    python -m puakiller_intel policy --mode collect
    python -m puakiller_intel fixtures

The default mode is ``fixture``: no network, no key, no cost, no paid model call. That is what
lets the pipeline run in CI and on a laptop, and it is what phase 2 is specified to deliver.
Live modes exist in the parser so each one's outbound policy is printable today, but the
providers behind them arrive in later phases, and the CLI says so rather than failing with
something cryptic.

Exit codes:
    0  a candidate was produced and routed
    1  the candidate was refused -- a normal, useful outcome, not an error
    2  the run could not proceed: bad input, non-public data, misconfiguration
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .critic import BenignCatalog
from .llm import DisabledLLM, FakeDeterministicLLM
from .pipeline import render_report, run_pipeline, write_outputs
from .providers import FixtureProvider, ProviderError
from .scout import ScoutError
from .security import ForbiddenDataError, OutboundPolicy, redact_secrets

PACKAGE_ROOT = Path(__file__).resolve().parent
INTEL_ROOT = PACKAGE_ROOT.parent.parent
REPO_ROOT = INTEL_ROOT.parent

DEFAULT_FIXTURES = INTEL_ROOT / "fixtures"
DEFAULT_BENIGN = REPO_ROOT / "rules" / "benign.json"

MODES = ["fixture", "collect", "evaluate", "propose"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="puakiller-intel",
        description=(
            "Public intel factory for PUAKILLER. Produces candidates for human review, "
            "never rules."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="fixture in, candidate or refusal out")
    run.add_argument("--mode", default="fixture", choices=MODES)
    run.add_argument("--family", required=True, help="family name; also the candidate id and the seed")
    run.add_argument("--seed", action="append", default=None, help="repeatable; defaults to --family")
    run.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    run.add_argument("--benign", type=Path, default=DEFAULT_BENIGN)
    run.add_argument(
        "--out", type=Path, default=None, help="write candidate.json, decision.json and report.md here"
    )
    run.add_argument("--llm", default="fake", choices=["fake", "disabled"], help="default: deterministic fake")
    run.add_argument("--triage", action="store_true", help="enable the optional Triage adapter (off by default)")

    policy = sub.add_parser("policy", help="print the outbound network policy for a mode")
    policy.add_argument("--mode", default="fixture", choices=MODES)
    policy.add_argument("--triage", action="store_true")

    sub.add_parser("fixtures", help="list available fixtures")
    return parser


def _client(name: str):
    return FakeDeterministicLLM() if name == "fake" else DisabledLLM()


def cmd_policy(args) -> int:
    policy = OutboundPolicy(mode=args.mode, triage_enabled=args.triage)
    print(policy.describe())
    if not policy.allowed_hosts:
        print("  this mode makes no outbound connections at all")
    for host in sorted(policy.allowed_hosts):
        print(f"  allowed: {host}")
    if not args.triage:
        print("  triage: disabled (the pipeline is specified to work entirely without it)")
    return 0


def cmd_fixtures(args) -> int:
    try:
        provider = FixtureProvider(DEFAULT_FIXTURES)
    except ProviderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    names = provider.available()
    if not names:
        print("no fixtures found")
        return 0
    print(f"{len(names)} fixture(s) in {DEFAULT_FIXTURES}:")
    for name in names:
        print(f"  {name}")
    return 0


def cmd_run(args) -> int:
    if args.mode != "fixture":
        print(
            f"error: mode {args.mode!r} needs a live provider, which arrives in a later phase. "
            f"Use --mode fixture, or run 'policy --mode {args.mode}' to see what it would contact.",
            file=sys.stderr,
        )
        return 2

    policy = OutboundPolicy(mode=args.mode, triage_enabled=args.triage)
    seeds = args.seed or [args.family]

    try:
        provider = FixtureProvider(args.fixtures)
        if not Path(args.benign).is_file():
            raise ProviderError(f"benign corpus not found: {args.benign}")
        BenignCatalog.load(args.benign)  # fail early, rather than after the model call

        config = {
            "mode": args.mode,
            "seeds": sorted(seeds),
            "family": args.family,
            "llm": args.llm,
            "triage_enabled": args.triage,
            "llm_client": _client(args.llm),
        }
        result = run_pipeline(
            provider=provider,
            seeds=seeds,
            family=args.family,
            benign_path=args.benign,
            config=config,
        )
    except ForbiddenDataError as exc:
        # The most important failure in the tool: loud, specific about the class of data, and
        # silent about the value itself.
        print(f"REFUSED: {exc}", file=sys.stderr)
        print("Nothing was sent anywhere. Fix the source; do not sanitise it by hand.", file=sys.stderr)
        return 2
    except (ProviderError, ScoutError) as exc:
        print(f"error: {redact_secrets(str(exc))}", file=sys.stderr)
        return 2

    report = render_report(result, policy.describe())
    if args.out:
        for path in write_outputs(result, args.out, report):
            print(f"wrote {path}")
    else:
        print(report)

    return 0 if result.decision.accepted else 1


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return {"run": cmd_run, "policy": cmd_policy, "fixtures": cmd_fixtures}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
