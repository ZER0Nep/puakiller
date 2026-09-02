"""Command line entry point.

    python -m puakiller_intel run --family OneStart --seed onestart
    python -m puakiller_intel run --mode collect --dry-run --family X --seed <sha256>
    python -m puakiller_intel policy --mode collect
    python -m puakiller_intel cache --purge-older-than 30
    python -m puakiller_intel fixtures

The default mode is ``fixture``: no network, no key, no cost, no paid model call. That is what
lets the pipeline run in CI and on a laptop.

``collect`` reaches Hybrid Analysis, read-only, and refuses to start without a key rather than
returning an empty result set -- an empty collector is indistinguishable from a collector that
found nothing. ``--dry-run`` prints the exact destination list without sending anything, which
is the review step before granting the container network access.

Exit codes:
    0  a candidate was produced and routed
    1  the candidate was refused -- a normal, useful outcome, not an error
    2  the run could not proceed: bad input, non-public data, misconfiguration
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config, ConfigError
from .critic import BenignCatalog
from .hybrid_analysis import HybridAnalysisError, HybridAnalysisProvider, plan_requests
from .llm import DisabledLLM, FakeDeterministicLLM
from .pipeline import render_report, run_pipeline, write_outputs
from .providers import FixtureProvider, ProviderError
from .scout import ScoutError
from .security import ForbiddenDataError, OutboundPolicy, redact_secrets
from .transport import DryRunBlocked, ReadOnlyHttpClient, TransportError

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
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="plan every request and print the destinations, then send nothing",
    )

    cache = sub.add_parser("cache", help="inspect or prune the response cache")
    cache.add_argument("--purge-older-than", type=int, default=None, metavar="DAYS")

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


def _build_provider(args, policy):
    """Pick the provider for the requested mode, and fail loudly for the ones not built yet."""
    if args.mode == "fixture":
        return FixtureProvider(args.fixtures), None

    if args.mode == "collect":
        config = Config.from_env(mode="collect", dry_run=args.dry_run)
        client = ReadOnlyHttpClient(config, policy)
        return HybridAnalysisProvider(client, config), config

    raise ProviderError(
        f"mode {args.mode!r} has no provider yet. Use --mode fixture or --mode collect, or run "
        f"'policy --mode {args.mode}' to see what it would contact."
    )


def cmd_cache(args) -> int:
    config = Config.from_env(mode="fixture")
    cache = ReadOnlyHttpClient(config, OutboundPolicy(mode="fixture")).cache
    if args.purge_older_than is None:
        entries = len(list(cache.directory.glob("*.json"))) if cache.directory.is_dir() else 0
        print(f"cache dir : {cache.directory}")
        print(f"entries   : {entries}")
        print(f"ttl       : {config.cache_ttl_seconds}s")
        print(f"retention : {config.raw_retention_days} days")
        return 0
    removed = cache.purge_older_than(args.purge_older_than)
    print(f"purged {removed} entr{'y' if removed == 1 else 'ies'} older than {args.purge_older_than} days")
    return 0


def cmd_run(args) -> int:
    policy = OutboundPolicy(mode=args.mode, triage_enabled=args.triage)
    seeds = args.seed or [args.family]

    try:
        provider, config = _build_provider(args, policy)

        # A dry run stops here, on purpose: it prints the exact destination list an operator
        # needs in order to decide whether to grant this container network access at all.
        if getattr(args, "dry_run", False):
            print(f"DRY RUN -- nothing will be sent. {policy.describe()}")
            if config is not None:
                print(config.describe())
            planned = plan_requests(provider, seeds) if config is not None else []
            if not planned:
                print("  no outbound request would be made")
            for line in planned:
                print(f"  would GET {line}")
            return 0

        if not Path(args.benign).is_file():
            raise ProviderError(f"benign corpus not found: {args.benign}")
        BenignCatalog.load(args.benign)  # fail early, rather than after the model call

        # Named apart from the provider Config above: shadowing the two would make it easy to
        # hand a Secret-bearing object to the pipeline, which has no business holding one.
        run_config = {
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
            config=run_config,
        )
    except ForbiddenDataError as exc:
        # The most important failure in the tool: loud, specific about the class of data, and
        # silent about the value itself.
        print(f"REFUSED: {exc}", file=sys.stderr)
        print("Nothing was sent anywhere. Fix the source; do not sanitise it by hand.", file=sys.stderr)
        return 2
    except ConfigError as exc:
        # A live mode that cannot work must say so rather than return an empty result set: an
        # empty collector is indistinguishable from a collector that found nothing.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except DryRunBlocked as exc:
        print(f"dry run stopped before sending: {exc}", file=sys.stderr)
        return 0
    except (ProviderError, ScoutError, HybridAnalysisError, TransportError) as exc:
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
    handlers = {"run": cmd_run, "policy": cmd_policy, "fixtures": cmd_fixtures, "cache": cmd_cache}
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
