"""Command line entry point.

    python -m puakiller_intel run --family OneStart --seed onestart
    python -m puakiller_intel run --mode collect --dry-run --family X --seed <sha256>
    python -m puakiller_intel publish --bundle out/bundle.json --repo ZER0Nep/puakiller
    python -m puakiller_intel policy --mode collect
    python -m puakiller_intel cache --purge-older-than 30
    python -m puakiller_intel fixtures

The default mode is ``fixture``: no network, no key, no cost, no paid model call. That is what
lets the pipeline run in CI and on a laptop.

``collect`` reaches Hybrid Analysis, read-only, and refuses to start without a key rather than
returning an empty result set -- an empty collector is indistinguishable from a collector that
found nothing. ``--dry-run`` prints the exact destination list without sending anything, which
is the review step before granting the container network access.

``publish`` is the other half, and it is deliberately a separate command run by a separate
job: it takes a bundle file and a GitHub token, and it has no provider key, no model key and
no access to any raw document. It defaults to a dry run, because a command that publishes by
default publishes by accident.

Exit codes:
    0  a candidate was produced and routed, or a publication was planned or carried out
    1  the candidate was refused -- a normal, useful outcome, not an error
    2  the run could not proceed: bad input, non-public data, misconfiguration
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .bundle import BundleError, build_bundle, load_bundle, write_bundle
from .config import Config, ConfigError
from .critic import BenignCatalog
from .hybrid_analysis import HybridAnalysisError, HybridAnalysisProvider, plan_requests
from .llm import DisabledLLM, FakeDeterministicLLM, LLMError, build_client
from .github import GitHubClient, GitHubError, Repo
from .pipeline import TOOL_VERSION, render_report, run_pipeline, write_outputs
from .providers import CompositeProvider, FixtureProvider, ProviderError
from .publish import PublishError, execute, plan_publication, write_proposal
from .runlock import LockBusy, RunLock, health, record_run
from .triage import TriageError, TriageProvider
from .triage import plan_requests as plan_triage_requests
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
    run.add_argument(
        "--bundle",
        type=Path,
        default=None,
        help="also write the publication bundle here -- the only artifact the publisher may read",
    )
    run.add_argument(
        "--llm",
        default="fake",
        choices=["fake", "disabled", "env"],
        help="fake (default, free and reproducible) | disabled | env (read LLM_* from the environment)",
    )
    run.add_argument("--triage", action="store_true", help="enable the optional Triage adapter (off by default)")
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="plan every request and print the destinations, then send nothing",
    )
    run.add_argument(
        "--lock",
        type=Path,
        default=None,
        help="anti-overlap lock file; a tick that finds it held skips instead of queueing",
    )
    run.add_argument(
        "--state",
        type=Path,
        default=None,
        help="write the last-run record here, for the container healthcheck",
    )

    publish = sub.add_parser(
        "publish", help="open an Issue or a Draft PR from a bundle; needs no provider or model key"
    )
    publish.add_argument("--bundle", type=Path, required=True, help="the bundle written by 'run'")
    publish.add_argument("--repo", required=True, metavar="OWNER/REPO")
    publish.add_argument("--base", default="main", help="base branch for a draft pull request")
    publish.add_argument(
        "--root", type=Path, default=REPO_ROOT, help="repository checkout to write the proposal into"
    )
    publish.add_argument(
        "--execute",
        action="store_true",
        help="actually create the Issue or Draft PR; without it nothing is sent",
    )

    health_cmd = sub.add_parser("health", help="is the scheduled factory still running?")
    health_cmd.add_argument("--state", type=Path, required=True, help="the last-run record")
    health_cmd.add_argument(
        "--max-age",
        type=int,
        default=90_000,
        help="seconds since the last run before the container is unhealthy (default: 25h)",
    )

    cache = sub.add_parser("cache", help="inspect or prune the response cache")
    cache.add_argument("--purge-older-than", type=int, default=None, metavar="DAYS")

    policy = sub.add_parser("policy", help="print the outbound network policy for a mode")
    policy.add_argument("--mode", default="fixture", choices=MODES)
    policy.add_argument("--triage", action="store_true")

    sub.add_parser("fixtures", help="list available fixtures")
    return parser


def _client(name: str):
    """Pick the model client. The fake is the default everywhere, always.

    'env' is the only path to a paid call, and it still refuses to start without a key rather
    than silently falling back -- a run that quietly skipped the model would still emit a
    candidate, and nobody would know the analysis never happened.
    """
    if name == "fake":
        return FakeDeterministicLLM()
    if name == "disabled":
        return DisabledLLM()
    return build_client(Config.from_env(mode="fixture"))


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
        provider = HybridAnalysisProvider(client, config)

        # Triage needs BOTH the flag and the environment switch. Either one alone leaves it
        # off, because an optional provider that turns itself on is not optional.
        if args.triage and config.triage_enabled:
            provider = CompositeProvider(provider, [TriageProvider(client, config)])
        elif args.triage and not config.triage_enabled:
            raise ProviderError(
                "--triage was passed but TRIAGE_ENABLED is not set. Triage is off by default "
                "and the pipeline is specified to work entirely without it; set both, or neither."
            )
        return provider, config

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


def _run_once(args) -> tuple:
    """One pipeline run. Returns (exit code, route) so the caller can record both."""
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
            planned = []
            if config is not None:
                base = getattr(provider, "required", provider)
                planned = plan_requests(base, seeds)
                for optional in getattr(provider, "optional", []):
                    planned.extend(plan_triage_requests(optional, seeds))
            if not planned:
                print("  no outbound request would be made")
            for line in planned:
                print(f"  would GET {line}")
            return 0, "dry-run"

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
        return 2, "refused"
    except ConfigError as exc:
        # A live mode that cannot work must say so rather than return an empty result set: an
        # empty collector is indistinguishable from a collector that found nothing.
        print(f"error: {exc}", file=sys.stderr)
        return 2, "error"
    except DryRunBlocked as exc:
        print(f"dry run stopped before sending: {exc}", file=sys.stderr)
        return 0, "dry-run"
    except LLMError as exc:
        print(f"error: {redact_secrets(str(exc))}", file=sys.stderr)
        return 2, "error"
    except (ProviderError, ScoutError, HybridAnalysisError, TriageError, TransportError) as exc:
        print(f"error: {redact_secrets(str(exc))}", file=sys.stderr)
        return 2, "error"

    # An optional source that was unavailable is reported, never swallowed: a run with less
    # corroboration than usual should look different from a quiet week.
    for skipped in getattr(provider, "skipped", []):
        print(f"warning: an optional source was unavailable -- {skipped}", file=sys.stderr)

    report = render_report(result, policy.describe())
    if args.out:
        for path in write_outputs(result, args.out, report):
            print(f"wrote {path}")
    else:
        print(report)

    bundle_path = args.bundle or (Path(args.out) / "bundle.json" if args.out else None)
    if bundle_path is not None:
        # A refused candidate has no bundle, and that is not an error: the publisher having
        # nothing to read is exactly how "published nowhere" is implemented.
        if result.decision.route not in ("issue", "draft-pr"):
            print(f"no bundle written: route {result.decision.route!r} is published nowhere")
        else:
            try:
                bundle = build_bundle(result, policy.describe())
                print(f"wrote {write_bundle(bundle, bundle_path)}")
            except (BundleError, ForbiddenDataError) as exc:
                print(f"REFUSED to build a publication bundle: {exc}", file=sys.stderr)
                return 2, "error"

    return (0 if result.decision.accepted else 1), result.decision.route


def cmd_run(args) -> int:
    """Wrap one run in the anti-overlap lock and the last-run record.

    Both are optional and off unless a path is given, so the interactive command stays a plain
    batch command. They exist for the scheduled container, where two facts have to survive the
    process: that a run is in progress, and that one finished.
    """
    lock = None
    if args.lock:
        try:
            lock = RunLock(args.lock, label=args.family).acquire()
        except LockBusy as exc:
            # Not an error. A tick that skips because the previous one is still working is the
            # lock doing its job, and failing the container for it would page someone.
            print(f"skipped: {exc}")
            return 0
        if lock.stole_stale_lock:
            print(f"warning: {args.lock} was stale and has been taken over; a previous run died",
                  file=sys.stderr)

    try:
        code, route = _run_once(args)
    finally:
        if lock is not None:
            lock.release()

    if args.state:
        path = record_run(
            args.state,
            mode=args.mode,
            family=args.family,
            route=route,
            exit_code=code,
            tool_version=TOOL_VERSION,
        )
        print(f"wrote {path}")
    return code


def cmd_health(args) -> int:
    """The container healthcheck. No network, no key, no provider -- it reads one file."""
    healthy, reason = health(args.state, max_age_seconds=args.max_age)
    print(("OK: " if healthy else "UNHEALTHY: ") + reason)
    return 0 if healthy else 1


def cmd_publish(args) -> int:
    """Open an Issue or a Draft PR from a bundle. No provider key, no model, no raw document.

    This is the whole of Job D. Its inputs are a JSON summary and a GitHub token; it cannot
    read a sandbox report even if one were on disk, because nothing here knows how to.
    """
    try:
        repo = Repo.parse(args.repo)
        bundle = load_bundle(args.bundle)
    except (BundleError, GitHubError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ForbiddenDataError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        print("Nothing was published. The bundle carries data that must never leave.", file=sys.stderr)
        return 2

    policy = OutboundPolicy(mode="propose")
    print(f"repo    : {repo.full_name}")
    print(f"bundle  : {args.bundle}")
    print(f"route   : {bundle['route']} (score {bundle['score']}/100)")
    print(f"policy  : {policy.describe()}")

    client = GitHubClient(repo, dry_run=not args.execute)

    try:
        # Only asked for when something will actually be sent: a dry run must not need a token.
        titles, heads = (), ()
        if args.execute:
            titles = client.open_issue_titles("ai-intel")
            heads = client.open_pull_head_refs()

        plan = plan_publication(
            bundle, base=args.base, existing_issue_titles=titles, existing_head_refs=heads
        )
        print(plan.describe())

        if plan.kind == "draft-pr":
            path = write_proposal(bundle, args.root)
            print(f"wrote {path}")

        if not args.execute:
            print("DRY RUN -- nothing was sent. Re-run with --execute to open it.")
            return 0

        outcome = execute(plan, client)
        number = (outcome.get("response") or {}).get("number")
        html = (outcome.get("response") or {}).get("html_url", "")
        print(f"{outcome['kind']}: {html or number or outcome.get('reason', 'done')}")
        if outcome.get("labels_error"):
            print(f"warning: labels were not applied: {outcome['labels_error']}", file=sys.stderr)
    except ForbiddenDataError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except (BundleError, PublishError, GitHubError) as exc:
        print(f"error: {redact_secrets(str(exc))}", file=sys.stderr)
        return 2
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "run": cmd_run,
        "publish": cmd_publish,
        "health": cmd_health,
        "policy": cmd_policy,
        "fixtures": cmd_fixtures,
        "cache": cmd_cache,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
