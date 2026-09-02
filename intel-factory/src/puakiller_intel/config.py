"""Configuration, and the one place a secret is allowed to exist.

Two rules shape this module.

First, a secret must never be printable. ``Secret`` wraps the value so ``repr``, ``str`` and
f-strings all produce a mask; getting the real thing takes an explicit ``.reveal()`` call, which
is greppable. Logs, reports, exception messages and tracebacks all go through one of the
suppressed paths, so a key cannot leak by accident -- only by someone writing ``.reveal()``
somewhere it does not belong, which review can catch.

Second, a live mode must refuse to start without the secrets it needs, rather than starting and
silently degrading. A collector that quietly returns nothing looks exactly like a collector that
found nothing, and the difference matters when the output feeds removal rules.

Fixture mode needs no configuration at all. That is the default, and it stays the default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BASE_URL = "https://www.hybrid-analysis.com/api/v2"

# Modes that need a provider key before they can do anything real.
LIVE_MODES = frozenset({"collect"})


class ConfigError(RuntimeError):
    """Raised when the requested mode cannot run with the configuration provided."""


class Secret:
    """A string that refuses to print itself.

    Not cryptography -- it stops a key reaching a log through an f-string, a repr in a
    traceback, or a dataclass dump. Those are how keys actually leak.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str = "") -> None:
        self._value = value or ""

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        # The real length would be a hint about the secret; report the mask's length instead.
        return 3

    def __repr__(self) -> str:
        return "Secret(***)" if self._value else "Secret(unset)"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return self.__repr__()

    def __eq__(self, other) -> bool:
        return isinstance(other, Secret) and self._value == other._value

    def __hash__(self) -> int:
        return hash(("Secret", bool(self._value)))

    def reveal(self) -> str:
        """Return the real value. Every call site should be obvious in review."""
        return self._value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass
class Config:
    """Everything a run needs, with the secrets kept unprintable."""

    mode: str = "fixture"

    hybrid_analysis_key: Secret = field(default_factory=Secret)
    hybrid_analysis_base_url: str = DEFAULT_BASE_URL

    triage_enabled: bool = False
    triage_key: Secret = field(default_factory=Secret)

    llm_enabled: bool = False
    llm_provider: str = ""
    llm_model: str = ""

    publish_enabled: bool = False

    data_dir: Path = field(default_factory=lambda: Path("./data"))
    raw_retention_days: int = 30
    log_level: str = "INFO"

    # Transport behaviour. Conservative by default: this client talks to someone else's
    # service, and being a polite client is part of being allowed to keep using it.
    timeout_seconds: float = 20.0
    max_retries: int = 3
    min_request_interval: float = 1.0
    cache_ttl_seconds: int = 86_400
    dry_run: bool = False

    @classmethod
    def from_env(cls, mode: str = "fixture", dry_run: bool = False) -> "Config":
        config = cls(
            mode=mode,
            hybrid_analysis_key=Secret(os.environ.get("HYBRID_ANALYSIS_API_KEY", "")),
            hybrid_analysis_base_url=os.environ.get("HYBRID_ANALYSIS_BASE_URL", DEFAULT_BASE_URL),
            triage_enabled=_env_bool("TRIAGE_ENABLED"),
            triage_key=Secret(os.environ.get("TRIAGE_API_KEY", "")),
            llm_enabled=_env_bool("LLM_ENABLED"),
            llm_provider=os.environ.get("LLM_PROVIDER", ""),
            llm_model=os.environ.get("LLM_MODEL", ""),
            publish_enabled=_env_bool("PUBLISH_ENABLED"),
            data_dir=Path(os.environ.get("DATA_DIR", "./data")),
            raw_retention_days=_env_int("RAW_PUBLIC_RETENTION_DAYS", 30),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
            dry_run=dry_run,
        )
        config.validate()
        return config

    def validate(self) -> None:
        """Refuse to start a live mode that cannot actually work."""
        if self.mode in LIVE_MODES and not self.dry_run and not self.hybrid_analysis_key:
            raise ConfigError(
                "mode 'collect' needs HYBRID_ANALYSIS_API_KEY. Set it on the external server "
                "only -- never in the repository, and never on a SOC machine. "
                "Use --dry-run to see what would be requested without a key."
            )

        if self.triage_enabled and not self.triage_key and not self.dry_run:
            raise ConfigError(
                "TRIAGE_ENABLED is set but TRIAGE_API_KEY is empty. Triage is optional and off "
                "by default; the pipeline works entirely without it."
            )

        if not self.hybrid_analysis_base_url.startswith("https://"):
            raise ConfigError(
                f"HYBRID_ANALYSIS_BASE_URL must be https, got {self.hybrid_analysis_base_url!r}"
            )

        if self.raw_retention_days < 1:
            raise ConfigError("RAW_PUBLIC_RETENTION_DAYS must be at least 1")

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    def describe(self) -> str:
        """A one-line summary safe to print, log, or paste into a report."""
        return (
            f"mode={self.mode} dry_run={self.dry_run} "
            f"hybrid_analysis_key={'set' if self.hybrid_analysis_key else 'unset'} "
            f"triage={'on' if self.triage_enabled else 'off'} "
            f"llm={'on' if self.llm_enabled else 'off'} "
            f"publish={'on' if self.publish_enabled else 'off'}"
        )
