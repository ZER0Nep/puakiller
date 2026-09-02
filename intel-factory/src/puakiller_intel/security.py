"""Two hard boundaries: what may never enter the factory, and what it may never talk to.

SECURITE-ET-TELEMETRIE.md states the invariant plainly: the external factory must never learn
what the SOC observed. It starts from public seeds and public reports, builds a public
catalog, and the SOC compares locally. Nothing flows the other way.

That invariant cannot be enforced by good intentions inside a prompt, because the prompt is
exactly what an attacker targets. It is enforced here, before any model sees a byte, and it
fails closed: input that merely *looks* like SOC data is refused rather than sanitised, since
a sanitiser that silently drops a hostname also silently drops the operator's chance to notice
that SOC data reached this code path at all.

Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
#  Forbidden data
# ---------------------------------------------------------------------------

# Each pattern names the class of data it catches. Messages are written for the operator who
# has to work out why a fixture was refused, so they say what was seen, never the value.
_FORBIDDEN_PATTERNS: tuple[tuple[str, "re.Pattern[str]", str], ...] = (
    (
        "windows-user-path",
        re.compile(r"(?i)\b[a-z]:\\users\\(?!public\b|default\b|all\s+users\b)[^\\\s\"']+"),
        "a Windows user profile path identifies a real person or machine",
    ),
    (
        "unc-share",
        re.compile(r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+"),
        "a UNC network share path is internal infrastructure",
    ),
    (
        "email-address",
        re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
        "an email address identifies a person",
    ),
    (
        "private-ipv4",
        re.compile(
            r"\b(?:10(?:\.\d{1,3}){3}"
            r"|192\.168(?:\.\d{1,3}){2}"
            r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
            r"|127(?:\.\d{1,3}){3})\b"
        ),
        "a private or loopback IPv4 address is internal infrastructure",
    ),
    (
        "internal-domain",
        re.compile(r"(?i)\b[a-z0-9-]+\.(?:local|internal|corp|lan|intranet|home\.arpa)\b"),
        "an internal domain suffix is not public information",
    ),
    (
        "soc-ticket",
        re.compile(r"(?i)\b(?:INC|TICKET|CASE|ALERT|RITM|SOC)[-_ ]?\d{3,}\b"),
        "a ticket or alert identifier is SOC-internal",
    ),
    (
        "edr-siem-marker",
        re.compile(r"(?i)\b(?:crowdstrike|sentinelone|defender\s+atp|splunk|qradar|elastic\s+siem)\b"),
        "an EDR/SIEM product reference suggests internal telemetry, not a public report",
    ),
    (
        "hostname-assignment",
        re.compile(r"(?i)\b(?:hostname|computername|machine(?:name)?|username|user\s*name)\s*[:=]\s*\S+"),
        "an explicitly labelled hostname or username identifies a machine or person",
    ),
)

# Secrets are redacted rather than refused: they appear in logs and exception text, not in
# source documents, and losing the surrounding message would cost more than it saves.
_SECRET_PATTERNS: tuple["re.Pattern[str]", ...] = (
    re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password|authorization|bearer)\b\s*[:=]\s*\S+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
)

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class ForbiddenMatch:
    """One reason an input was refused. Carries the class, never the offending value."""

    code: str
    reason: str
    where: str

    def render(self) -> str:
        return f"{self.code} in {self.where}: {self.reason}"


class ForbiddenDataError(RuntimeError):
    """Raised when input carries data the factory must never receive."""

    def __init__(self, matches: list[ForbiddenMatch]) -> None:
        self.matches = matches
        detail = "; ".join(m.render() for m in matches)
        super().__init__(f"refusing input that carries non-public data: {detail}")


def _scannable(text: str) -> str:
    """Collapse the escaping that would otherwise hide a path from these patterns.

    Sources arrive as JSON, and JSON doubles every backslash: a Windows profile path is stored
    as C:\\Users\\jdoe. Scanning the raw document without undoing that lets the one
    thing these patterns most need to catch walk straight through -- which is exactly what
    happened until a test caught it. URL-encoded separators get the same treatment.
    """
    return text.replace("\\\\", "\\").replace("%5C", "\\").replace("%5c", "\\")


def scan_forbidden(text: str, where: str = "input") -> list[ForbiddenMatch]:
    """Return every class of forbidden data found in *text*.

    The offending substring is deliberately not returned or logged. Reporting "a Windows user
    profile path was found in fixture X" is enough to act on; echoing the path would copy the
    very data this function exists to keep out.
    """
    if not text:
        return []
    # Both forms are scanned, because each hides something the other reveals: JSON escaping
    # conceals a user profile path from the raw text, while un-escaping conceals a UNC share
    # (\\SERVER\share becomes \SERVER\share). Checking one form only leaves a real gap.
    haystacks = (text, _scannable(text))
    return [
        ForbiddenMatch(code=code, reason=reason, where=where)
        for code, pattern, reason in _FORBIDDEN_PATTERNS
        if any(pattern.search(h) for h in haystacks)
    ]


def assert_public(text: str, where: str = "input") -> None:
    """Fail closed if *text* carries anything the factory must never learn."""
    matches = scan_forbidden(text, where)
    if matches:
        raise ForbiddenDataError(matches)


def redact_secrets(text: str) -> str:
    """Mask credentials so they cannot reach a log, a report or an exception message."""
    if not text:
        return text
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


# ---------------------------------------------------------------------------
#  Outbound network policy
# ---------------------------------------------------------------------------

# The project must be able to produce an auditable list of destinations per mode. In fixture
# mode -- the default for development and CI -- that list is empty, and this module is what
# makes the claim checkable rather than aspirational.
ALLOWED_HOSTS_BY_MODE: dict[str, frozenset] = {
    "fixture": frozenset(),
    "collect": frozenset({"www.hybrid-analysis.com"}),
    "evaluate": frozenset(),
    "propose": frozenset({"api.github.com"}),
}

# Only ever enabled explicitly, never by default (DECISIONS.md).
TRIAGE_HOST = "tria.ge"

# Hosts the SOC-side PowerShell must never contact. Kept here so the policy lives in one place,
# even though the scripts enforce it by simply not containing these names.
FORBIDDEN_FOR_SOC = frozenset(
    {"www.hybrid-analysis.com", "tria.ge", "api.anthropic.com", "api.openai.com"}
)


class OutboundPolicyError(RuntimeError):
    """Raised when code attempts to reach a host the current mode does not allow."""


@dataclass(frozen=True)
class OutboundPolicy:
    """The set of hosts reachable in a given mode.

    Held as data so a test can assert the whole surface, and so an operator can print it
    before granting the container any network access at all.
    """

    mode: str
    triage_enabled: bool = False
    # The model API is its own axis, not a property of a mode. Job B (analysis) may talk to a
    # model; Job C (validation) may not, and both can happen in an 'evaluate' run. Making this
    # explicit means "the validator works with no network" stays true by construction rather
    # than by the mode happening to be set right.
    llm_host: str = ""

    @property
    def allowed_hosts(self) -> frozenset:
        if self.mode not in ALLOWED_HOSTS_BY_MODE:
            raise OutboundPolicyError(f"unknown mode {self.mode!r}")
        hosts = ALLOWED_HOSTS_BY_MODE[self.mode]
        if self.triage_enabled and self.mode == "collect":
            hosts = hosts | {TRIAGE_HOST}
        if self.llm_host:
            hosts = hosts | {self.llm_host}
        return frozenset(hosts)

    def check(self, url: str) -> None:
        """Raise unless *url* targets a host this mode allows."""
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            raise OutboundPolicyError(f"refusing a request with no host: {url!r}")
        if host not in self.allowed_hosts:
            allowed = ", ".join(sorted(self.allowed_hosts)) or "(none)"
            raise OutboundPolicyError(
                f"mode {self.mode!r} may not contact {host!r}; allowed: {allowed}"
            )

    def describe(self) -> str:
        hosts = sorted(self.allowed_hosts)
        return f"mode={self.mode} outbound={'none' if not hosts else ', '.join(hosts)}"

    @property
    def reaches_nothing(self) -> bool:
        return not self.allowed_hosts
