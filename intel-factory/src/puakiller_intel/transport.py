"""HTTP transport: the only code in this package that may open a socket.

Everything that makes a client safe and polite lives here, in one place, so the provider
adapters stay thin enough to read in a sitting:

  * the outbound policy is checked before every request, so a mode that allows no host cannot
    reach one even if an adapter asks;
  * timeouts on every call, because a hung collector is a silent collector;
  * exponential backoff with jitter, and 429/503 honoured via Retry-After;
  * a minimum interval between requests, because this client is a guest on someone else's
    service and quota exhaustion is a self-inflicted outage;
  * an on-disk cache with a TTL, so re-running a report does not re-fetch it;
  * structured logging that cannot print a secret;
  * a dry-run mode that plans the whole request and then does not send it.

Standard library only. urllib is unglamorous, but it is auditable, and a package that decides
what gets deleted from user machines should not take on a transport dependency for convenience.

GET only. No method here can send a body, which is what makes "Hybrid Analysis is read-only for
this project" a property of the code rather than a promise.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .models import utc_now
from .security import OutboundPolicy, OutboundPolicyError, redact_secrets

LOGGER = logging.getLogger("puakiller_intel.transport")

USER_AGENT = "puakiller-intel/0.1 (+https://github.com/ZER0Nep/puakiller)"

# Retried: the server said "not now". Everything else is a real answer, including 401 and 403,
# which mean the key is wrong -- retrying those just burns quota against a broken credential.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class TransportError(RuntimeError):
    """A request could not be completed. The message never carries a secret."""


class DryRunBlocked(TransportError):
    """Raised when a dry run reaches the point of actually sending."""


@dataclass
class RateLimiter:
    """A floor on the interval between requests.

    Not a quota manager -- the provider's own limits are the authority. This just stops a loop
    over a hundred report ids turning into a hundred requests in one second.
    """

    min_interval: float
    _last: float = field(default=0.0, repr=False)

    def wait(self, sleep=time.sleep, now=time.monotonic) -> float:
        if self.min_interval <= 0:
            return 0.0
        elapsed = now() - self._last
        delay = self.min_interval - elapsed
        if delay > 0:
            sleep(delay)
        else:
            delay = 0.0
        self._last = now()
        return delay


@dataclass
class CachedResponse:
    """One recorded response. The same shape on disk and in a test cassette."""

    url: str
    status: int
    body: str
    fetched_at: str

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "body": self.body,
            "fetched_at": self.fetched_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CachedResponse":
        return cls(
            url=data["url"],
            status=int(data.get("status", 200)),
            body=data["body"],
            fetched_at=data.get("fetched_at", ""),
        )

    def json(self):
        try:
            return json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise TransportError(f"response for {self.url} is not JSON: {exc}") from exc


class ResponseCache:
    """A content cache keyed by URL, with a TTL.

    Deliberately keyed on the URL alone and never on the credential: the cache holds public
    responses, so a second operator with a different key gets the same answers, and no file in
    the cache directory can identify who fetched it.
    """

    def __init__(self, directory, ttl_seconds: int) -> None:
        self.directory = Path(directory)
        self.ttl_seconds = ttl_seconds

    def _path(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
        return self.directory / f"{digest}.json"

    def get(self, url: str, now=time.time):
        path = self._path(url)
        if not path.is_file():
            return None
        if self.ttl_seconds > 0 and (now() - path.stat().st_mtime) > self.ttl_seconds:
            return None
        try:
            return CachedResponse.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError):
            # A corrupt cache entry is a cache miss: never a crash, and never a wrong answer.
            return None

    def put(self, response: CachedResponse) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self._path(response.url)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(response.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(path)

    def purge_older_than(self, days: int, now=time.time) -> int:
        """Retention is configurable, so it has to actually happen; nobody prunes by hand."""
        if not self.directory.is_dir():
            return 0
        cutoff = now() - days * 86_400
        removed = 0
        for path in self.directory.glob("*.json"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        return removed


def _parse_retry_after(value):
    if not value:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    # A server asking us to wait an hour is telling us to stop, not to sleep through it.
    return min(max(seconds, 0.0), 120.0)


class ReadOnlyHttpClient:
    """GET-only HTTP with policy checks, retries, rate limiting and caching.

    There is no post(), put() or upload(). Adding one would be a visible change to this file,
    which is the point: the read-only guarantee is structural, not procedural.
    """

    def __init__(self, config: Config, policy: OutboundPolicy, opener=None, sleep=time.sleep) -> None:
        self.config = config
        self.policy = policy
        self.cache = ResponseCache(config.cache_dir, config.cache_ttl_seconds)
        self.limiter = RateLimiter(config.min_request_interval)
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep
        self.planned_requests: list = []

    def build_url(self, base: str, path: str, params: dict = None) -> str:
        url = base.rstrip("/") + "/" + path.lstrip("/")
        if params:
            query = urllib.parse.urlencode(
                sorted((k, v) for k, v in params.items() if v is not None)
            )
            url = f"{url}?{query}" if query else url
        return url

    def get_json(self, url: str, headers: dict = None):
        """Fetch and parse JSON, honouring policy, cache, dry-run and backoff."""
        return self.get(url, headers=headers).json()

    def get(self, url: str, headers: dict = None) -> CachedResponse:
        # 1. Policy first. A mode that allows no host must be unable to reach one, no matter
        #    which adapter asked or how convinced it is.
        self.policy.check(url)

        cached = self.cache.get(url)
        if cached is not None:
            LOGGER.debug("cache hit %s", redact_secrets(url))
            return cached

        # 2. A dry run plans everything -- URL, header names, policy check -- and then refuses
        #    to send. That makes it useful for review, not merely a no-op.
        if self.config.dry_run:
            self.planned_requests.append(url)
            LOGGER.info(
                "dry-run would GET %s with headers %s",
                redact_secrets(url),
                sorted((headers or {}).keys()),
            )
            raise DryRunBlocked(f"dry run: would GET {url}")

        return self._fetch_with_retries(url, headers or {})

    def _fetch_with_retries(self, url: str, headers: dict) -> CachedResponse:
        attempt = 0
        while True:
            attempt += 1
            self.limiter.wait(sleep=self._sleep)
            try:
                response = self._fetch_once(url, headers)
                self.cache.put(response)
                return response
            except TransportError as exc:
                status = getattr(exc, "status", None)
                if attempt > self.config.max_retries or status not in RETRYABLE_STATUS:
                    raise
                delay = getattr(exc, "retry_after", None) or self._backoff(attempt)
                LOGGER.warning(
                    "attempt %d/%d for %s failed (%s); retrying in %.1fs",
                    attempt,
                    self.config.max_retries,
                    redact_secrets(url),
                    status,
                    delay,
                )
                self._sleep(delay)

    def _backoff(self, attempt: int) -> float:
        """Exponential with jitter.

        The jitter matters: without it, every retrying client in a fleet wakes at the same
        instant and re-creates the outage it is backing off from.
        """
        base = min(2.0 ** attempt, 30.0)
        return base * (0.5 + random.random() / 2.0)

    def _fetch_once(self, url: str, headers: dict) -> CachedResponse:
        request = urllib.request.Request(url, method="GET")
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("Accept", "application/json")
        for name, value in headers.items():
            request.add_header(name, value)

        try:
            with self._opener(request, timeout=self.config.timeout_seconds) as raw:
                body = raw.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise TransportError(f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes")
                return CachedResponse(
                    url=url,
                    status=int(getattr(raw, "status", 200)),
                    body=body.decode("utf-8", errors="replace"),
                    fetched_at=utc_now(),
                )
        except urllib.error.HTTPError as exc:
            error = TransportError(f"HTTP {exc.code} for {url}")
            error.status = exc.code
            error.retry_after = _parse_retry_after(
                exc.headers.get("Retry-After") if exc.headers else None
            )
            raise error from None
        except urllib.error.URLError as exc:
            # A URLError reason can carry a proxy URL with credentials embedded in it.
            error = TransportError(f"network error for {url}: {redact_secrets(str(exc.reason))}")
            error.status = None
            error.retry_after = None
            raise error from None
        except OutboundPolicyError:
            raise
        except TimeoutError as exc:
            error = TransportError(f"timeout after {self.config.timeout_seconds}s for {url}")
            error.status = 504
            error.retry_after = None
            raise error from exc


class CassettePlayer:
    """Replays recorded responses so contract tests need no network and no key.

    A cassette is the same JSON shape the cache writes, so a real response can be promoted to a
    test fixture by copying a file -- and, more usefully, the recording format is exercised by
    production code rather than only by tests.
    """

    def __init__(self, directory) -> None:
        self.directory = Path(directory)
        self._by_url = {}
        for path in sorted(self.directory.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            for record in data if isinstance(data, list) else [data]:
                self._by_url[record["url"]] = CachedResponse.from_dict(record)
        self.requested: list = []

    def __len__(self) -> int:
        return len(self._by_url)

    def get(self, url: str) -> CachedResponse:
        self.requested.append(url)
        if url not in self._by_url:
            known = "\n  ".join(sorted(self._by_url)) or "(none)"
            raise TransportError(f"no cassette for {url}\nrecorded:\n  {known}")
        return self._by_url[url]

    def get_json(self, url: str, headers: dict = None):
        return self.get(url).json()
