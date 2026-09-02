"""The only client in this package that may write anywhere. Deliberately small.

Five calls, all against ``api.github.com``: list open issues, list open pull requests, create
an issue, create a **draft** pull request, add labels. That is the whole surface.

What is missing is the design:

  * **No merge.** There is no merge endpoint at all, no auto-merge mutation, no branch
    protection call, no release, no workflow dispatch. "Aucune regle destructive n'est
    auto-mergee" is not a policy this code is asked to respect -- it is a call it cannot make.
  * **No content write.** Files are written into the checkout by ``publish.py`` and committed
    by git in the workflow, under the same review as any other commit. Handing this module the
    Contents API would let a bug write to ``main`` directly.
  * **``draft=True`` is hard-coded**, not a parameter. A parameter is something a caller can
    get wrong; here there is nothing to get wrong.
  * **No token attribute.** The credential is read from the environment at the moment a
    request is built and dropped with the header. Nothing holds it, so nothing can repr it,
    log it, or serialise it into an artifact.

This module imports no provider, no model client and no Config. The publishing job runs with a
GitHub token and with *no* Hybrid Analysis, Triage or model secret in its environment; keeping
those modules un-imported here is what makes that arrangement checkable rather than trusted.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .security import redact_secrets

API_HOST = "api.github.com"
API_ROOT = f"https://{API_HOST}"
USER_AGENT = "puakiller-intel-publisher/0.1 (+https://github.com/ZER0Nep/puakiller)"
ACCEPT = "application/vnd.github+json"
API_VERSION = "2022-11-28"

TOKEN_ENV = "GITHUB_TOKEN"

TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# GitHub's own limits. Exceeding either is a 422 after the fact; trimming beforehand keeps a
# long critique from costing a publication.
MAX_TITLE = 250
MAX_BODY = 60000

SLUG_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._")


class GitHubError(RuntimeError):
    """A GitHub call failed. The message is redacted before it is ever raised."""


def _check_slug(value: str, what: str) -> str:
    if not value or len(value) > 100 or set(value) - SLUG_CHARS:
        raise GitHubError(f"{what} {value!r} is not a valid GitHub name")
    return value


@dataclass(frozen=True)
class Repo:
    """Where publications go. Owner and name are validated, never interpolated blindly."""

    owner: str
    name: str

    def __post_init__(self) -> None:
        _check_slug(self.owner, "owner")
        _check_slug(self.name, "repository")

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @classmethod
    def parse(cls, slug: str) -> "Repo":
        owner, _, name = (slug or "").partition("/")
        if not owner or not name:
            raise GitHubError(f"expected owner/repo, got {slug!r}")
        return cls(owner=owner, name=name)


def _auth_header() -> str:
    """Build the Authorization header from the environment, and hold nothing.

    Read at call time on purpose. A client that stored the token would put it inside an object
    a traceback, a ``repr`` or a debug dump could print; this way the only copy lives for the
    duration of one request.
    """
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        raise GitHubError(
            f"{TOKEN_ENV} is not set. The publisher refuses to run without a token rather than "
            "silently producing nothing: a publication step that quietly does nothing is "
            "indistinguishable from one that had nothing to publish."
        )
    return f"Bearer {token}"


class GitHubClient:
    """Minimal, read-and-propose GitHub client.

    ``opener`` is injectable so every test in this project runs offline. The default opener is
    built only when a real request is made, which is why importing this module costs nothing
    and reaches nothing.
    """

    def __init__(self, repo: Repo, *, opener=None, dry_run: bool = False) -> None:
        self.repo = repo
        self.dry_run = dry_run
        self._opener = opener
        self.sent: list = []  # every request attempted, for the run report and for tests

    # -- transport ---------------------------------------------------------

    def _request(self, method: str, path: str, payload: dict | None = None) -> object:
        if method not in ("GET", "POST"):
            # Not a defensive nicety: PUT and DELETE are how a merge, a force-push or a branch
            # deletion would be expressed. Refusing them here means no future caller reaches
            # one by accident.
            raise GitHubError(f"method {method!r} is not available to the publisher")

        url = f"{API_ROOT}{path}"
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if host != API_HOST:
            raise GitHubError(
                f"refusing to contact {host!r}; the publisher only talks to {API_HOST}"
            )

        record = {"method": method, "path": path, "payload": payload}
        self.sent.append(record)
        if self.dry_run:
            record["result"] = "not sent (dry run)"
            return {}

        body = json.dumps(payload).encode("utf-8") if payload is not None else None

        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", _auth_header())
        request.add_header("Accept", ACCEPT)
        request.add_header("X-GitHub-Api-Version", API_VERSION)
        request.add_header("User-Agent", USER_AGENT)
        if body is not None:
            request.add_header("Content-Type", "application/json")

        # Same injection convention as llm.py: a plain callable taking (request, timeout).
        opener = self._opener or urllib.request.urlopen
        try:
            with opener(request, timeout=TIMEOUT_SECONDS) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read(4096).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - the status code is the useful part
                detail = ""
            raise GitHubError(
                redact_secrets(f"{method} {path} failed with HTTP {exc.code}: {detail}")
            ) from None
        except urllib.error.URLError as exc:
            raise GitHubError(
                redact_secrets(f"{method} {path} could not be sent: {exc.reason}")
            ) from None

        if len(raw) > MAX_RESPONSE_BYTES:
            raise GitHubError(f"{method} {path} returned more than {MAX_RESPONSE_BYTES} bytes")
        text = raw.decode("utf-8", "replace")
        if not text.strip():
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise GitHubError(f"{method} {path} did not return JSON: {exc}") from None

    # -- reads -------------------------------------------------------------

    def open_issue_titles(self, label: str) -> list:
        """Titles of open issues carrying *label*. Used to avoid filing the same one twice."""
        query = urllib.parse.urlencode({"state": "open", "labels": label, "per_page": 100})
        data = self._request("GET", f"/repos/{self.repo.full_name}/issues?{query}")
        if not isinstance(data, list):
            return []
        return [str(item.get("title", "")) for item in data if isinstance(item, dict)]

    def open_pull_head_refs(self) -> list:
        """Head branch names of open pull requests, for the same reason."""
        query = urllib.parse.urlencode({"state": "open", "per_page": 100})
        data = self._request("GET", f"/repos/{self.repo.full_name}/pulls?{query}")
        if not isinstance(data, list):
            return []
        return [
            str((item.get("head") or {}).get("ref", "")) for item in data if isinstance(item, dict)
        ]

    # -- proposals ---------------------------------------------------------

    def create_issue(self, title: str, body: str, labels) -> object:
        return self._request(
            "POST",
            f"/repos/{self.repo.full_name}/issues",
            {"title": title[:MAX_TITLE], "body": body[:MAX_BODY], "labels": sorted(set(labels))},
        )

    def create_draft_pull_request(self, title: str, body: str, head: str, base: str) -> object:
        """Open a pull request. Always a draft, never anything else.

        ``draft`` is a literal rather than an argument because a draft PR is the entire safety
        margin between a machine-written proposal and a rule that deletes user folders.
        """
        return self._request(
            "POST",
            f"/repos/{self.repo.full_name}/pulls",
            {
                "title": title[:MAX_TITLE],
                "body": body[:MAX_BODY],
                "head": head,
                "base": base,
                "draft": True,
                "maintainer_can_modify": True,
            },
        )

    def add_labels(self, issue_number: int, labels) -> object:
        if not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number <= 0:
            raise GitHubError(f"invalid issue number {issue_number!r}")
        return self._request(
            "POST",
            f"/repos/{self.repo.full_name}/issues/{issue_number}/labels",
            {"labels": sorted(set(labels))},
        )


__all__ = ["API_HOST", "GitHubClient", "GitHubError", "Repo", "TOKEN_ENV"]
