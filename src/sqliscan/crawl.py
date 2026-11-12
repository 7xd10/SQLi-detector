"""Target parsing, scope enforcement, link extraction and the bounded crawl.

The crawl is breadth-first by depth level and bounded three ways: total pages,
per-page link count, and the shared request budget. Every bound exists because
unbounded crawling is how a scanner takes a site down by accident.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .http import (
    BudgetExceeded,
    RateLimiter,
    Request,
    RequestBudget,
    Response,
    Transport,
    TransportError,
    send,
)
from .models import CrawlStats, Method

LOGGER = logging.getLogger(__name__)

DEFAULT_PORTS = {"http": 80, "https": 443}

# Paths that change state on a GET. A crawler that follows a logout link ends
# the session it was using; one that follows a delete link destroys data.
DEFAULT_DENY = (
    r"/log[-_]?out",
    r"/sign[-_]?out",
    r"/log[-_]?off",
    r"/delete",
    r"/remove",
    r"/destroy",
    r"/unsubscribe",
    r"/deactivate",
    r"/revoke",
    r"/checkout",
    r"/purchase",
    r"/shutdown",
)

# Fetched only if a link explicitly points at them, and never parsed as HTML.
SKIP_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".bmp",
        ".css",
        ".js",
        ".map",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp3",
        ".mp4",
        ".webm",
        ".ogg",
        ".wav",
        ".avi",
        ".mov",
        ".zip",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
    }
)

_MAX_LINKS_PER_PAGE = 2000


class TargetError(ValueError):
    """The target string is not something this scanner can address."""


def parse_target(raw: str) -> str:
    """Normalise a target into an absolute http(s) URL.

    A bare host gets https. Credentials in the URL are rejected rather than
    silently dropped, because a scan that authenticates as the wrong principal
    produces evidence nobody can reproduce.
    """
    text = raw.strip()
    if not text:
        raise TargetError("empty target")
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    if parts.scheme.lower() not in ("http", "https"):
        raise TargetError(f"unsupported scheme {parts.scheme!r}; use http or https")
    if parts.username or parts.password:
        raise TargetError(
            "credentials in the target URL are not supported; use --header"
        )
    if not parts.hostname:
        raise TargetError(f"target has no host: {raw!r}")
    try:
        _ = parts.port
    except ValueError as exc:
        raise TargetError(f"invalid port in target {raw!r}") from exc
    canonical = canonicalise(text)
    if canonical is None:  # pragma: no cover - guarded by the checks above
        raise TargetError(f"cannot parse target {raw!r}")
    return canonical


def canonicalise(url: str) -> str | None:
    """Lowercase scheme and host, drop default ports and fragments."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        return None
    host = parts.hostname
    if not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


class Scope:
    """Which hosts may be touched. Ports and schemes are not restricted."""

    def __init__(
        self,
        hosts: Iterable[str],
        *,
        include_subdomains: bool = False,
    ) -> None:
        self._hosts = frozenset(host.lower() for host in hosts)
        self._subdomains = include_subdomains

    @classmethod
    def from_url(cls, url: str, *, include_subdomains: bool = False) -> Scope:
        host = urlsplit(url).hostname or ""
        return cls([host], include_subdomains=include_subdomains)

    def extend(self, hosts: Iterable[str]) -> Scope:
        merged = self._hosts.union(host.lower() for host in hosts)
        return Scope(merged, include_subdomains=self._subdomains)

    def allows(self, url: str) -> bool:
        host = urlsplit(url).hostname
        if not host:
            return False
        host = host.lower()
        if host in self._hosts:
            return True
        if self._subdomains:
            return any(host.endswith(f".{base}") for base in self._hosts)
        return False

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(sorted(self._hosts))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Scope({sorted(self._hosts)}, subdomains={self._subdomains})"


class DenyList:
    """Path patterns that must never be requested during a crawl."""

    def __init__(
        self,
        patterns: Sequence[str] = DEFAULT_DENY,
        extra: Sequence[str] = (),
    ) -> None:
        self._patterns = tuple(
            re.compile(pattern, re.IGNORECASE) for pattern in (*patterns, *extra)
        )

    def blocks(self, url: str) -> bool:
        parts = urlsplit(url)
        target = f"{parts.path}?{parts.query}" if parts.query else parts.path
        return any(pattern.search(target) for pattern in self._patterns)

    def __len__(self) -> int:
        return len(self._patterns)


@dataclass(frozen=True)
class Form:
    action: str
    method: Method
    fields: tuple[tuple[str, str], ...]
    has_file: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "method": self.method.value,
            "fields": [[name, value] for name, value in self.fields],
            "has_file": self.has_file,
        }


@dataclass(frozen=True)
class Page:
    url: str
    status: int
    content_type: str
    links: tuple[str, ...] = ()
    forms: tuple[Form, ...] = ()


@dataclass(frozen=True)
class CrawlOutcome:
    seed: str
    pages: tuple[Page, ...]
    stats: CrawlStats


class _PageParser(HTMLParser):
    """Collect anchors, form actions and form fields from one document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._action: str | None = None
        self._method: str = "GET"
        self._fields: list[tuple[str, str]] = []
        self._has_file = False
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        tag = tag.lower()

        if tag == "base" and "href" in values and self.base_href is None:
            self.base_href = values["href"]
            return

        if tag in ("a", "area") and "href" in values:
            self._add(values["href"])
            return

        if tag == "iframe" and "src" in values:
            self._add(values["src"])
            return

        if tag == "form":
            self._in_form = True
            self._action = values.get("action", "")
            self._method = values.get("method", "GET").upper()
            self._fields = []
            self._has_file = False
            return

        if not self._in_form:
            return

        if tag == "input":
            kind = values.get("type", "text").lower()
            name = values.get("name", "")
            if kind == "file":
                self._has_file = True
                return
            if not name or kind in ("submit", "button", "reset", "image"):
                return
            if kind in ("checkbox", "radio") and "checked" not in values:
                return
            self._fields.append((name, values.get("value", "")))
        elif tag in ("textarea", "select"):
            name = values.get("name", "")
            if name:
                self._fields.append((name, ""))
        elif tag == "button":
            name = values.get("name", "")
            if name and values.get("type", "submit").lower() == "submit":
                self._fields.append((name, values.get("value", "")))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form:
            self._in_form = False
            method = Method.POST if self._method == "POST" else Method.GET
            self.forms.append(
                Form(
                    action=self._action or "",
                    method=method,
                    fields=tuple(self._fields),
                    has_file=self._has_file,
                )
            )
            self._action = None
            self._fields = []

    def _add(self, href: str) -> None:
        href = href.strip()
        if not href:
            return
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return
        if len(self.links) < _MAX_LINKS_PER_PAGE:
            self.links.append(href)


def parse_page(html: str) -> tuple[str | None, tuple[str, ...], tuple[Form, ...]]:
    """Return ``(base_href, links, forms)`` from one document."""
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:
        LOGGER.debug("html parser stopped early: %s", exc)
    return parser.base_href, tuple(parser.links), tuple(parser.forms)


def resolve_links(
    raw_links: Sequence[str],
    page_url: str,
    base_href: str | None,
    *,
    scope: Scope,
    deny: DenyList,
) -> list[str]:
    """Turn raw hrefs into unique, in-scope, non-denied absolute URLs."""
    base = urljoin(page_url, base_href) if base_href else page_url
    seen: set[str] = set()
    resolved: list[str] = []
    for href in raw_links:
        absolute = canonicalise(urljoin(base, href))
        if absolute is None or absolute in seen:
            continue
        if not scope.allows(absolute) or deny.blocks(absolute):
            continue
        if _extension(absolute) in SKIP_EXTENSIONS:
            continue
        seen.add(absolute)
        resolved.append(absolute)
    return resolved


def _extension(url: str) -> str:
    path = urlsplit(url).path.lower()
    dot = path.rfind(".")
    slash = path.rfind("/")
    if dot <= slash:
        return ""
    return path[dot:]


def load_robots(text: str | None) -> RobotFileParser | None:
    """Build a policy from an already-fetched robots.txt body.

    Fetching through the transport (rather than ``RobotFileParser.read``) keeps
    the request on the budget, the rate limiter and the retry policy.
    """
    if text is None:
        return None
    parser = RobotFileParser()
    parser.parse(text.splitlines())
    return parser


def robots_allows(
    parser: RobotFileParser | None,
    user_agent: str,
    url: str,
) -> bool:
    if parser is None:
        return True
    try:
        return parser.can_fetch(user_agent, url)
    except Exception:
        return True


@dataclass
class CrawlSettings:
    depth: int = 3
    max_urls: int = 200
    workers: int = 8
    timeout: float = 10.0
    follow_redirects: bool = True
    respect_robots: bool = True
    user_agent: str = "sqliscan/2.0"


@dataclass(frozen=True)
class _Fetched:
    """A page as fetched, before link resolution."""

    url: str
    status: int
    content_type: str
    base_href: str | None
    raw_links: tuple[str, ...]
    forms: tuple[Form, ...]


def crawl(
    seed: str,
    *,
    transport: Transport,
    scope: Scope,
    deny: DenyList,
    limiter: RateLimiter | None = None,
    budget: RequestBudget | None = None,
    settings: CrawlSettings | None = None,
) -> CrawlOutcome:
    """Breadth-first crawl from ``seed``, bounded by depth, pages and budget.

    Depth is carried on the frontier as ``(url, depth)``. A page at depth
    ``d < settings.depth`` contributes its links at ``d + 1``; nothing deeper
    is enqueued, so the frontier cannot grow without the page ceiling applying.
    """
    cfg = settings or CrawlSettings()
    robots: RobotFileParser | None = None
    if cfg.respect_robots:
        robots = _fetch_robots(seed, transport, limiter, budget, cfg)

    pages: list[Page] = []
    seen: set[str] = {seed}
    level: list[tuple[str, int]] = [(seed, 0)]
    fetched = failed = discovered = forms_found = 0
    disallowed = 0
    seed_url = seed
    # Distinct parameter *names*, not occurrences: the same `id` on fifty pages
    # is one thing to test, and the report should say one. The seed's own query
    # string is included, since those are the first points the scanner tests.
    parameter_names: set[str] = {
        name for name, _ in parse_qsl(urlsplit(seed).query, keep_blank_values=True)
    }

    while level and fetched < cfg.max_urls:
        batch = level[: cfg.max_urls - fetched]
        level = []

        with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as pool:
            futures = {
                pool.submit(_fetch_page, url, transport, limiter, budget, cfg): (
                    url,
                    depth,
                )
                for url, depth in batch
            }
            for future in as_completed(futures):
                requested, depth = futures[future]
                try:
                    fetched_page = future.result()
                except BudgetExceeded:
                    raise
                except TransportError:
                    failed += 1
                    continue

                if requested == seed_url and fetched_page.url != requested:
                    seed_url = fetched_page.url

                links = resolve_links(
                    fetched_page.raw_links,
                    fetched_page.url,
                    fetched_page.base_href,
                    scope=scope,
                    deny=deny,
                )
                page = Page(
                    url=fetched_page.url,
                    status=fetched_page.status,
                    content_type=fetched_page.content_type,
                    links=tuple(links),
                    forms=fetched_page.forms,
                )
                fetched += 1
                pages.append(page)
                discovered += len(links)
                forms_found += len(page.forms)
                parameter_names.update(
                    name
                    for name, _ in parse_qsl(
                        urlsplit(page.url).query, keep_blank_values=True
                    )
                )
                for form in page.forms:
                    parameter_names.update(name for name, _ in form.fields)

                if fetched >= cfg.max_urls:
                    break

                if depth >= cfg.depth:
                    continue
                for link in links:
                    if link in seen:
                        continue
                    if not robots_allows(robots, cfg.user_agent, link):
                        disallowed += 1
                        continue
                    seen.add(link)
                    level.append((link, depth + 1))

    # ``seen`` holds every URL the crawl admitted. Anything admitted but never
    # fetched was cut by the page ceiling, which is the only honest meaning of
    # "truncated" — a crawl that ended because the site ran out is complete.
    truncated = fetched < len(seen)

    stats = CrawlStats(
        pages_fetched=fetched,
        pages_failed=failed,
        urls_discovered=discovered,
        forms_discovered=forms_found,
        parameters_found=len(parameter_names),
        robots_disallowed=disallowed,
        truncated=truncated,
    )
    return CrawlOutcome(seed=seed_url, pages=tuple(pages), stats=stats)


def _fetch_robots(
    seed: str,
    transport: Transport,
    limiter: RateLimiter | None,
    budget: RequestBudget | None,
    cfg: CrawlSettings,
) -> RobotFileParser | None:
    parts = urlsplit(seed)
    robots_url = urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))
    try:
        response = send(
            transport,
            Request("GET", robots_url),
            timeout=cfg.timeout,
            follow_redirects=True,
            limiter=limiter,
            budget=budget,
        )
    except (TransportError, BudgetExceeded):
        return None
    if response.status != 200:
        return None
    return load_robots(response.text)


def _fetch_page(
    url: str,
    transport: Transport,
    limiter: RateLimiter | None,
    budget: RequestBudget | None,
    cfg: CrawlSettings,
) -> _Fetched:
    response: Response = send(
        transport,
        Request("GET", url),
        timeout=cfg.timeout,
        follow_redirects=cfg.follow_redirects,
        limiter=limiter,
        budget=budget,
    )
    if response.status >= 400 or "html" not in response.content_type.lower():
        return _Fetched(
            url=response.url,
            status=response.status,
            content_type=response.content_type,
            base_href=None,
            raw_links=(),
            forms=(),
        )

    base_href, raw_links, forms = parse_page(response.text)
    return _Fetched(
        url=response.url,
        status=response.status,
        content_type=response.content_type,
        base_href=base_href,
        raw_links=raw_links,
        forms=forms,
    )
