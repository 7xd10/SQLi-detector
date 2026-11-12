"""Orchestration: crawl, collect injection points, test them, build a report."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urljoin

from ._version import __version__
from .crawl import (
    CrawlOutcome,
    CrawlSettings,
    DenyList,
    Scope,
    TargetError,
    canonicalise,
    crawl,
    parse_target,
)
from .detect import Detector, DetectSettings, scan_points
from .http import (
    BudgetExceeded,
    HttpxTransport,
    RateLimiter,
    RequestBudget,
    RetryingTransport,
    Transport,
)
from .models import (
    Confidence,
    CrawlStats,
    Finding,
    InjectionPoint,
    Location,
    Method,
    ScanMeta,
    ScanReport,
    utcnow,
)

LOGGER = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "sqliscan/2.0 (+https://github.com/7xd10/SQLi-detector)"


class ScanError(ValueError):
    """The scan cannot be set up as requested."""


@dataclass(frozen=True)
class ScanConfig:
    """Every knob a run needs. Frozen so a scan can be replayed from a report."""

    target: str
    depth: int = 3
    max_urls: int = 200
    max_requests: int = 2000
    rate_limit: float = 10.0
    workers: int = 8
    timeout: float = 10.0
    retries: int = 1
    verify_tls: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    proxy: str | None = None
    forms: bool = False
    max_forms: int = 50
    time_based: bool = False
    time_delay: int = 5
    respect_robots: bool = True
    allow_hosts: Sequence[str] = ()
    include_subdomains: bool = False
    exclude: Sequence[str] = ()

    def options(self) -> dict[str, object]:
        """The subset of settings that changes what a report means."""
        return {
            "depth": self.depth,
            "max_urls": self.max_urls,
            "max_requests": self.max_requests,
            "rate_limit": self.rate_limit,
            "forms": self.forms,
            "time_based": self.time_based,
            "time_delay": self.time_delay,
            "respect_robots": self.respect_robots,
            "include_subdomains": self.include_subdomains,
            "allow_hosts": list(self.allow_hosts),
            "exclude": list(self.exclude),
        }


def build_scope(config: ScanConfig) -> Scope:
    """The seed host plus anything explicitly allowed."""
    try:
        seed = parse_target(config.target)
    except TargetError as exc:
        raise ScanError(str(exc)) from exc
    scope = Scope.from_url(seed, include_subdomains=config.include_subdomains)
    if config.allow_hosts:
        scope = scope.extend(config.allow_hosts)
    return scope


def collect_points(
    outcome: CrawlOutcome,
    *,
    scope: Scope,
    forms: bool,
    max_forms: int,
) -> list[InjectionPoint]:
    """Every query parameter and form field the crawl found, de-duplicated."""
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(point: InjectionPoint) -> None:
        key = (
            point.method.value,
            point.url,
            point.location.value,
            point.parameter,
        )
        if key in seen:
            return
        seen.add(key)
        points.append(point)

    for page in outcome.pages:
        query = page.url.partition("?")[2]
        for name, value in parse_qsl(query, keep_blank_values=True):
            add(
                InjectionPoint(
                    method=Method.GET,
                    url=page.url,
                    location=Location.QUERY,
                    parameter=name,
                    value=value,
                )
            )

    if not forms:
        return points

    submitted = 0
    for page in outcome.pages:
        for form in page.forms:
            if submitted >= max_forms:
                return points
            if form.has_file or not form.fields:
                continue
            action = canonicalise(urljoin(page.url, form.action or page.url))
            if action is None or not scope.allows(action):
                continue
            submitted += 1
            if form.method is Method.GET:
                separator = "&" if "?" in action else "?"
                url = f"{action}{separator}{urlencode(form.fields)}"
                for name, value in form.fields:
                    add(
                        InjectionPoint(
                            method=Method.GET,
                            url=url,
                            location=Location.QUERY,
                            parameter=name,
                            value=value,
                        )
                    )
            else:
                for name, value in form.fields:
                    add(
                        InjectionPoint(
                            method=Method.POST,
                            url=action,
                            location=Location.FORM,
                            parameter=name,
                            value=value,
                            fields=form.fields,
                        )
                    )
    return points


class Scanner:
    """A single scan: one target, one transport, one report."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        transport: Transport | None = None,
        on_finding: Callable[[Finding], None] | None = None,
        on_progress: Callable[[str, int, int], None] | None = None,
    ) -> None:
        self.config = config
        self._owns_transport = transport is None
        self._transport: Transport = transport or _build_transport(config)
        self._on_finding = on_finding
        self._on_progress = on_progress
        self._budget = RequestBudget(config.max_requests)
        self._limiter = RateLimiter(config.rate_limit)

    def run(self) -> ScanReport:
        config = self.config
        seed = parse_target(config.target)
        scope = build_scope(config)
        deny = DenyList(extra=config.exclude)
        started = utcnow()
        stats = CrawlStats()
        findings: list[Finding] = []
        points: list[InjectionPoint] = []
        reported_seed = seed

        try:
            outcome = crawl(
                seed,
                transport=self._transport,
                scope=scope,
                deny=deny,
                limiter=self._limiter,
                budget=self._budget,
                settings=CrawlSettings(
                    depth=config.depth,
                    max_urls=config.max_urls,
                    workers=config.workers,
                    timeout=config.timeout,
                    respect_robots=config.respect_robots,
                    user_agent=config.user_agent,
                ),
            )
            reported_seed = outcome.seed
            stats = outcome.stats
            points = collect_points(
                outcome,
                scope=scope,
                forms=config.forms,
                max_forms=config.max_forms,
            )
            # What the report should say is what was actually tested. The crawl
            # counts every parameter name it saw, including form fields the
            # caller did not ask to submit.
            stats = replace(
                stats, parameters_found=len({point.parameter for point in points})
            )
            self._progress("points", 0, len(points))

            detector = Detector(
                self._transport,
                limiter=self._limiter,
                budget=self._budget,
                settings=DetectSettings(
                    timeout=config.timeout,
                    time_based=config.time_based,
                    time_delay=config.time_delay,
                ),
            )
            findings = scan_points(points, detector, on_finding=self._on_finding)
            self._progress("scan", len(findings), len(points))
        except BudgetExceeded:
            LOGGER.warning(
                "request budget of %d exhausted; this report covers a partial scan",
                config.max_requests,
            )
            stats = replace(stats, truncated=True)
        finally:
            if self._owns_transport:
                self._transport.close()

        return ScanReport(
            meta=ScanMeta(
                target=reported_seed,
                started_at=started,
                finished_at=utcnow(),
                tool_version=_version(),
                options=config.options(),
            ),
            stats=stats,
            points=tuple(points),
            findings=tuple(findings),
        )

    def _progress(self, phase: str, done: int, total: int) -> None:
        if self._on_progress is not None:
            self._on_progress(phase, done, total)


def _build_transport(config: ScanConfig) -> Transport:
    inner = HttpxTransport(
        user_agent=config.user_agent,
        verify=config.verify_tls,
        max_connections=max(4, config.workers),
        headers=dict(config.headers),
        cookies=dict(config.cookies),
        proxy=config.proxy,
    )
    return RetryingTransport(inner, retries=config.retries)


def _version() -> str:
    return __version__


def threshold_reached(findings: Sequence[Finding], threshold: Confidence) -> bool:
    """True when any finding is at or above ``threshold``."""
    return any(item.confidence.rank >= threshold.rank for item in findings)
