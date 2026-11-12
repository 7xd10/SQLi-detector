"""Value types shared by the crawler, the detector and the reporters.

Every type in this module is frozen. The ``to_dict`` methods define the
on-wire shape for each output format, so renaming a key is a breaking change.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    """A timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def iso(moment: datetime | None) -> str | None:
    """Render a timestamp identically in JSON, Markdown and the console.

    Two reports of the same scan must diff cleanly, so there is exactly one
    timestamp format in the package: UTC, millisecond precision, ``Z`` suffix.
    """
    if moment is None:
        return None
    return (
        moment.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class Method(str, Enum):
    """HTTP methods the scanner will issue."""

    GET = "GET"
    POST = "POST"


class Location(str, Enum):
    """Where a parameter lives in the request."""

    QUERY = "query"
    FORM = "form"


class Context(str, Enum):
    """The syntactic context a value sits in, inferred from the value itself."""

    NUMERIC = "numeric"
    STRING = "string"


class Confidence(str, Enum):
    """How strongly the evidence supports the finding.

    ``CONFIRMED`` requires the error signature to be absent from the baseline,
    absent from a same-shape escaped control, and reproducible on a repeat
    request. Anything less is downgraded rather than discarded.
    """

    SUSPECTED = "suspected"
    LIKELY = "likely"
    CONFIRMED = "confirmed"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    @classmethod
    def parse(cls, value: str) -> Confidence:
        key = value.strip().lower()
        for member in cls:
            if member.value == key:
                return member
        allowed = ", ".join(member.value for member in cls)
        raise ValueError(f"unknown confidence {value!r}; expected one of {allowed}")


_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.SUSPECTED: 1,
    Confidence.LIKELY: 2,
    Confidence.CONFIRMED: 3,
}


@dataclass(frozen=True)
class InjectionPoint:
    """One parameter of one request, and the value it carried when observed."""

    method: Method
    url: str
    location: Location
    parameter: str
    value: str
    fields: tuple[tuple[str, str], ...] = ()

    @property
    def label(self) -> str:
        return (
            f"{self.method.value} {self.url} [{self.location.value}] {self.parameter}"
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "method": self.method.value,
            "url": self.url,
            "location": self.location.value,
            "parameter": self.parameter,
            "value": self.value,
        }
        if self.fields:
            payload["fields"] = [[name, value] for name, value in self.fields]
        return payload


@dataclass(frozen=True)
class Evidence:
    """One request/response pair, reduced to what a reviewer needs to re-run it."""

    request_line: str
    payload: str
    status: int
    length: int
    content_type: str
    elapsed_ms: float
    matched: tuple[str, ...] = ()
    excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request_line,
            "payload": self.payload,
            "status": self.status,
            "length": self.length,
            "content_type": self.content_type,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "matched": list(self.matched),
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True)
class Finding:
    """A candidate injection, with the evidence that produced it."""

    point: InjectionPoint
    kind: str
    confidence: Confidence
    dbms: str
    payload: str
    rationale: str
    evidence: tuple[Evidence, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.confidence.value.upper()} {self.point.label}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence.value,
            "kind": self.kind,
            "dbms": self.dbms,
            "payload": self.payload,
            "rationale": self.rationale,
            "point": self.point.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class CrawlStats:
    """What the crawler observed. Counts, not claims."""

    pages_fetched: int = 0
    pages_failed: int = 0
    urls_discovered: int = 0
    forms_discovered: int = 0
    parameters_found: int = 0
    robots_disallowed: int = 0
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "pages_fetched": self.pages_fetched,
            "pages_failed": self.pages_failed,
            "urls_discovered": self.urls_discovered,
            "forms_discovered": self.forms_discovered,
            "parameters_found": self.parameters_found,
            "robots_disallowed": self.robots_disallowed,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class ScanMeta:
    """Provenance for a report: what was run, against what, with which knobs."""

    target: str
    started_at: datetime
    finished_at: datetime | None = None
    tool_version: str = ""
    options: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "tool": "sqliscan",
            "version": self.tool_version,
            "started_at": iso(self.started_at),
            "finished_at": iso(self.finished_at),
            "options": dict(self.options),
        }


@dataclass(frozen=True)
class ScanReport:
    """Everything one run produced."""

    meta: ScanMeta
    stats: CrawlStats = field(default_factory=CrawlStats)
    points: tuple[InjectionPoint, ...] = ()
    findings: tuple[Finding, ...] = ()

    @property
    def highest(self) -> Confidence | None:
        if not self.findings:
            return None
        return max((item.confidence for item in self.findings), key=lambda c: c.rank)

    def sorted_findings(self) -> list[Finding]:
        """Confirmed first, then by URL, so two runs of one scan list equally."""

        return sorted(
            self.findings,
            key=lambda f: (-f.confidence.rank, f.point.url, f.point.parameter),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "stats": self.stats.to_dict(),
            "summary": {
                "findings": len(self.findings),
                "confirmed": sum(
                    1 for f in self.findings if f.confidence is Confidence.CONFIRMED
                ),
                "likely": sum(
                    1 for f in self.findings if f.confidence is Confidence.LIKELY
                ),
                "suspected": sum(
                    1 for f in self.findings if f.confidence is Confidence.SUSPECTED
                ),
                "points_tested": len(self.points),
            },
            "findings": [item.to_dict() for item in self.sorted_findings()],
            "points": [item.to_dict() for item in self.points],
        }
