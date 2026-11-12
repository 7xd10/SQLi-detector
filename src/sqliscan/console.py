"""Terminal rendering: a width-aware, colourable report.

Colour is opt-out and off by default when stdout is not a TTY, so piping a scan
into a file or a pager does not fill it with escape sequences.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from typing import Callable

from .models import Confidence, ScanReport, iso


@dataclass(frozen=True)
class Style:
    """ANSI styling that can be switched off wholesale."""

    enabled: bool = False

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


COLOURS = {
    Confidence.CONFIRMED: "red",
    Confidence.LIKELY: "yellow",
    Confidence.SUSPECTED: "cyan",
}


def terminal_width(default: int = 100) -> int:
    try:
        return max(60, shutil.get_terminal_size((default, 24)).columns)
    except OSError:  # pragma: no cover - defensive
        return default


def colour_for(style: Style, confidence: Confidence) -> Callable[[str], str]:
    return {
        Confidence.CONFIRMED: style.red,
        Confidence.LIKELY: style.yellow,
        Confidence.SUSPECTED: style.cyan,
    }[confidence]


def _plural(count: int, noun: str) -> str:
    return noun if count == 1 else noun + "s"


def render_report(
    report: ScanReport,
    *,
    style: Style | None = None,
    width: int | None = None,
) -> str:
    s = style or Style(enabled=False)
    columns = width or terminal_width(default=100)
    lines: list[str] = []

    meta = report.meta
    lines.append(s.bold("sqliscan"))
    lines.append(f"target   {meta.target}")
    lines.append(
        f"started  {iso(meta.started_at)}"
        if meta.started_at is not None
        else "started  unknown"
    )
    if meta.finished_at is not None:
        lines.append(f"finished {iso(meta.finished_at)}")
    stats = report.stats
    pages = f"{stats.pages_fetched} {_plural(stats.pages_fetched, 'page')} fetched"
    forms = f"{stats.forms_discovered} {_plural(stats.forms_discovered, 'form')}"
    lines.append(
        f"pages    {pages}, {stats.pages_failed} failed, {forms}"
        + ("  (truncated)" if stats.truncated else "")
    )
    lines.append(
        f"points   {len(report.points)} injection "
        f"{_plural(len(report.points), 'point')} tested"
    )
    lines.append("")

    findings = report.sorted_findings()
    if not findings:
        lines.append(s.green("no injection confirmed, likely or suspected"))
        lines.append("")
        lines.append(_summary(report, s))
        return "\n".join(lines)

    lines.append(s.bold("findings"))
    for index, finding in enumerate(findings, start=1):
        severity = colour_for(s, finding.confidence)(finding.confidence.value.upper())
        lines.append(
            f"{index:>2}. {severity:<22} {finding.dbms:<11} "
            f"{finding.point.parameter} @ {finding.point.url}"
        )
        lines.append(
            f"    {s.dim('kind')} {finding.kind}  "
            f"{s.dim('payload')} {finding.payload!r}"
        )
        lines.append(f"    {s.dim('why')} {finding.rationale}")
        for evidence in finding.evidence:
            excerpt = evidence.excerpt[: max(20, columns - 20)]
            lines.append(
                f"    {s.dim('>')} {evidence.request_line} -> "
                f"{evidence.status} {evidence.length}B "
                f"{evidence.elapsed_ms:.0f}ms"
            )
            if excerpt:
                lines.append(f"      {s.dim(excerpt)}")
        lines.append("")

    lines.append(_summary(report, s))
    return "\n".join(lines)


def _summary(report: ScanReport, style: Style) -> str:
    counts = {"confirmed": 0, "likely": 0, "suspected": 0}
    for finding in report.findings:
        counts[finding.confidence.value] += 1
    return (
        f"{style.bold('summary')}  "
        f"{counts['confirmed']} confirmed | "
        f"{counts['likely']} likely | "
        f"{counts['suspected']} suspected"
    )


def supports_colour(stream: object = None) -> bool:
    target = stream if stream is not None else sys.stdout
    return bool(getattr(target, "isatty", lambda: False)())
