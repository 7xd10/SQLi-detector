"""Terminal rendering: layout, colour gating and width handling."""

from __future__ import annotations

import io

import pytest

from helpers import point
from sqliscan.console import (
    COLOURS,
    Style,
    colour_for,
    render_report,
    supports_colour,
    terminal_width,
)
from sqliscan.models import Confidence, CrawlStats, ScanMeta, ScanReport, utcnow


def test_plain_style_has_no_escapes() -> None:
    style = Style(enabled=False)
    assert style.bold("x") == "x"
    assert style.red("x") == "x"


@pytest.mark.parametrize(
    ("method", "code"),
    [
        ("bold", "1"),
        ("dim", "2"),
        ("red", "31"),
        ("green", "32"),
        ("yellow", "33"),
        ("cyan", "36"),
    ],
)
def test_enabled_style_wraps_and_resets(method: str, code: str) -> None:
    style = Style(enabled=True)
    assert getattr(style, method)("x") == f"\x1b[{code}mx\x1b[0m"


@pytest.mark.parametrize(
    ("confidence", "method"),
    [
        (Confidence.CONFIRMED, "red"),
        (Confidence.LIKELY, "yellow"),
        (Confidence.SUSPECTED, "cyan"),
    ],
)
def test_each_confidence_has_its_own_colour(
    confidence: Confidence, method: str
) -> None:
    style = Style(enabled=True)
    assert colour_for(style, confidence)("x") == getattr(style, method)("x")
    assert COLOURS[confidence] == method


def test_terminal_width_has_a_floor() -> None:
    assert terminal_width(default=100) >= 60


def test_colour_support_follows_isatty() -> None:
    class Stream:
        def __init__(self, tty: bool) -> None:
            self._tty = tty

        def isatty(self) -> bool:
            return self._tty

    assert supports_colour(Stream(True)) is True
    assert supports_colour(Stream(False)) is False
    assert supports_colour(io.StringIO()) is False


def test_report_without_findings_says_so(empty_report: ScanReport) -> None:
    text = render_report(empty_report, style=Style(enabled=False))
    assert "no injection confirmed" in text
    assert "summary  0 confirmed | 0 likely | 0 suspected" in text
    assert "points   0 injection points tested" in text


def test_report_lists_a_finding_with_its_evidence(sample_report: ScanReport) -> None:
    text = render_report(sample_report, style=Style(enabled=False))
    assert "CONFIRMED" in text
    assert "MySQL" in text
    assert "id @ https://example.com/item?id=1" in text
    assert "GET /item?id=1' HTTP/1.1" in text
    assert "500 1234B 12ms" in text


def test_report_marks_a_truncated_crawl() -> None:
    report = ScanReport(
        meta=ScanMeta(target="https://example.com/", started_at=utcnow()),
        stats=CrawlStats(pages_fetched=1, truncated=True),
    )
    assert "(truncated)" in render_report(report)


def test_counts_are_pluralised() -> None:
    one = ScanReport(
        meta=ScanMeta(target="https://example.com/", started_at=utcnow()),
        stats=CrawlStats(pages_fetched=1, forms_discovered=1),
        points=(point(),),
    )
    text = render_report(one)
    assert "1 page fetched" in text
    assert "1 form" in text
    assert "1 injection point tested" in text

    many = ScanReport(
        meta=ScanMeta(target="https://example.com/", started_at=utcnow()),
        stats=CrawlStats(pages_fetched=3, forms_discovered=2),
        points=(point(), point()),
    )
    text = render_report(many)
    assert "3 pages fetched" in text
    assert "2 forms" in text
    assert "2 injection points tested" in text


def test_report_without_a_start_time_says_unknown() -> None:
    report = ScanReport(meta=ScanMeta(target="https://e/", started_at=None))  # type: ignore[arg-type]
    assert "started  unknown" in render_report(report)


def test_report_omits_the_finish_line_when_unset() -> None:
    report = ScanReport(meta=ScanMeta(target="https://e/", started_at=utcnow()))
    assert "finished" not in render_report(report)


def test_colour_is_emitted_only_when_enabled(sample_report: ScanReport) -> None:
    plain = render_report(sample_report, style=Style(enabled=False))
    coloured = render_report(sample_report, style=Style(enabled=True))
    assert "\x1b[" not in plain
    assert "\x1b[" in coloured


def test_excerpt_is_clipped_to_the_terminal_width(sample_report: ScanReport) -> None:
    narrow = render_report(sample_report, width=80)
    wide = render_report(sample_report, width=200)
    assert "You have an error" in narrow
    assert "You have an error" in wide


def test_report_of_a_suspected_finding(suspected_report: ScanReport) -> None:
    text = render_report(suspected_report, style=Style(enabled=False))
    assert "SUSPECTED" in text
    assert "unknown" in text
