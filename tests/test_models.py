"""Value types: timestamps, ordering, and the on-wire dict shapes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sqliscan.models import (
    Confidence,
    CrawlStats,
    Evidence,
    Finding,
    InjectionPoint,
    Location,
    Method,
    ScanMeta,
    ScanReport,
    iso,
    utcnow,
)


def test_iso_of_none_is_none() -> None:
    assert iso(None) is None


def test_iso_is_utc_z_with_milliseconds() -> None:
    moment = datetime(2026, 11, 11, 9, 14, 2, 881000, tzinfo=timezone.utc)
    assert iso(moment) == "2026-11-11T09:14:02.881Z"


def test_iso_converts_offsets_to_utc() -> None:
    plus_two = timezone(timedelta(hours=2))
    moment = datetime(2026, 11, 11, 11, 14, 2, tzinfo=plus_two)
    assert iso(moment) == "2026-11-11T09:14:02.000Z"


def test_utcnow_is_aware() -> None:
    assert utcnow().tzinfo is timezone.utc


def test_confidence_ranks_are_ordered() -> None:
    assert Confidence.SUSPECTED.rank < Confidence.LIKELY.rank
    assert Confidence.LIKELY.rank < Confidence.CONFIRMED.rank


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("confirmed", Confidence.CONFIRMED),
        ("  LIKELY ", Confidence.LIKELY),
        ("Suspected", Confidence.SUSPECTED),
    ],
)
def test_confidence_parse_accepts_case_and_padding(
    text: str, expected: Confidence
) -> None:
    assert Confidence.parse(text) is expected


def test_confidence_parse_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown confidence"):
        Confidence.parse("definitely")


def test_injection_point_label_names_method_location_and_parameter() -> None:
    point = InjectionPoint(
        method=Method.GET,
        url="https://example.com/a?id=1",
        location=Location.QUERY,
        parameter="id",
        value="1",
    )
    assert point.label == "GET https://example.com/a?id=1 [query] id"


def test_injection_point_dict_omits_empty_fields() -> None:
    point = InjectionPoint(
        method=Method.GET,
        url="https://example.com/",
        location=Location.QUERY,
        parameter="q",
        value="x",
    )
    assert "fields" not in point.to_dict()


def test_injection_point_dict_includes_form_fields() -> None:
    point = InjectionPoint(
        method=Method.POST,
        url="https://example.com/login",
        location=Location.FORM,
        parameter="user",
        value="bob",
        fields=(("user", "bob"), ("pass", "hunter2")),
    )
    payload = point.to_dict()
    assert payload["fields"] == [["user", "bob"], ["pass", "hunter2"]]
    assert payload["method"] == "POST"


def test_evidence_dict_rounds_elapsed() -> None:
    evidence = Evidence(
        request_line="GET / HTTP/1.1",
        payload="'",
        status=500,
        length=12,
        content_type="text/html",
        elapsed_ms=12.3456789,
        matched=("a",),
        excerpt="x",
    )
    payload = evidence.to_dict()
    assert payload["elapsed_ms"] == 12.346
    assert payload["matched"] == ["a"]


def test_finding_dict_embeds_point_and_evidence() -> None:
    point = InjectionPoint(
        method=Method.GET,
        url="https://example.com/",
        location=Location.QUERY,
        parameter="id",
        value="1",
    )
    evidence = Evidence(
        request_line="GET /?id=1' HTTP/1.1",
        payload="'",
        status=500,
        length=1,
        content_type="text/html",
        elapsed_ms=1.0,
    )
    finding = Finding(
        point=point,
        kind="error",
        confidence=Confidence.CONFIRMED,
        dbms="MySQL",
        payload="'",
        rationale="because",
        evidence=(evidence,),
    )
    payload = finding.to_dict()
    assert payload["confidence"] == "confirmed"
    assert payload["point"]["parameter"] == "id"
    assert payload["evidence"][0]["status"] == 500
    assert "CONFIRMED" in finding.label


def test_report_highest_is_none_without_findings(empty_report: ScanReport) -> None:
    assert empty_report.highest is None


def test_report_highest_picks_confirmed(sample_report: ScanReport) -> None:
    assert sample_report.highest is Confidence.CONFIRMED


def test_report_sorted_findings_puts_confirmed_first() -> None:
    low = Finding(
        point=InjectionPoint(Method.GET, "https://a/", Location.QUERY, "z", "1"),
        kind="boolean",
        confidence=Confidence.SUSPECTED,
        dbms="unknown",
        payload="'",
        rationale="r",
    )
    high = Finding(
        point=InjectionPoint(Method.GET, "https://b/", Location.QUERY, "a", "1"),
        kind="error",
        confidence=Confidence.CONFIRMED,
        dbms="MySQL",
        payload="'",
        rationale="r",
    )
    report = ScanReport(
        meta=ScanMeta(target="https://a/", started_at=utcnow()),
        findings=(low, high),
    )
    assert [item.confidence for item in report.sorted_findings()] == [
        Confidence.CONFIRMED,
        Confidence.SUSPECTED,
    ]


def test_report_dict_counts_each_confidence() -> None:
    def make(confidence: Confidence) -> Finding:
        return Finding(
            point=InjectionPoint(Method.GET, "https://a/", Location.QUERY, "id", "1"),
            kind="error",
            confidence=confidence,
            dbms="MySQL",
            payload="'",
            rationale="r",
        )

    report = ScanReport(
        meta=ScanMeta(target="https://a/", started_at=utcnow()),
        findings=(
            make(Confidence.CONFIRMED),
            make(Confidence.LIKELY),
            make(Confidence.SUSPECTED),
            make(Confidence.SUSPECTED),
        ),
    )
    summary = report.to_dict()["summary"]
    assert summary == {
        "findings": 4,
        "confirmed": 1,
        "likely": 1,
        "suspected": 2,
        "points_tested": 0,
    }


def test_crawl_stats_dict() -> None:
    stats = CrawlStats(pages_fetched=3, truncated=True)
    assert stats.to_dict()["truncated"] is True
    assert stats.to_dict()["pages_fetched"] == 3


def test_scan_meta_dict_uses_iso() -> None:
    meta = ScanMeta(
        target="https://example.com/",
        started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 2, 3, 4, 6, tzinfo=timezone.utc),
        tool_version="2.0.0",
    )
    payload = meta.to_dict()
    assert payload["started_at"] == "2026-01-02T03:04:05.000Z"
    assert payload["finished_at"] == "2026-01-02T03:04:06.000Z"
    assert payload["tool"] == "sqliscan"
