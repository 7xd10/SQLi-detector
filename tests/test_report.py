"""Serialisation: each format, the CSV shape and the atomic writer."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from helpers import finding
from sqliscan.models import Confidence, ScanMeta, ScanReport, utcnow
from sqliscan.report import (
    CSV_COLUMNS,
    render,
    render_csv,
    render_json,
    render_markdown,
    render_ndjson,
    rows,
    summarise,
    write_report,
    write_text,
)

# -- json -------------------------------------------------------------------


def test_json_round_trips(sample_report: ScanReport) -> None:
    payload = json.loads(render_json(sample_report))
    assert payload["meta"]["target"] == "https://example.com/"
    assert payload["summary"]["findings"] == 1
    assert payload["findings"][0]["confidence"] == "confirmed"
    assert payload["points"][0]["parameter"] == "id"


def test_json_ends_with_a_newline(sample_report: ScanReport) -> None:
    assert render_json(sample_report).endswith("\n")


def test_json_is_stable_across_runs(sample_report: ScanReport) -> None:
    assert render_json(sample_report) == render_json(sample_report)


# -- ndjson -----------------------------------------------------------------


def test_ndjson_emits_meta_findings_and_a_summary(sample_report: ScanReport) -> None:
    lines = render_ndjson(sample_report).strip().split("\n")
    kinds = [next(iter(json.loads(line))) for line in lines]
    assert kinds == ["meta", "finding", "summary"]


def test_ndjson_lines_are_independently_parseable(empty_report: ScanReport) -> None:
    lines = render_ndjson(empty_report).strip().split("\n")
    assert all(json.loads(line) for line in lines)
    assert len(lines) == 2  # meta and summary, no findings


def test_ndjson_summary_counts_the_scan(sample_report: ScanReport) -> None:
    summary = json.loads(render_ndjson(sample_report).strip().split("\n")[-1])[
        "summary"
    ]
    assert summary["findings"] == 1
    assert summary["points_tested"] == 1
    assert summary["stats"]["pages_fetched"] == 2


# -- csv --------------------------------------------------------------------


def test_csv_header_matches_the_declared_columns(sample_report: ScanReport) -> None:
    reader = csv.DictReader(io.StringIO(render_csv(sample_report)))
    assert tuple(reader.fieldnames or ()) == CSV_COLUMNS


def test_csv_row_carries_the_point_and_the_evidence(sample_report: ScanReport) -> None:
    reader = csv.DictReader(io.StringIO(render_csv(sample_report)))
    row = next(iter(reader))
    assert row["confidence"] == "confirmed"
    assert row["method"] == "GET"
    assert row["parameter"] == "id"
    assert row["status"] == "500"
    assert row["length"] == "1234"


def test_csv_without_findings_is_header_only(empty_report: ScanReport) -> None:
    assert render_csv(empty_report).strip() == ",".join(CSV_COLUMNS)


def test_csv_quotes_a_payload_containing_a_comma() -> None:
    report = ScanReport(
        meta=ScanMeta(target="https://example.com/", started_at=utcnow()),
        findings=(finding(payload="' OR 1=1,2--"),),
    )
    row = next(iter(csv.DictReader(io.StringIO(render_csv(report)))))
    assert row["payload"] == "' OR 1=1,2--"


def test_rows_helper_projects_any_finding_sequence() -> None:
    projected = rows([finding()])
    assert projected[0]["dbms"] == "MySQL"
    assert set(projected[0]) == set(CSV_COLUMNS)


def test_row_without_evidence_leaves_observables_blank() -> None:
    item = finding()
    stripped = item.__class__(
        point=item.point,
        kind=item.kind,
        confidence=item.confidence,
        dbms=item.dbms,
        payload=item.payload,
        rationale=item.rationale,
    )
    projected = rows([stripped])[0]
    assert projected["status"] == ""
    assert projected["length"] == ""
    assert projected["excerpt"] == ""


# -- markdown ---------------------------------------------------------------


def test_markdown_names_the_target_and_the_summary(sample_report: ScanReport) -> None:
    text = render_markdown(sample_report)
    assert "# SQL injection scan report" in text
    assert "https://example.com/" in text
    assert "| Findings | 1 |" in text


def test_markdown_lists_the_finding_and_its_evidence(sample_report: ScanReport) -> None:
    text = render_markdown(sample_report)
    assert "## Findings" in text
    assert "### 1. id on https://example.com/" in text
    assert "GET /item?id=1' HTTP/1.1" in text


def test_markdown_says_so_when_nothing_was_found(empty_report: ScanReport) -> None:
    text = render_markdown(empty_report)
    assert "No injection was confirmed" in text
    assert "## Findings" not in text


def test_markdown_escapes_pipes_in_an_excerpt() -> None:
    item = finding()
    evidence = item.evidence[0].__class__(
        request_line="GET / HTTP/1.1",
        payload="'",
        status=500,
        length=1,
        content_type="text/html",
        elapsed_ms=1.0,
        excerpt="a | b",
    )
    report = ScanReport(
        meta=ScanMeta(target="https://example.com/", started_at=utcnow()),
        findings=(
            item.__class__(
                point=item.point,
                kind=item.kind,
                confidence=item.confidence,
                dbms=item.dbms,
                payload=item.payload,
                rationale=item.rationale,
                evidence=(evidence,),
            ),
        ),
    )
    assert r"a \| b" in render_markdown(report)


# -- dispatch ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fmt", "marker"),
    [
        ("json", '"meta"'),
        ("ndjson", '"summary"'),
        ("csv", "confidence,kind,dbms"),
        ("md", "# SQL injection scan report"),
    ],
)
def test_render_dispatches_each_format(
    sample_report: ScanReport, fmt: str, marker: str
) -> None:
    assert marker in render(sample_report, fmt)


def test_render_rejects_an_unknown_format(sample_report: ScanReport) -> None:
    with pytest.raises(ValueError, match="unsupported format"):
        render(sample_report, "yaml")


# -- writing ----------------------------------------------------------------


def test_write_text_creates_missing_directories(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "report.json"
    write_text("{}", str(destination))
    assert destination.read_text(encoding="utf-8") == "{}"


def test_write_text_replaces_an_existing_file(tmp_path: Path) -> None:
    destination = tmp_path / "report.txt"
    destination.write_text("old", encoding="utf-8")
    write_text("new", str(destination))
    assert destination.read_text(encoding="utf-8") == "new"


def test_write_text_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    write_text("hello\n", "-")
    assert capsys.readouterr().out == "hello\n"


def test_write_text_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    write_text("{}", str(destination))
    assert sorted(path.name for path in tmp_path.iterdir()) == ["report.json"]


def test_write_text_cleans_up_when_the_replace_fails(tmp_path: Path) -> None:
    blocked = tmp_path / "report.json"
    blocked.mkdir()

    with pytest.raises(OSError):
        write_text("{}", str(blocked))

    leftovers = [path.name for path in tmp_path.iterdir() if path.name != "report.json"]
    assert leftovers == []


# -- counts -----------------------------------------------------------------


def test_summarise_counts_each_confidence(sample_report: ScanReport) -> None:
    counts = summarise(sample_report)
    assert counts == {
        "confirmed": 1,
        "likely": 0,
        "suspected": 0,
        "total": 1,
        "points": 1,
    }


def test_summarise_of_an_empty_report(empty_report: ScanReport) -> None:
    assert summarise(empty_report)["total"] == 0


def test_suspected_report_is_counted_apart(suspected_report: ScanReport) -> None:
    assert summarise(suspected_report)["suspected"] == 1
    assert suspected_report.highest is Confidence.SUSPECTED


def test_write_report_dispatches_on_the_format(
    sample_report: ScanReport, tmp_path: Path
) -> None:
    destination = tmp_path / "scan.csv"
    write_report(sample_report, str(destination), "csv")
    assert destination.read_text(encoding="utf-8").startswith("confidence,kind,dbms")


def test_write_report_rejects_an_unknown_format(
    sample_report: ScanReport, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="unsupported format"):
        write_report(sample_report, str(tmp_path / "x.txt"), "yaml")
