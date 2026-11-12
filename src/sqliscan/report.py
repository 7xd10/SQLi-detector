"""Serialisation: json, ndjson, csv and Markdown, written atomically."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from .models import Finding, ScanReport, iso

FORMATS = ("console", "json", "ndjson", "csv", "md")


def render(report: ScanReport, fmt: str) -> str:
    """Render a report in one of the machine-readable formats."""
    if fmt == "json":
        return render_json(report)
    if fmt == "ndjson":
        return render_ndjson(report)
    if fmt == "csv":
        return render_csv(report)
    if fmt == "md":
        return render_markdown(report)
    raise ValueError(
        f"unsupported format {fmt!r}; expected one of json, ndjson, csv, md"
    )


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False) + "\n"


def render_ndjson(report: ScanReport) -> str:
    """One JSON object per line: meta, findings, summary.

    Streaming-friendly: a consumer can act on each finding as it is parsed
    without holding the whole document.
    """
    lines: list[str] = [json.dumps({"meta": report.meta.to_dict()}, sort_keys=True)]
    for finding in report.sorted_findings():
        lines.append(json.dumps({"finding": finding.to_dict()}, sort_keys=True))
    lines.append(
        json.dumps(
            {
                "summary": {
                    "findings": len(report.findings),
                    "points_tested": len(report.points),
                    "stats": report.stats.to_dict(),
                }
            },
            sort_keys=True,
        )
    )
    return "\n".join(lines) + "\n"


CSV_COLUMNS = (
    "confidence",
    "kind",
    "dbms",
    "method",
    "url",
    "location",
    "parameter",
    "payload",
    "status",
    "length",
    "excerpt",
)


def render_csv(report: ScanReport) -> str:
    """One row per finding. csv.writer handles quoting, not string joining."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for finding in report.sorted_findings():
        writer.writerow(_row(finding))
    return buffer.getvalue()


def _row(finding: Finding) -> dict[str, object]:
    evidence = finding.evidence[0] if finding.evidence else None
    return {
        "confidence": finding.confidence.value,
        "kind": finding.kind,
        "dbms": finding.dbms,
        "method": finding.point.method.value,
        "url": finding.point.url,
        "location": finding.point.location.value,
        "parameter": finding.point.parameter,
        "payload": finding.payload,
        "status": evidence.status if evidence else "",
        "length": evidence.length if evidence else "",
        "excerpt": evidence.excerpt if evidence else "",
    }


def render_markdown(report: ScanReport) -> str:
    meta = report.meta
    lines: list[str] = [
        "# SQL injection scan report",
        "",
        f"- **Target**: `{meta.target}`",
        f"- **Started**: {iso(meta.started_at)}",
        f"- **Finished**: {iso(meta.finished_at)}",
        f"- **Tool**: {meta.tool_version or 'sqliscan'}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Pages fetched | {report.stats.pages_fetched} |",
        f"| Pages failed | {report.stats.pages_failed} |",
        f"| Injection points | {len(report.points)} |",
        f"| Findings | {len(report.findings)} |",
        "",
    ]

    findings = report.sorted_findings()
    if not findings:
        lines.append("No injection was confirmed, likely or suspected.")
        lines.append("")
        return "\n".join(lines)

    lines.extend(
        [
            "## Findings",
            "",
            "| # | Confidence | DBMS | Point | Parameter | Payload |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"| {index} | {finding.confidence.value} | {finding.dbms} | "
            f"`{finding.point.method.value} {finding.point.url}` | "
            f"`{finding.point.parameter}` | `{finding.payload}` |"
        )
    lines.append("")

    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.point.parameter} on {finding.point.url}",
                "",
                f"- **Confidence**: {finding.confidence.value}",
                f"- **Kind**: {finding.kind}",
                f"- **DBMS**: {finding.dbms}",
                f"- **Why**: {finding.rationale}",
                "",
                "| Request | Payload | Status | Length | Excerpt |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for evidence in finding.evidence:
            excerpt = evidence.excerpt.replace("|", "\\|")[:120]
            lines.append(
                f"| `{evidence.request_line}` | `{evidence.payload}` | "
                f"{evidence.status} | {evidence.length} | {excerpt} |"
            )
        lines.append("")
    return "\n".join(lines)


def write_text(text: str, output: str) -> None:
    """Write text atomically: temp file in the destination directory, replace.

    An interrupted run leaves the previous report intact rather than a
    half-written file that parses as truncated JSON.
    """
    if output == "-":
        sys.stdout.write(text)
        return

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        dir=str(destination.parent),
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(destination)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()
        raise


def write_report(report: ScanReport, output: str, fmt: str) -> None:
    write_text(render(report, fmt), output)


def summarise(report: ScanReport) -> dict[str, int]:
    counts = {"confirmed": 0, "likely": 0, "suspected": 0}
    for finding in report.findings:
        counts[finding.confidence.value] += 1
    counts["total"] = len(report.findings)
    counts["points"] = len(report.points)
    return counts


def rows(findings: Sequence[Finding]) -> list[dict[str, object]]:
    """The CSV rows for an arbitrary finding sequence."""
    return [_row(finding) for finding in findings]
