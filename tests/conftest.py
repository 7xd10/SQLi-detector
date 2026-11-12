"""Fixtures shared by the whole suite.

No test in this suite opens a socket. The detector talks to ``Transport``, so
every test hands it a scripted implementation and asserts on the requests it
would have sent.
"""

from __future__ import annotations

import pytest

from helpers import ScriptedTransport, finding, point
from sqliscan.models import (
    Confidence,
    CrawlStats,
    ScanMeta,
    ScanReport,
    utcnow,
)


@pytest.fixture()
def transport() -> ScriptedTransport:
    return ScriptedTransport()


@pytest.fixture()
def sample_report() -> ScanReport:
    return ScanReport(
        meta=ScanMeta(
            target="https://example.com/",
            started_at=utcnow(),
            finished_at=utcnow(),
            tool_version="2.0.0",
            options={"depth": 1},
        ),
        stats=CrawlStats(pages_fetched=2, urls_discovered=3, forms_discovered=1),
        points=(point(),),
        findings=(finding(),),
    )


@pytest.fixture()
def empty_report() -> ScanReport:
    return ScanReport(
        meta=ScanMeta(
            target="https://example.com/",
            started_at=utcnow(),
            tool_version="2.0.0",
        ),
        stats=CrawlStats(pages_fetched=1),
    )


@pytest.fixture()
def suspected_report() -> ScanReport:
    return ScanReport(
        meta=ScanMeta(target="https://example.com/", started_at=utcnow()),
        points=(point(),),
        findings=(finding(confidence=Confidence.SUSPECTED, dbms="unknown"),),
    )
