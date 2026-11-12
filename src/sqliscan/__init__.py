"""sqliscan — SQL injection scanner with baseline differencing.

The public surface is small on purpose. Everything the CLI does is available
as a library call, and every type it returns is a frozen dataclass with a
``to_dict`` method that defines the report schema.

    from sqliscan import DetectSettings, Detector, ScanConfig, Scanner

    report = Scanner(ScanConfig(target="https://example.com/a?id=1")).run()
    for finding in report.findings:
        print(finding.confidence.value, finding.point.parameter)
"""

from __future__ import annotations

from ._version import __version__
from .crawl import (
    DenyList,
    Form,
    Page,
    Scope,
    TargetError,
    canonicalise,
    parse_target,
)
from .detect import Detector, DetectSettings, scan_points
from .models import (
    Confidence,
    Context,
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
from .report import FORMATS, render, write_report
from .scanner import ScanConfig, ScanError, Scanner, collect_points, threshold_reached

__all__ = [
    "FORMATS",
    "Confidence",
    "Context",
    "CrawlStats",
    "DenyList",
    "DetectSettings",
    "Detector",
    "Evidence",
    "Finding",
    "Form",
    "InjectionPoint",
    "Location",
    "Method",
    "Page",
    "ScanConfig",
    "ScanError",
    "ScanMeta",
    "ScanReport",
    "Scanner",
    "Scope",
    "TargetError",
    "__version__",
    "canonicalise",
    "collect_points",
    "iso",
    "parse_target",
    "render",
    "scan_points",
    "threshold_reached",
    "utcnow",
    "write_report",
]
