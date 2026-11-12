"""The command line: the exit-code contract, output routing and dry run."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, ClassVar

import pytest

from helpers import finding
from sqliscan import cli
from sqliscan.cli import (
    EXIT_INTERNAL,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_THRESHOLD,
    EXIT_USAGE,
    _configure_logging,
    _parse_cookie,
    _parse_headers,
    _Parser,
    _progress,
    _stream_finding,
    build_parser,
    main,
)
from sqliscan.models import Confidence, ScanReport
from sqliscan.scanner import ScanConfig, ScanError


class FakeScanner:
    """Stands in for the real scanner so no test opens a socket."""

    report: ScanReport | None = None
    error: BaseException | None = None
    seen: ClassVar[dict[str, Any]] = {}

    def __init__(
        self,
        config: ScanConfig,
        *,
        on_progress: object = None,
        on_finding: object = None,
    ) -> None:
        FakeScanner.seen = {
            "config": config,
            "on_progress": on_progress,
            "on_finding": on_finding,
        }

    def run(self) -> ScanReport | None:
        if FakeScanner.error is not None:
            raise FakeScanner.error
        return FakeScanner.report


@pytest.fixture(autouse=True)
def fake_scanner(monkeypatch: pytest.MonkeyPatch) -> type[FakeScanner]:
    FakeScanner.report = None
    FakeScanner.error = None
    FakeScanner.seen = {}
    monkeypatch.setattr("sqliscan.cli.Scanner", FakeScanner)
    return FakeScanner


# -- usage and help ---------------------------------------------------------


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["-h"]) == EXIT_OK
    assert "usage: sqliscan" in capsys.readouterr().out


def test_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == EXIT_OK
    assert capsys.readouterr().out.startswith("sqliscan ")


def test_missing_target_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == EXIT_USAGE
    assert "sqliscan:" in capsys.readouterr().err


def test_two_targets_are_rejected() -> None:
    assert main(["https://a.example/", "https://b.example/"]) == EXIT_USAGE


def test_unknown_flag_is_a_usage_error() -> None:
    assert main(["--nonsense", "https://a.example/"]) == EXIT_USAGE


@pytest.mark.parametrize(
    "argv",
    [
        ["--timeout", "0", "https://a.example/"],
        ["--max-urls", "0", "https://a.example/"],
        ["--max-requests", "-1", "https://a.example/"],
        ["--workers", "0", "https://a.example/"],
        ["--depth", "-1", "https://a.example/"],
        ["--retries", "-1", "https://a.example/"],
        ["--rate-limit", "-5", "https://a.example/"],
    ],
)
def test_out_of_range_numbers_are_usage_errors(argv: list[str]) -> None:
    assert main(argv) == EXIT_USAGE


def test_an_unusable_target_is_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["ftp://example.com/"]) == EXIT_USAGE
    assert "unsupported scheme" in capsys.readouterr().err


# -- header and cookie parsing ---------------------------------------------


def test_headers_are_split_on_the_first_colon() -> None:
    assert _parse_headers(["Authorization: Bearer a:b:c"]) == {
        "Authorization": "Bearer a:b:c"
    }


def test_headers_accumulate() -> None:
    assert _parse_headers(["A: 1", "B: 2 "]) == {"A": "1", "B": "2"}


@pytest.mark.parametrize("item", ["no-colon", ": value", "  : value"])
def test_malformed_header_is_rejected(item: str) -> None:
    with pytest.raises(cli.UsageError, match="malformed --header"):
        _parse_headers([item])


def test_cookies_are_split_on_semicolons() -> None:
    assert _parse_cookie("a=1; b=2=3") == {"a": "1", "b": "2=3"}


@pytest.mark.parametrize("value", ["novalue", "=x", "a=1; =2"])
def test_malformed_cookie_is_rejected(value: str) -> None:
    with pytest.raises(cli.UsageError, match="malformed --cookie"):
        _parse_cookie(value)


# -- dry run ----------------------------------------------------------------


def test_dry_run_prints_the_plan_and_stops(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--dry-run", "example.com", "--depth", "2"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "sqliscan plan" in out
    assert "seed            https://example.com/" in out
    assert "no request has been sent" in out


def test_dry_run_never_constructs_a_scanner() -> None:
    main(["--dry-run", "example.com"])
    assert FakeScanner.seen == {}


def test_dry_run_still_validates_the_target() -> None:
    assert main(["--dry-run", "ftp://example.com/"]) == EXIT_USAGE


# -- a scan that ran --------------------------------------------------------


def test_a_clean_run_exits_zero(
    sample_report: ScanReport, capsys: pytest.CaptureFixture[str]
) -> None:
    FakeScanner.report = sample_report
    assert main(["example.com"]) == EXIT_OK
    assert "sqliscan" in capsys.readouterr().out


def test_report_is_written_to_the_named_file(
    sample_report: ScanReport, tmp_path: Path
) -> None:
    FakeScanner.report = sample_report
    destination = tmp_path / "scan.json"

    assert main(["example.com", "-f", "json", "-o", str(destination)]) == EXIT_OK

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["meta"]["target"] == "https://example.com/"


def test_dash_output_goes_to_stdout_and_suppresses_the_console(
    sample_report: ScanReport, capsys: pytest.CaptureFixture[str]
) -> None:
    FakeScanner.report = sample_report

    assert main(["example.com", "-f", "json", "-o", "-"]) == EXIT_OK

    out = capsys.readouterr().out
    assert json.loads(out)["summary"]["findings"] == 1


def test_quiet_suppresses_the_console(
    sample_report: ScanReport, capsys: pytest.CaptureFixture[str]
) -> None:
    FakeScanner.report = sample_report
    assert main(["example.com", "-q"]) == EXIT_OK
    assert capsys.readouterr().out == ""


def test_quiet_still_prints_a_machine_format_asked_for_by_name(
    sample_report: ScanReport, capsys: pytest.CaptureFixture[str]
) -> None:
    """-q silences the console report, not the format the caller requested."""
    FakeScanner.report = sample_report
    assert main(["example.com", "-q", "-f", "csv"]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("confidence,kind,dbms")
    assert out.endswith("\n")


def test_markdown_goes_to_stdout_without_an_output_path(
    sample_report: ScanReport, capsys: pytest.CaptureFixture[str]
) -> None:
    FakeScanner.report = sample_report
    assert main(["example.com", "-q", "-f", "md"]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("# SQL injection scan report")
    assert out.endswith("\n")


def test_console_output_can_also_be_written_to_a_file(
    sample_report: ScanReport, tmp_path: Path
) -> None:
    FakeScanner.report = sample_report
    destination = tmp_path / "scan.txt"
    assert main(["example.com", "-o", str(destination)]) == EXIT_OK
    assert "sqliscan" in destination.read_text(encoding="utf-8")


def test_verbose_wires_the_streaming_callbacks(sample_report: ScanReport) -> None:
    FakeScanner.report = sample_report
    main(["example.com", "-v"])
    assert FakeScanner.seen["on_progress"] is not None
    assert FakeScanner.seen["on_finding"] is not None


def test_default_run_has_no_callbacks(sample_report: ScanReport) -> None:
    FakeScanner.report = sample_report
    main(["example.com"])
    assert FakeScanner.seen["on_progress"] is None
    assert FakeScanner.seen["on_finding"] is None


# -- the threshold contract -------------------------------------------------


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ("confirmed", EXIT_THRESHOLD),
        ("likely", EXIT_THRESHOLD),
        ("suspected", EXIT_THRESHOLD),
        ("none", EXIT_OK),
    ],
)
def test_fail_on_finding_trips_the_threshold(
    sample_report: ScanReport, flag: str, expected: int
) -> None:
    FakeScanner.report = sample_report
    assert main(["example.com", "--fail-on-finding", flag]) == expected


def test_fail_on_confirmed_ignores_a_weaker_finding(
    suspected_report: ScanReport,
) -> None:
    FakeScanner.report = suspected_report
    assert main(["example.com", "--fail-on-finding", "confirmed"]) == EXIT_OK


def test_fail_on_finding_passes_when_nothing_was_found(
    empty_report: ScanReport,
) -> None:
    FakeScanner.report = empty_report
    assert main(["example.com", "--fail-on-finding", "suspected"]) == EXIT_OK


# -- failure mapping --------------------------------------------------------


def test_interrupt_exits_130(capsys: pytest.CaptureFixture[str]) -> None:
    FakeScanner.error = KeyboardInterrupt()
    assert main(["example.com"]) == EXIT_INTERRUPTED
    assert "interrupted" in capsys.readouterr().err


def test_scan_setup_error_is_a_usage_error() -> None:
    FakeScanner.error = ScanError("bad scope")
    assert main(["example.com"]) == EXIT_USAGE


def test_an_unexpected_error_is_an_internal_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    FakeScanner.error = RuntimeError("boom")
    assert main(["example.com"]) == EXIT_INTERNAL
    assert "internal error: RuntimeError: boom" in capsys.readouterr().err


def test_verbose_internal_error_prints_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    FakeScanner.error = RuntimeError("boom")
    assert main(["example.com", "-vv"]) == EXIT_INTERNAL
    assert "Traceback" in capsys.readouterr().err


def test_an_unwritable_report_path_is_a_usage_error(
    sample_report: ScanReport, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    FakeScanner.report = sample_report
    blocked = tmp_path / "dir"
    blocked.mkdir()

    assert main(["example.com", "-f", "json", "-o", str(blocked)]) == EXIT_USAGE
    assert "cannot write report" in capsys.readouterr().err


# -- config translation -----------------------------------------------------


def test_flags_reach_the_config(sample_report: ScanReport) -> None:
    FakeScanner.report = sample_report
    main(
        [
            "example.com/path?id=1",
            "--depth",
            "2",
            "--max-urls",
            "11",
            "--max-requests",
            "12",
            "--rate-limit",
            "0",
            "--workers",
            "3",
            "--timeout",
            "2.5",
            "--retries",
            "0",
            "--forms",
            "--max-forms",
            "4",
            "--time-based",
            "--time-delay",
            "9",
            "--no-robots",
            "--include-subdomains",
            "--allow-host",
            "api.example.com",
            "--exclude",
            "/admin",
            "--insecure",
            "--proxy",
            "http://127.0.0.1:8080",
            "--user-agent",
            "probe/1",
            "--header",
            "X-Test: 1",
            "--cookie",
            "sid=abc",
        ]
    )

    config = FakeScanner.seen["config"]
    assert config.target == "example.com/path?id=1"
    assert config.depth == 2
    assert config.max_urls == 11
    assert config.max_requests == 12
    assert config.rate_limit == 0
    assert config.workers == 3
    assert config.timeout == 2.5
    assert config.retries == 0
    assert config.forms is True
    assert config.max_forms == 4
    assert config.time_based is True
    assert config.time_delay == 9
    assert config.respect_robots is False
    assert config.include_subdomains is True
    assert tuple(config.allow_hosts) == ("api.example.com",)
    assert tuple(config.exclude) == ("/admin",)
    assert config.verify_tls is False
    assert config.proxy == "http://127.0.0.1:8080"
    assert config.user_agent == "probe/1"
    assert config.headers == {"X-Test": "1"}
    assert config.cookies == {"sid": "abc"}


def test_defaults_are_the_documented_ones(sample_report: ScanReport) -> None:
    FakeScanner.report = sample_report
    main(["example.com"])
    config = FakeScanner.seen["config"]
    assert config.depth == 3
    assert config.max_urls == 200
    assert config.max_requests == 2000
    assert config.rate_limit == 10.0
    assert config.verify_tls is True
    assert config.respect_robots is True
    assert config.forms is False
    assert config.time_based is False


def test_the_fake_report_fixture_is_confirmed(sample_report: ScanReport) -> None:
    assert sample_report.highest is Confidence.CONFIRMED


# -- parser internals -------------------------------------------------------


def test_parser_exit_with_a_message_writes_it_to_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """argparse hands ``exit`` a message in some code paths; it belongs on stderr."""
    with pytest.raises(cli._HelpRequested):
        _Parser(prog="sqliscan").exit(0, "usage: sqliscan ...\n")
    assert "usage: sqliscan" in capsys.readouterr().err


def test_parser_exit_without_a_message_is_silent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(cli._HelpRequested):
        _Parser(prog="sqliscan").exit(0, None)
    assert capsys.readouterr().err == ""


def test_parser_reports_an_unknown_flag_through_usage_error() -> None:
    with pytest.raises(cli.UsageError):
        build_parser().parse_args(["--nonsense", "example.com"])


# -- logging and streaming --------------------------------------------------


def test_log_file_is_opened_when_named(tmp_path: Path) -> None:
    destination = tmp_path / "scan.log"
    args = build_parser().parse_args(["example.com", "--log-file", str(destination)])

    _configure_logging(args)
    logging.getLogger("sqliscan.test").info("bench note")
    for handler in logging.getLogger().handlers:
        handler.flush()

    assert destination.exists()
    assert "bench note" in destination.read_text(encoding="utf-8")


def test_very_verbose_selects_debug() -> None:
    args = build_parser().parse_args(["example.com", "-vv"])
    _configure_logging(args)
    assert logging.getLogger().level == logging.DEBUG
    logging.getLogger().setLevel(logging.INFO)


def test_progress_rewrites_the_line_and_ends_it_on_the_last_item(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _progress("scan", 1, 2)
    _progress("scan", 2, 2)
    err = capsys.readouterr().err
    assert "\rsqliscan: scan 1/2" in err
    assert "\rsqliscan: scan 2/2\n" in err


def test_stream_finding_names_the_confidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stream_finding(finding())
    assert "CONFIRMED" in capsys.readouterr().err
