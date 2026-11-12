"""Command line interface and exit-code contract.

  0  the scan ran to completion
  1  --fail-on-finding was tripped
  2  usage or input error
  3  internal error
130  interrupted (Ctrl-C)
"""

from __future__ import annotations

import argparse
import logging
import sys
import traceback
from collections.abc import Sequence
from typing import NoReturn

from . import __version__
from .console import Style, render_report, supports_colour
from .crawl import TargetError, parse_target
from .models import Confidence, Finding
from .payloads import ERROR_PAYLOADS
from .report import FORMATS, render, write_text
from .scanner import (
    DEFAULT_USER_AGENT,
    ScanConfig,
    ScanError,
    Scanner,
    threshold_reached,
)

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3
EXIT_INTERRUPTED = 130

LOGGER = logging.getLogger("sqliscan")


class UsageError(ValueError):
    """Bad arguments. Always mapped to exit code 2."""


class _HelpRequested(Exception):
    """Raised by ``-h`` after argparse has printed help."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise UsageError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            sys.stderr.write(message)
        raise _HelpRequested()


EPILOG = """\
examples:
  sqliscan https://example.com/product.php?id=1
  sqliscan example.com --forms --depth 2 --max-urls 50
  sqliscan https://example.com -f json -o scan.json --fail-on-finding confirmed
  sqliscan https://example.com --rate-limit 5 --max-requests 500 -v
"""


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="sqliscan",
        description="SQL injection scanner with baseline differencing and "
        "dual-request confirmation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument(
        "target",
        metavar="TARGET",
        help="seed URL or host",
    )

    crawl = parser.add_argument_group("crawl")
    crawl.add_argument(
        "--depth",
        type=int,
        default=3,
        metavar="N",
        help="maximum link depth from the seed (default: 3)",
    )
    crawl.add_argument(
        "--max-urls",
        type=int,
        default=200,
        metavar="N",
        help="maximum pages fetched per target (default: 200)",
    )
    crawl.add_argument(
        "--forms", action="store_true", help="also submit same-origin HTML forms"
    )
    crawl.add_argument(
        "--max-forms",
        type=int,
        default=50,
        metavar="N",
        help="maximum forms submitted per target (default: 50)",
    )
    crawl.add_argument(
        "--no-robots", action="store_true", help="ignore robots.txt while crawling"
    )
    crawl.add_argument(
        "--include-subdomains",
        action="store_true",
        help="allow hosts under the seed host",
    )
    crawl.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="additional in-scope host; repeatable",
    )
    crawl.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="REGEX",
        help="path pattern never to request; repeatable",
    )

    network = parser.add_argument_group("network")
    network.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="S",
        help="per-request timeout in seconds (default: 10)",
    )
    network.add_argument(
        "--retries",
        type=int,
        default=1,
        metavar="N",
        help="retries for connection failures and 502/503/504 (default: 1)",
    )
    network.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="concurrent crawl fetches (default: 8)",
    )
    network.add_argument(
        "--rate-limit",
        type=float,
        default=10.0,
        metavar="N",
        help="requests per second across the whole scan; "
        "0 disables pacing (default: 10)",
    )
    network.add_argument(
        "--max-requests",
        type=int,
        default=2000,
        metavar="N",
        help="hard request ceiling per target (default: 2000)",
    )
    network.add_argument(
        "--insecure", action="store_true", help="do not verify TLS certificates"
    )
    network.add_argument(
        "--proxy", metavar="URL", help="route every request through this proxy"
    )
    network.add_argument(
        "--user-agent", metavar="STRING", help="override the default User-Agent"
    )
    network.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'K: V'",
        help="extra request header; repeatable",
    )
    network.add_argument(
        "--cookie", metavar="'a=1; b=2'", help="cookie header value for the whole scan"
    )

    detect = parser.add_argument_group("detection")
    detect.add_argument(
        "--time-based",
        action="store_true",
        help="also try DBMS sleep payloads (slow, 1 request each)",
    )
    detect.add_argument(
        "--time-delay",
        type=int,
        default=5,
        metavar="S",
        help="seconds the sleep payloads ask for (default: 5)",
    )
    detect.add_argument(
        "--fail-on-finding",
        choices=["none", "suspected", "likely", "confirmed"],
        default="none",
        help="exit 1 when a finding reaches this confidence (default: none)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-f",
        "--format",
        choices=list(FORMATS),
        default="console",
        help="report format (default: console)",
    )
    output.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to PATH atomically; '-' is stdout",
    )
    output.add_argument(
        "-q", "--quiet", action="store_true", help="suppress the console report"
    )
    output.add_argument(
        "--no-colour", action="store_true", help="disable ANSI colour even on a TTY"
    )
    output.add_argument(
        "--dry-run", action="store_true", help="print the plan and send no requests"
    )
    output.add_argument(
        "-v", "--verbose", action="count", default=0, help="repeat for debug logging"
    )
    output.add_argument(
        "--log-file", metavar="PATH", help="write logs to PATH as well as stderr"
    )
    output.add_argument(
        "--version", action="version", version=f"sqliscan {__version__}"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        config = _config_from(args)
    except _HelpRequested:
        return EXIT_OK
    except UsageError as exc:
        sys.stderr.write(f"sqliscan: {exc}\n")
        return EXIT_USAGE
    except TargetError as exc:
        sys.stderr.write(f"sqliscan: {exc}\n")
        return EXIT_USAGE

    _configure_logging(args)

    if args.dry_run:
        _print_plan(config, args)
        return EXIT_OK

    style = Style(enabled=not args.no_colour and supports_colour())

    try:
        scanner = Scanner(
            config,
            on_progress=_progress if args.verbose else None,
            on_finding=_stream_finding if args.verbose else None,
        )
        report = scanner.run()
    except KeyboardInterrupt:
        sys.stderr.write("\nsqliscan: interrupted\n")
        return EXIT_INTERRUPTED
    except (ScanError, TargetError) as exc:
        sys.stderr.write(f"sqliscan: {exc}\n")
        return EXIT_USAGE
    except Exception as exc:
        sys.stderr.write(f"sqliscan: internal error: {type(exc).__name__}: {exc}\n")
        if args.verbose:
            traceback.print_exc()
        return EXIT_INTERNAL

    try:
        if args.output is None and args.format == "console":
            # The interactive case: colour only here, and -q is what silences it.
            if not args.quiet:
                sys.stdout.write(render_report(report, style=style) + "\n")
        else:
            if args.format == "console":
                text = render_report(report, style=Style(enabled=False))
            else:
                text = render(report, args.format)
            if not text.endswith("\n"):
                text += "\n"
            if args.output is None:
                # A machine format was asked for by name; -q suppresses the
                # console report, not the thing that was explicitly requested.
                sys.stdout.write(text)
            else:
                # write_text treats "-" as stdout, so this covers both.
                write_text(text, args.output)
    except OSError as exc:
        sys.stderr.write(f"sqliscan: cannot write report: {exc}\n")
        return EXIT_USAGE

    threshold = (
        Confidence.parse(args.fail_on_finding)
        if args.fail_on_finding != "none"
        else None
    )
    if threshold is not None and threshold_reached(report.findings, threshold):
        return EXIT_THRESHOLD
    return EXIT_OK


def _config_from(args: argparse.Namespace) -> ScanConfig:
    # Parse the target here, not at scan time: an unusable target must fail
    # before a single request is sent, including under --dry-run.
    parse_target(args.target)

    _require_positive("--timeout", args.timeout)
    _require_non_negative("--rate-limit", args.rate_limit)
    _require_positive("--max-requests", args.max_requests)
    _require_positive("--max-urls", args.max_urls)
    _require_positive("--max-forms", args.max_forms)
    _require_positive("--workers", args.workers)
    _require_positive("--time-delay", args.time_delay)
    _require_non_negative("--depth", args.depth)
    _require_non_negative("--retries", args.retries)

    headers = _parse_headers(args.header)
    cookies = _parse_cookie(args.cookie) if args.cookie else {}

    return ScanConfig(
        target=args.target,
        depth=args.depth,
        max_urls=args.max_urls,
        max_requests=args.max_requests,
        rate_limit=args.rate_limit,
        workers=args.workers,
        timeout=args.timeout,
        retries=args.retries,
        verify_tls=not args.insecure,
        user_agent=args.user_agent or DEFAULT_USER_AGENT,
        headers=headers,
        cookies=cookies,
        proxy=args.proxy,
        forms=args.forms,
        max_forms=args.max_forms,
        time_based=args.time_based,
        time_delay=args.time_delay,
        respect_robots=not args.no_robots,
        allow_hosts=tuple(args.allow_host),
        include_subdomains=args.include_subdomains,
        exclude=tuple(args.exclude),
    )


def _require_positive(label: str, value: float) -> None:
    if value <= 0:
        raise UsageError(f"{label} must be greater than 0")


def _require_non_negative(label: str, value: float) -> None:
    if value < 0:
        raise UsageError(f"{label} must not be negative")


def _parse_headers(items: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items:
        name, separator, value = item.partition(":")
        if not separator or not name.strip():
            raise UsageError(f"malformed --header {item!r}; expected 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers


def _parse_cookie(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in value.split(";"):
        name, separator, content = part.partition("=")
        if not separator or not name.strip():
            raise UsageError(f"malformed --cookie {value!r}; expected 'a=1; b=2'")
        cookies[name.strip()] = content.strip()
    return cookies


def _configure_logging(args: argparse.Namespace) -> None:
    level = logging.DEBUG if args.verbose > 1 else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    # httpx logs one INFO line per request. Over a 2000-request scan that is a
    # wall of noise on stderr and no information the scanner does not already
    # report; only -vv brings it back.
    if args.verbose <= 1:
        for noisy in ("httpx", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def _progress(phase: str, done: int, total: int) -> None:
    sys.stderr.write(f"\rsqliscan: {phase} {done}/{total}")
    if done >= total:
        sys.stderr.write("\n")
    sys.stderr.flush()


def _stream_finding(finding: Finding) -> None:
    sys.stderr.write(f"\r\nsqliscan: {finding.label}\n")


def _print_plan(config: ScanConfig, args: argparse.Namespace) -> None:
    seed = parse_target(config.target)
    estimated = len(ERROR_PAYLOADS) * config.max_urls
    lines = [
        "sqliscan plan",
        f"  seed            {seed}",
        f"  depth           {config.depth}",
        f"  max pages       {config.max_urls}",
        f"  max requests    {config.max_requests}",
        f"  rate limit      {config.rate_limit:g} req/s",
        f"  workers         {config.workers}",
        f"  forms           {'yes' if config.forms else 'no'}",
        f"  time-based      {'yes' if config.time_based else 'no'}",
        f"  robots.txt      {'respected' if config.respect_robots else 'ignored'}",
        f"  format          {args.format}",
        f"  ceiling check   ~{estimated} probe requests for {config.max_urls} pages",
        "  no request has been sent",
    ]
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
