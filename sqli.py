#!/usr/bin/env python3
"""Compatibility shim for the pre-2.0 single-file scanner.

The old entry point took ``-d/--domain`` and a handful of flags. Those still
work, translated onto the packaged CLI. Nothing new will be added here.

    python sqli.py -d testphp.vulnweb.com --max-depth 2
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

USAGE_HINT = (
    "sqli.py: this entry point is deprecated; use the 'sqliscan' command "
    "(pip install -e . then: sqliscan -h)."
)


def _ensure_importable() -> None:
    """Allow running from a checkout without installing the package."""
    try:
        import sqliscan  # noqa: F401
    except ImportError:
        source = Path(__file__).resolve().parent / "src"
        if source.is_dir():
            sys.path.insert(0, str(source))


def _value(items: Sequence[str], index: int, flag: str) -> str:
    if index + 1 >= len(items):
        raise SystemExit(f"sqli.py: {flag} needs a value")
    return items[index + 1]


def translate(argv: Sequence[str]) -> list[str]:
    """Map pre-2.0 arguments onto the packaged CLI's arguments."""
    items = list(argv)
    out: list[str] = []
    target: str | None = None
    index = 0

    replacements: tuple[tuple[str, str], ...] = (
        ("--max-depth", "--depth"),
        ("--threads", "--workers"),
        ("--timeout", "--timeout"),
        ("--user-agent", "--user-agent"),
    )
    rename = dict(replacements)

    while index < len(items):
        item = items[index]
        if item in ("-d", "--domain"):
            target = _value(items, index, item)
            index += 2
            continue
        if item in rename:
            out.extend([rename[item], _value(items, index, item)])
            index += 2
            continue
        if item == "--verify-ssl":
            index += 1
            continue
        if item == "--log-level":
            level = _value(items, index, item).upper()
            if level == "DEBUG":
                out.append("-vv")
            index += 2
            continue
        out.append(item)
        index += 1

    help_requested = any(flag in items for flag in ("-h", "--help"))
    if help_requested:
        return out
    if target is not None:
        out.append(target)
    # The legacy scanner disabled TLS verification unless --verify-ssl was
    # passed, so an old invocation keeps that behaviour.
    if "--verify-ssl" not in items and "--insecure" not in items:
        out.append("--insecure")
    return out


def main(argv: Sequence[str] | None = None) -> int:
    _ensure_importable()
    from sqliscan.cli import main as cli_main

    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        sys.stderr.write(USAGE_HINT + "\n")
        return 2
    sys.stderr.write(USAGE_HINT + "\n")
    return cli_main(translate(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
