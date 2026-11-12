"""``python -m sqliscan`` — the module entry point forwards to the CLI."""

from __future__ import annotations

import runpy
import sys

import pytest


def test_module_entry_point_runs_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """``runpy`` executes ``__main__`` as a script, which is how -m works."""
    calls: list[list[str] | None] = []

    def fake_main(argv: list[str] | None = None) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr("sqliscan.cli.main", fake_main)
    monkeypatch.setattr(sys, "argv", ["sqliscan", "example.com"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("sqliscan", run_name="__main__", alter_sys=True)

    assert exit_info.value.code == 0
    assert calls == [None]
