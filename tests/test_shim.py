"""The pre-2.0 entry point: flag translation and the deprecation notice."""

from __future__ import annotations

import sys

import pytest
import sqli

from sqliscan import cli


@pytest.fixture(autouse=True)
def stub_cli(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Capture the argv ``sqli.py`` hands to the packaged CLI."""
    calls: list[list[str]] = []

    def fake_main(argv: list[str] | None = None) -> int:
        calls.append(list(argv or []))
        return 0

    monkeypatch.setattr(cli, "main", fake_main)
    return calls


# -- translation ------------------------------------------------------------


def test_domain_becomes_the_positional_target() -> None:
    assert sqli.translate(["-d", "example.com"]) == ["example.com", "--insecure"]


def test_long_domain_flag_is_accepted() -> None:
    assert sqli.translate(["--domain", "example.com"])[0] == "example.com"


def test_max_depth_becomes_depth() -> None:
    translated = sqli.translate(["-d", "example.com", "--max-depth", "2"])
    assert "--depth" in translated
    assert translated[translated.index("--depth") + 1] == "2"


def test_threads_becomes_workers() -> None:
    translated = sqli.translate(["-d", "example.com", "--threads", "4"])
    assert translated[translated.index("--workers") + 1] == "4"


def test_timeout_and_user_agent_survive() -> None:
    translated = sqli.translate(
        ["-d", "example.com", "--timeout", "3", "--user-agent", "probe/1"]
    )
    assert translated[translated.index("--timeout") + 1] == "3"
    assert translated[translated.index("--user-agent") + 1] == "probe/1"


def test_verify_ssl_suppresses_the_insecure_default() -> None:
    assert "--insecure" not in sqli.translate(["-d", "example.com", "--verify-ssl"])


def test_insecure_is_not_duplicated() -> None:
    translated = sqli.translate(["-d", "example.com", "--insecure"])
    assert translated.count("--insecure") == 1


def test_log_level_debug_becomes_very_verbose() -> None:
    translated = sqli.translate(["-d", "example.com", "--log-level", "DEBUG"])
    assert "-vv" in translated


def test_log_level_info_is_dropped() -> None:
    assert "-vv" not in sqli.translate(["-d", "example.com", "--log-level", "INFO"])


def test_unknown_flags_are_forwarded_untouched() -> None:
    translated = sqli.translate(["-d", "example.com", "--forms", "-q"])
    assert "--forms" in translated
    assert "-q" in translated


def test_help_is_forwarded_without_a_target() -> None:
    assert sqli.translate(["--help"]) == ["--help"]


def test_translation_without_a_domain_leaves_no_target() -> None:
    translated = sqli.translate(["--max-depth", "1"])
    assert "example.com" not in translated


def test_a_flag_without_a_value_is_rejected() -> None:
    with pytest.raises(SystemExit, match="needs a value"):
        sqli.translate(["-d"])


# -- entry point ------------------------------------------------------------


def test_main_forwards_the_translated_arguments(
    stub_cli: list[list[str]],
) -> None:
    assert sqli.main(["-d", "example.com", "--max-depth", "2"]) == 0
    assert stub_cli == [["--depth", "2", "example.com", "--insecure"]]


def test_main_without_arguments_explains_itself(
    stub_cli: list[list[str]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert sqli.main([]) == 2
    assert "deprecated" in capsys.readouterr().err
    assert stub_cli == []


def test_main_always_warns_on_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    sqli.main(["-d", "example.com"])
    assert "use the 'sqliscan' command" in capsys.readouterr().err


def test_main_reads_sys_argv_when_no_list_is_given(
    monkeypatch: pytest.MonkeyPatch, stub_cli: list[list[str]]
) -> None:
    monkeypatch.setattr(sys, "argv", ["sqli.py", "-d", "example.com"])
    assert sqli.main() == 0
    assert "example.com" in stub_cli[0]


def test_ensure_importable_tolerates_a_missing_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the package is installed the shim must not touch sys.path."""
    before = list(sys.path)
    sqli._ensure_importable()
    assert sys.path == before
