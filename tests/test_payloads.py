"""Payload catalogue: context inference, controls and DBMS signatures."""

from __future__ import annotations

import pytest

from sqliscan.models import Context
from sqliscan.payloads import (
    DBMS_PATTERNS,
    ERROR_PAYLOADS,
    boolean_pairs,
    control_for,
    first_excerpt,
    infer_context,
    match_signatures,
    name_dbms,
    time_payloads,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", Context.NUMERIC),
        ("-12", Context.NUMERIC),
        ("+7", Context.NUMERIC),
        (" 42 ", Context.NUMERIC),
        ("1a", Context.STRING),
        ("", Context.STRING),
        ("abc", Context.STRING),
        ("1.5", Context.STRING),
    ],
)
def test_infer_context(value: str, expected: Context) -> None:
    assert infer_context(value) is expected


@pytest.mark.parametrize("payload", ERROR_PAYLOADS)
def test_every_error_payload_has_a_control(payload: str) -> None:
    control = control_for(payload)
    assert control != payload
    assert control


def test_control_for_unknown_payload_matches_length() -> None:
    control = control_for("abcdef")
    assert len(control) == 6
    assert set(control) == {"z"}


@pytest.mark.parametrize("context", list(Context))
def test_boolean_pairs_are_same_length(context: Context) -> None:
    pairs = boolean_pairs(context)
    assert pairs
    for truthy, falsy in pairs:
        assert len(truthy) == len(falsy)
        assert truthy != falsy


def test_time_payloads_embed_the_delay() -> None:
    payloads = time_payloads(7)
    assert set(payloads) == {"MySQL", "PostgreSQL", "MSSQL", "Oracle"}
    assert "SLEEP(7)" in payloads["MySQL"]
    assert "pg_sleep(7)" in payloads["PostgreSQL"]
    assert "0:0:7" in payloads["MSSQL"]


def test_match_signatures_finds_mysql() -> None:
    hits = match_signatures(
        "You have an error in your SQL syntax; check the manual that "
        "corresponds to your MySQL server version"
    )
    assert "MySQL" in hits
    assert name_dbms(hits) == "MySQL"


def test_match_signatures_finds_postgres_oracle_and_mssql() -> None:
    assert (
        name_dbms(match_signatures('ERROR: syntax error at or near "\'"'))
        == "PostgreSQL"
    )
    assert name_dbms(match_signatures("ORA-01756: quoted string")) == "Oracle"
    assert (
        name_dbms(
            match_signatures("Unclosed quotation mark after the character string")
        )
        == "MSSQL"
    )


def test_match_signatures_is_empty_for_benign_text() -> None:
    assert match_signatures("<html><body>welcome to the shop</body></html>") == {}


def test_generic_signature_never_names_a_product() -> None:
    hits = match_signatures("SQL syntax error near the end of input")
    assert name_dbms(hits) == "unknown"


def test_name_dbms_prefers_specific_over_generic() -> None:
    hits: dict[str, tuple[str, ...]] = {
        "Generic": ("SQL syntax[^.<]{0,40}error",),
        "MySQL": ("You have an error in your SQL syntax",),
    }
    assert name_dbms(hits) == "MySQL"


def test_name_dbms_without_hits_is_unknown() -> None:
    assert name_dbms({}) == "unknown"


def test_first_excerpt_is_bounded_and_printable() -> None:
    text = "\x1b[31m" + ("x" * 400) + "ERROR: syntax error at or near" + ("y" * 400)
    excerpt = first_excerpt(text, limit=120)
    assert excerpt is not None
    assert "syntax error at or near" in excerpt
    assert "\x1b" not in excerpt
    assert len(excerpt) <= 200


def test_first_excerpt_none_without_a_match() -> None:
    assert first_excerpt("nothing to see") is None


def test_patterns_are_precompiled() -> None:
    for _dbms, pattern in DBMS_PATTERNS:
        assert hasattr(pattern, "search")
        assert pattern.pattern
