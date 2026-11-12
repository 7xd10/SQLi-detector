"""Payload catalogue and DBMS error signatures.

Two rules govern this module and both are load-bearing:

1. A signature only counts if it was **absent from the baseline**. The
   comparison lives in :mod:`sqliscan.detect`; this module just supplies the
   patterns. A blog post containing the words "SQL syntax error" must not
   become a finding, and baseline subtraction is what prevents that.

2. Every error probe has a **same-shape escaped control**. If the control
   trips the same signature, the response is reflecting input, not failing to
   parse SQL, and the detector discards it. See :func:`control_for`.
"""

from __future__ import annotations

import re

from .models import Context

# Probes that try to break out of a quoted or unquoted literal. The control for
# each is the escaped form of the same character, so a server that merely echoes
# the input trips both and the pair cancels out.
ERROR_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    "')",
    '"))',
    "';",
    '")',
)

CONTROLS: dict[str, str] = {
    "'": "''",
    '"': '""',
    "')": "'')",
    '"))': '""))',
    "';": "'';",
    '")': '""")',
}

# Boolean pairs. Each pair is the same length, so a length-based comparison is
# not skewed by the payload itself.
BOOLEAN_PAIRS: dict[Context, tuple[tuple[str, str], ...]] = {
    Context.STRING: (
        ("' AND '1'='1", "' AND '1'='2"),
        ('" AND "1"="1', '" AND "1"="2'),
        ("' OR '1'='1", "' OR '1'='2"),
    ),
    Context.NUMERIC: (
        (" AND 1=1", " AND 1=2"),
        (") AND 1=1", ") AND 1=2"),
    ),
}

# Time-based probes, one per family. Only used with --time-based because each
# one costs the delay value in wall clock.
TIME_PAYLOADS: dict[str, str] = {
    "MySQL": "' AND SLEEP({delay})-- -",
    "PostgreSQL": "'; SELECT pg_sleep({delay})-- -",
    "MSSQL": "'; WAITFOR DELAY '0:0:{delay}'-- -",
    "Oracle": "' AND 1=dbms_pipe.receive_message(CHR(10),{delay})-- -",
}

# Ordered so the specific signatures are evaluated before the generic ones.
# ``Generic`` is a last resort and is never used to name a DBMS in a finding.
DBMS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "MySQL",
        re.compile(
            r"You have an error in your SQL syntax",
            re.IGNORECASE,
        ),
    ),
    (
        "MySQL",
        re.compile(
            r"check the manual that corresponds to your "
            r"(?:MariaDB|MySQL) server version",
            re.IGNORECASE,
        ),
    ),
    (
        "MySQL",
        re.compile(
            r"supplied argument is not a valid MySQL result resource",
            re.IGNORECASE,
        ),
    ),
    ("MySQL", re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE)),
    (
        "MySQL",
        re.compile(r"com\.mysql\.jdbc\.exceptions\.\w+Exception", re.IGNORECASE),
    ),
    ("PostgreSQL", re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE)),
    (
        "PostgreSQL",
        re.compile(r"unterminated quoted string at or near", re.IGNORECASE),
    ),
    (
        "PostgreSQL",
        re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE),
    ),
    ("PostgreSQL", re.compile(r"pg_query\(\): Query failed", re.IGNORECASE)),
    (
        "MSSQL",
        re.compile(
            r"Unclosed quotation mark after the character string",
            re.IGNORECASE,
        ),
    ),
    ("MSSQL", re.compile(r"Incorrect syntax near", re.IGNORECASE)),
    (
        "MSSQL",
        re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
    ),
    ("MSSQL", re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE)),
    ("Oracle", re.compile(r"ORA-\d{5}", re.IGNORECASE)),
    ("Oracle", re.compile(r"quoted string not properly terminated", re.IGNORECASE)),
    ("Oracle", re.compile(r"SQL command not properly ended", re.IGNORECASE)),
    ("SQLite", re.compile(r"sqlite3\.OperationalError", re.IGNORECASE)),
    ("SQLite", re.compile(r"SQLiteException", re.IGNORECASE)),
    ("SQLite", re.compile(r"\[SQLITE_ERROR\]", re.IGNORECASE)),
    # Generic last: it may confirm "something SQL failed here" but it never
    # names a product, and detect.py reports dbms="unknown" when only these hit.
    ("Generic", re.compile(r"SQL syntax[^.<]{0,40}error", re.IGNORECASE)),
    ("Generic", re.compile(r"syntax error in SQL statement", re.IGNORECASE)),
)

_NUMERIC = re.compile(r"^[+-]?\d+$")


def infer_context(value: str) -> Context:
    """Numeric if the value is a bare integer, string otherwise.

    A scanner cannot see the query, so this is an inference from the observed
    value and nothing more. It selects which boolean pair to try, not what the
    server is doing.
    """
    return Context.NUMERIC if _NUMERIC.match(value.strip()) else Context.STRING


def control_for(payload: str) -> str:
    """The escaped form of an error probe.

    ``'`` is controlled by ``''``, ``')`` by ``'')``, and so on. A payload with
    no entry falls back to a benign string of the same length, which is enough
    to catch length- or reflection-based noise.
    """
    if payload in CONTROLS:
        return CONTROLS[payload]
    return "z" * max(1, len(payload))


def boolean_pairs(context: Context) -> tuple[tuple[str, str], ...]:
    return BOOLEAN_PAIRS[context]


def time_payloads(delay: int) -> dict[str, str]:
    return {
        dbms: template.format(delay=delay) for dbms, template in TIME_PAYLOADS.items()
    }


def match_signatures(text: str) -> dict[str, tuple[str, ...]]:
    """Group matched signature sources by DBMS family.

    Returns the *pattern text* rather than the match, because two responses of
    the same page must produce the same key for baseline subtraction to work.
    """
    hits: dict[str, list[str]] = {}
    for dbms, pattern in DBMS_PATTERNS:
        if pattern.search(text):
            hits.setdefault(dbms, []).append(pattern.pattern)
    return {dbms: tuple(patterns) for dbms, patterns in hits.items()}


def name_dbms(hits: dict[str, tuple[str, ...]]) -> str:
    """Pick the most specific family that matched, or ``unknown``."""
    for family in ("MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"):
        if family in hits:
            return family
    if "Generic" in hits:
        return "unknown"
    return "unknown"


def first_excerpt(text: str, limit: int = 160) -> str | None:
    """A bounded, printable excerpt around the first signature match."""
    for _dbms, pattern in DBMS_PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        start = max(0, match.start() - limit // 2)
        end = min(len(text), match.end() + limit // 2)
        return _printable(text[start:end])
    return None


_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_WHITESPACE = re.compile(r"\s+")


def _printable(text: str) -> str:
    """Responses are attacker-controlled bytes; never emit them raw."""
    text = _ANSI.sub("", text)
    text = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
    return _WHITESPACE.sub(" ", text).strip()
