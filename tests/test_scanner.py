"""Orchestration: point collection, scope construction, and a full run."""

from __future__ import annotations

import pytest

from helpers import ScriptedTransport, point, response
from sqliscan.crawl import CrawlOutcome, Form, Page, Scope
from sqliscan.http import HttpxTransport, RetryingTransport
from sqliscan.models import Confidence, CrawlStats, Finding, Method
from sqliscan.scanner import (
    ScanConfig,
    ScanError,
    Scanner,
    _build_transport,
    build_scope,
    collect_points,
    threshold_reached,
)

CLEAN = "<html><body>shop</body></html>"
MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version"
)


def outcome(*pages: Page) -> CrawlOutcome:
    return CrawlOutcome(seed="https://example.com/", pages=pages, stats=CrawlStats())


def page(url: str, **kwargs: object) -> Page:
    defaults: dict[str, object] = {
        "status": 200,
        "content_type": "text/html",
    }
    defaults.update(kwargs)
    return Page(url=url, **defaults)  # type: ignore[arg-type]


# -- scope ------------------------------------------------------------------


def test_build_scope_uses_the_seed_host() -> None:
    scope = build_scope(ScanConfig(target="https://example.com/a?id=1"))
    assert scope.hosts == ("example.com",)


def test_build_scope_adds_allowed_hosts() -> None:
    scope = build_scope(
        ScanConfig(target="example.com", allow_hosts=("api.example.com",))
    )
    assert scope.hosts == ("api.example.com", "example.com")


def test_build_scope_honours_include_subdomains() -> None:
    scope = build_scope(ScanConfig(target="example.com", include_subdomains=True))
    assert scope.allows("https://api.example.com/")


def test_build_scope_rejects_an_unusable_target() -> None:
    with pytest.raises(ScanError, match="unsupported scheme"):
        build_scope(ScanConfig(target="ftp://example.com/"))


# -- point collection -------------------------------------------------------


def test_collect_points_reads_query_parameters() -> None:
    points = collect_points(
        outcome(page("https://example.com/item?id=1&page=2")),
        scope=Scope(["example.com"]),
        forms=False,
        max_forms=10,
    )
    assert [(item.parameter, item.value) for item in points] == [
        ("id", "1"),
        ("page", "2"),
    ]
    assert all(item.location.value == "query" for item in points)


def test_collect_points_keeps_a_blank_value() -> None:
    points = collect_points(
        outcome(page("https://example.com/search?q=")),
        scope=Scope(["example.com"]),
        forms=False,
        max_forms=10,
    )
    assert points[0].parameter == "q"
    assert points[0].value == ""


def test_collect_points_ignores_pages_without_a_query() -> None:
    points = collect_points(
        outcome(page("https://example.com/about")),
        scope=Scope(["example.com"]),
        forms=False,
        max_forms=10,
    )
    assert points == []


def test_collect_points_deduplicates_identical_points() -> None:
    duplicated = Page(
        url="https://example.com/item?id=1",
        status=200,
        content_type="text/html",
    )
    points = collect_points(
        outcome(duplicated, duplicated),
        scope=Scope(["example.com"]),
        forms=False,
        max_forms=10,
    )
    assert len(points) == 1


def test_collect_points_skips_forms_unless_asked() -> None:
    form = Form(action="/search", method=Method.POST, fields=(("q", ""),))
    points = collect_points(
        outcome(page("https://example.com/", forms=(form,))),
        scope=Scope(["example.com"]),
        forms=False,
        max_forms=10,
    )
    assert points == []


def test_collect_points_reads_a_post_form() -> None:
    form = Form(
        action="/login",
        method=Method.POST,
        fields=(("user", "bob"), ("pass", "")),
    )
    points = collect_points(
        outcome(page("https://example.com/login", forms=(form,))),
        scope=Scope(["example.com"]),
        forms=True,
        max_forms=10,
    )
    assert [(item.parameter, item.location.value) for item in points] == [
        ("user", "form"),
        ("pass", "form"),
    ]
    assert points[0].method is Method.POST
    assert points[0].fields == (("user", "bob"), ("pass", ""))


def test_collect_points_reads_a_get_form() -> None:
    form = Form(action="/search", method=Method.GET, fields=(("q", ""),))
    points = collect_points(
        outcome(page("https://example.com/", forms=(form,))),
        scope=Scope(["example.com"]),
        forms=True,
        max_forms=10,
    )
    assert points[0].method is Method.GET
    assert points[0].url == "https://example.com/search?q="


def test_collect_points_resolves_a_relative_form_action() -> None:
    form = Form(action="search", method=Method.GET, fields=(("q", ""),))
    points = collect_points(
        outcome(page("https://example.com/dir/", forms=(form,))),
        scope=Scope(["example.com"]),
        forms=True,
        max_forms=10,
    )
    assert points[0].url == "https://example.com/dir/search?q="


def test_collect_points_skips_a_form_that_uploads_files() -> None:
    form = Form(
        action="/upload",
        method=Method.POST,
        fields=(("name", ""),),
        has_file=True,
    )
    points = collect_points(
        outcome(page("https://example.com/", forms=(form,))),
        scope=Scope(["example.com"]),
        forms=True,
        max_forms=10,
    )
    assert points == []


def test_collect_points_skips_an_out_of_scope_form_action() -> None:
    form = Form(
        action="https://evil.test/steal", method=Method.POST, fields=(("a", ""),)
    )
    points = collect_points(
        outcome(page("https://example.com/", forms=(form,))),
        scope=Scope(["example.com"]),
        forms=True,
        max_forms=10,
    )
    assert points == []


def test_collect_points_skips_a_form_without_fields() -> None:
    form = Form(action="/empty", method=Method.POST, fields=())
    points = collect_points(
        outcome(page("https://example.com/", forms=(form,))),
        scope=Scope(["example.com"]),
        forms=True,
        max_forms=10,
    )
    assert points == []


def test_collect_points_stops_at_max_forms() -> None:
    forms = tuple(
        Form(action=f"/f{n}", method=Method.POST, fields=(("q", ""),)) for n in range(5)
    )
    points = collect_points(
        outcome(page("https://example.com/", forms=forms)),
        scope=Scope(["example.com"]),
        forms=True,
        max_forms=2,
    )
    assert len(points) == 2


# -- a full run -------------------------------------------------------------


def test_scan_config_options_record_what_changes_meaning() -> None:
    options = ScanConfig(
        target="example.com",
        depth=2,
        allow_hosts=("api.example.com",),
        exclude=(r"/admin",),
    ).options()
    assert options["depth"] == 2
    assert options["allow_hosts"] == ["api.example.com"]
    assert options["exclude"] == [r"/admin"]
    assert options["forms"] is False


def test_scanner_runs_end_to_end_without_a_socket() -> None:
    transport = ScriptedTransport()
    transport.set_default_body(CLEAN)
    transport.add(
        lambda request: request.url.endswith("%27%27"),
        lambda request: response(request.url, CLEAN),
    )
    transport.add(
        lambda request: request.url.endswith("%27"),
        lambda request: response(request.url, MYSQL_ERROR),
    )

    report = Scanner(
        ScanConfig(
            target="https://example.com/?id=1",
            depth=0,
            respect_robots=False,
            rate_limit=0,
        ),
        transport=transport,
    ).run()

    assert report.meta.target == "https://example.com/?id=1"
    assert report.meta.tool_version
    assert report.stats.pages_fetched == 1
    assert len(report.points) == 1
    assert report.highest is Confidence.CONFIRMED


def test_scanner_reports_a_clean_site() -> None:
    transport = ScriptedTransport()
    transport.set_default_body(CLEAN)

    report = Scanner(
        ScanConfig(
            target="https://example.com/?id=1",
            depth=0,
            respect_robots=False,
            rate_limit=0,
        ),
        transport=transport,
    ).run()

    assert report.findings == ()
    assert report.highest is None
    assert len(report.points) == 1


def test_scanner_reports_the_parameter_count_it_actually_tested() -> None:
    """A form field the caller did not ask to submit is not a tested parameter."""
    transport = ScriptedTransport()
    transport.set_default_body(
        CLEAN + "<form method='post' action='/go'><input name='q'></form>"
    )

    report = Scanner(
        ScanConfig(
            target="https://example.com/?id=1",
            depth=0,
            respect_robots=False,
            rate_limit=0,
            forms=False,
        ),
        transport=transport,
    ).run()

    assert report.stats.parameters_found == 1
    assert [point.parameter for point in report.points] == ["id"]


def test_scanner_never_closes_a_transport_it_does_not_own() -> None:
    transport = ScriptedTransport()
    Scanner(
        ScanConfig(
            target="https://example.com/",
            depth=0,
            respect_robots=False,
            rate_limit=0,
        ),
        transport=transport,
    ).run()
    assert transport.closed is False


def test_scanner_emits_progress() -> None:
    phases: list[tuple[str, int, int]] = []
    transport = ScriptedTransport()

    Scanner(
        ScanConfig(
            target="https://example.com/?id=1",
            depth=0,
            respect_robots=False,
            rate_limit=0,
        ),
        transport=transport,
        on_progress=lambda phase, done, total: phases.append((phase, done, total)),
    ).run()

    assert [phase for phase, _done, _total in phases] == ["points", "scan"]


def test_scanner_marks_a_budget_limited_run_as_truncated() -> None:
    transport = ScriptedTransport()

    report = Scanner(
        ScanConfig(
            target="https://example.com/?id=1",
            depth=0,
            respect_robots=False,
            rate_limit=0,
            max_requests=1,
        ),
        transport=transport,
    ).run()

    assert report.stats.truncated is True


def test_scanner_closes_a_transport_it_built(monkeypatch: pytest.MonkeyPatch) -> None:
    built = ScriptedTransport()
    monkeypatch.setattr("sqliscan.scanner._build_transport", lambda _config: built)

    Scanner(
        ScanConfig(
            target="https://example.com/?id=1",
            depth=0,
            respect_robots=False,
            rate_limit=0,
        )
    ).run()

    assert built.closed is True


# -- confidence threshold ---------------------------------------------------


@pytest.mark.parametrize(
    ("worst", "threshold", "expected"),
    [
        (Confidence.CONFIRMED, Confidence.CONFIRMED, True),
        (Confidence.CONFIRMED, Confidence.SUSPECTED, True),
        (Confidence.SUSPECTED, Confidence.CONFIRMED, False),
        (Confidence.LIKELY, Confidence.CONFIRMED, False),
        (Confidence.LIKELY, Confidence.LIKELY, True),
    ],
)
def test_threshold_reached(
    worst: Confidence, threshold: Confidence, expected: bool
) -> None:
    item = Finding(
        point=point(),
        kind="error",
        confidence=worst,
        dbms="MySQL",
        payload="'",
        rationale="r",
    )
    assert threshold_reached([item], threshold) is expected


def test_threshold_of_an_empty_list_is_never_reached() -> None:
    assert threshold_reached([], Confidence.SUSPECTED) is False


# -- transport construction -------------------------------------------------


def test_build_transport_wraps_httpx_with_retries() -> None:
    transport = _build_transport(
        ScanConfig(
            target="example.com",
            timeout=3.0,
            retries=2,
            verify_tls=False,
            proxy="http://127.0.0.1:8080",
            headers={"X-Scope": "engagement"},
            cookies={"sid": "abc"},
        )
    )
    try:
        assert isinstance(transport, RetryingTransport)
        assert transport._retries == 2
        assert isinstance(transport._inner, HttpxTransport)
    finally:
        transport.close()
