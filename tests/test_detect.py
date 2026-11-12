"""The detector: baseline subtraction, the escaped control, confirmation."""

from __future__ import annotations

from helpers import ScriptedTransport, point, response
from sqliscan.detect import Detector, DetectSettings, scan_points
from sqliscan.http import Request, TransportError
from sqliscan.models import Confidence, Location, Method

MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near"
)
CLEAN = "<html><body>nothing to see here</body></html>"

PROBE = "id=1%27"
CONTROL = "id=1%27%27"


def detector(transport: ScriptedTransport, **settings: object) -> Detector:
    return Detector(transport, settings=settings_for(**settings))


def settings_for(**overrides: object) -> DetectSettings:
    defaults: dict[str, object] = {"timeout": 1.0, "repeats": 1}
    defaults.update(overrides)
    return DetectSettings(**defaults)  # type: ignore[arg-type]


def route(
    transport: ScriptedTransport, fragment: str, body: str, **kwargs: object
) -> None:
    transport.add(
        lambda request: fragment in request.url,
        lambda request: response(request.url, body, **kwargs),  # type: ignore[arg-type]
    )


def error_site(transport: ScriptedTransport, *, control_errors: bool = False) -> None:
    """A target that fails to parse the probe and does not fail the control."""
    route(transport, CONTROL, MYSQL_ERROR if control_errors else CLEAN)
    route(transport, PROBE, MYSQL_ERROR)


# -- request construction ---------------------------------------------------


def test_build_replaces_the_parameter_and_keeps_the_rest() -> None:
    target = point(url="https://example.com/item?id=1&page=2")
    request = detector(ScriptedTransport()).build(target, "1'")
    assert request.url == "https://example.com/item?id=1%27&page=2"
    assert request.method == "GET"


def test_build_replaces_every_duplicate_occurrence() -> None:
    target = point(url="https://example.com/item?id=1&id=2")
    request = detector(ScriptedTransport()).build(target, "x")
    assert request.url == "https://example.com/item?id=x&id=x"


def test_build_appends_a_parameter_that_is_absent() -> None:
    target = point(url="https://example.com/item")
    request = detector(ScriptedTransport()).build(target, "1'")
    assert request.url == "https://example.com/item?id=1%27"


def test_build_encodes_a_form_body() -> None:
    target = point(
        url="https://example.com/login",
        method=Method.POST,
        location=Location.FORM,
        parameter="user",
        value="bob",
        fields=(("user", "bob"), ("pass", "hunter2")),
    )
    request = detector(ScriptedTransport()).build(target, "bob'")
    assert request.content == b"user=bob%27&pass=hunter2"
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_build_appends_a_form_field_that_is_absent() -> None:
    target = point(
        url="https://example.com/login",
        method=Method.POST,
        location=Location.FORM,
        parameter="extra",
        value="",
        fields=(("user", "bob"),),
    )
    request = detector(ScriptedTransport()).build(target, "1")
    assert request.content == b"user=bob&extra=1"


# -- error based ------------------------------------------------------------


def test_error_based_confirms_with_probe_control_and_repeat() -> None:
    transport = ScriptedTransport()
    error_site(transport)

    findings = detector(transport).scan_point(point())

    assert len(findings) == 1
    found = findings[0]
    assert found.confidence is Confidence.CONFIRMED
    assert found.kind == "error"
    assert found.dbms == "MySQL"
    assert found.payload == "'"
    assert found.evidence[0].request_line == "GET /item?id=1%27 HTTP/1.1"
    assert found.evidence[0].status == 200
    assert found.evidence[0].matched


def test_error_based_downgrades_when_the_repeat_does_not_reproduce() -> None:
    transport = ScriptedTransport()
    route(transport, CONTROL, CLEAN)
    answers = [MYSQL_ERROR, CLEAN]
    transport.add(
        lambda request: request.url.endswith(PROBE),
        lambda request: response(request.url, answers.pop(0) if answers else CLEAN),
    )

    findings = detector(transport).scan_point(point())

    assert len(findings) == 1
    assert findings[0].confidence is Confidence.LIKELY
    assert "did not reproduce" in findings[0].rationale


def test_error_based_discards_a_reflection() -> None:
    """The escaped control trips the same signature: input is echoed, not parsed."""
    transport = ScriptedTransport()
    error_site(transport, control_errors=True)

    assert detector(transport).scan_point(point()) == []


def test_error_based_subtracts_the_baseline() -> None:
    """A page that already mentions the error text is not a finding."""
    transport = ScriptedTransport()
    route(transport, "id=1", MYSQL_ERROR)

    assert detector(transport).scan_point(point()) == []


def test_error_based_ignores_a_benign_target() -> None:
    transport = ScriptedTransport()
    assert detector(transport).scan_point(point()) == []


def test_error_based_tries_each_payload_until_one_fires() -> None:
    transport = ScriptedTransport()
    route(transport, CONTROL, CLEAN)
    transport.add(
        lambda request: "%22" in request.url and "id=1%22%22" not in request.url,
        lambda request: response(request.url, MYSQL_ERROR),
    )

    findings = detector(transport).scan_point(point())

    assert len(findings) == 1
    assert findings[0].payload == '"'
    assert findings[0].confidence is Confidence.CONFIRMED


def test_error_based_only_needs_one_confirmed_payload() -> None:
    transport = ScriptedTransport()
    error_site(transport)

    findings = detector(transport).scan_point(point())

    assert [item.payload for item in findings] == ["'"]


def test_a_generic_signature_reports_an_unknown_dbms() -> None:
    transport = ScriptedTransport()
    route(transport, CONTROL, CLEAN)
    route(transport, PROBE, "SQL syntax error near the end of input")

    findings = detector(transport).scan_point(point())

    assert findings[0].dbms == "unknown"


# -- boolean based ----------------------------------------------------------


def boolean_site(
    transport: ScriptedTransport, *, baseline: int, truthy: int, falsy: int
) -> None:
    transport.set_default_body("x" * baseline)
    route(transport, "1+AND+1%3D1", "x" * truthy)
    route(transport, "1+AND+1%3D2", "x" * falsy)


def test_boolean_based_reports_a_suspected_blind_injection() -> None:
    transport = ScriptedTransport()
    boolean_site(transport, baseline=100, truthy=100, falsy=20)

    findings = detector(transport).scan_point(point())

    assert len(findings) == 1
    found = findings[0]
    assert found.kind == "boolean"
    assert found.confidence is Confidence.SUSPECTED
    assert found.dbms == "unknown"
    assert found.payload == " AND 1=1"
    assert len(found.evidence) == 2


def test_boolean_based_skips_when_the_true_condition_differs_from_baseline() -> None:
    transport = ScriptedTransport()
    boolean_site(transport, baseline=100, truthy=10, falsy=20)

    assert detector(transport).scan_point(point()) == []


def test_boolean_based_skips_when_both_conditions_match() -> None:
    transport = ScriptedTransport()
    boolean_site(transport, baseline=100, truthy=100, falsy=100)

    assert detector(transport).scan_point(point()) == []


def test_boolean_based_uses_the_string_pairs_for_a_string_value() -> None:
    transport = ScriptedTransport()
    transport.set_default_body("x" * 100)
    target = point(
        url="https://example.com/item?name=bob", parameter="name", value="bob"
    )
    route(transport, "bob%27+AND+%271%27%3D%271", "x" * 100)
    route(transport, "bob%27+AND+%271%27%3D%272", "x" * 20)

    findings = detector(transport).scan_point(target)

    assert findings[0].kind == "boolean"
    assert findings[0].payload == "' AND '1'='1"


def test_boolean_based_respects_the_length_tolerance() -> None:
    transport = ScriptedTransport()
    # 2% of 1000 bytes is 20 bytes; a 19-byte difference still counts as equal,
    # so the pair never looks like a boolean oracle.
    boolean_site(transport, baseline=1000, truthy=1000, falsy=981)

    assert detector(transport).scan_point(point()) == []


def test_boolean_based_skips_when_the_status_differs() -> None:
    transport = ScriptedTransport()
    transport.set_default_body("x" * 100)
    route(transport, "1+AND+1%3D1", "x" * 100, status=500)
    route(transport, "1+AND+1%3D2", "x" * 20)

    assert detector(transport).scan_point(point()) == []


# -- time based -------------------------------------------------------------


def slow_site(transport: ScriptedTransport, *, delayed: bool) -> None:
    route(
        transport,
        "SLEEP",
        CLEAN,
        elapsed_ms=6000.0 if delayed else 5.0,
    )


def test_time_based_is_off_by_default() -> None:
    transport = ScriptedTransport()
    slow_site(transport, delayed=True)

    assert detector(transport).scan_point(point()) == []


def test_time_based_confirms_a_delay() -> None:
    transport = ScriptedTransport()
    slow_site(transport, delayed=True)

    findings = detector(transport, time_based=True, time_delay=5).scan_point(point())

    assert len(findings) == 1
    found = findings[0]
    assert found.kind == "time"
    assert found.confidence is Confidence.CONFIRMED
    assert found.dbms == "MySQL"
    assert "SLEEP(5)" in found.payload
    assert "delayed by" in found.rationale
    assert "reproduced on a repeat request" in found.rationale
    assert len(found.evidence) == 2


def test_time_based_downgrades_a_delay_that_does_not_repeat() -> None:
    """One slow response is a flaky sample; the repeat decides the rung."""
    transport = ScriptedTransport()
    seen: list[int] = []

    def once_slow(request: object) -> object:
        seen.append(1)
        return response(
            getattr(request, "url", "https://example.com/"),
            CLEAN,
            elapsed_ms=6000.0 if len(seen) == 1 else 5.0,
        )

    transport.add(lambda request: "SLEEP" in request.url, once_slow)  # type: ignore[arg-type]
    transport.set_default_body(CLEAN)

    findings = detector(transport, time_based=True, time_delay=5).scan_point(point())

    assert len(findings) == 1
    found = findings[0]
    assert found.confidence is Confidence.LIKELY
    assert "did not reproduce" in found.rationale
    assert [item.status for item in found.evidence] == [200, 200]


def test_time_based_ignores_a_fast_response() -> None:
    transport = ScriptedTransport()
    slow_site(transport, delayed=False)

    assert detector(transport, time_based=True).scan_point(point()) == []


def test_time_based_is_not_attempted_after_an_error_finding() -> None:
    transport = ScriptedTransport()
    error_site(transport)
    slow_site(transport, delayed=True)

    findings = detector(transport, time_based=True).scan_point(point())

    assert [item.kind for item in findings] == ["error"]
    assert not any("SLEEP" in url for url in transport.urls)


# -- orchestration ----------------------------------------------------------


def test_scan_points_tests_every_point() -> None:
    transport = ScriptedTransport()
    error_site(transport)

    points = [
        point(url="https://example.com/a?id=1"),
        point(url="https://example.com/b?id=1"),
    ]
    findings = scan_points(points, detector(transport))

    assert len(findings) == 2


def test_scan_points_reports_each_finding_as_it_lands() -> None:
    transport = ScriptedTransport()
    error_site(transport)
    seen: list[str] = []

    scan_points(
        [point(), point(url="https://example.com/b?id=1")],
        detector(transport),
        on_finding=lambda item: seen.append(item.label),
    )

    assert len(seen) == 2
    assert all(label.startswith("CONFIRMED") for label in seen)


def test_scan_points_tolerates_a_failing_point() -> None:
    transport = ScriptedTransport()

    def boom(request: Request) -> object:
        raise TransportError("connection reset")

    transport.add(lambda request: request.url.startswith("https://dead/"), boom)  # type: ignore[arg-type]
    error_site(transport)

    findings = scan_points(
        [point(url="https://dead/?id=1"), point()],
        detector(transport),
    )

    assert len(findings) == 1
