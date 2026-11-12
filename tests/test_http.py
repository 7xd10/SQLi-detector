"""Transport, retry policy, pacing and the request budget."""

from __future__ import annotations

import threading
from typing import Any

import httpx
import pytest

from sqliscan.http import (
    BudgetExceeded,
    HttpxTransport,
    RateLimiter,
    Request,
    RequestBudget,
    Response,
    RetryingTransport,
    TransportError,
    _build_client,
    send,
)


def make_response(status: int = 200, url: str = "https://example.com/") -> Response:
    return Response(url=url, status=status, headers={}, body=b"", elapsed_ms=0.0)


class StubTransport:
    """Answers from a script: a Response instance or an exception to raise."""

    def __init__(self, script: list[object]) -> None:
        self.script = list(script)
        self.requests: list[Request] = []
        self.closed = False

    def send(
        self,
        request: Request,
        *,
        timeout: float,
        follow_redirects: bool,
    ) -> Response:
        self.requests.append(request)
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, Response)
        return item

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record sleeps instead of taking them. Retry backoff is not under test."""
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", slept.append)
    return slept


# -- value types ------------------------------------------------------------


def test_request_line_includes_path_and_query() -> None:
    request = Request("GET", "https://example.com/a/b?id=1&x=2")
    assert request.request_line == "GET /a/b?id=1&x=2 HTTP/1.1"


def test_request_line_of_bare_host_is_root() -> None:
    assert Request("GET", "https://example.com").request_line == "GET / HTTP/1.1"


def test_request_line_escapes_nothing_further() -> None:
    request = Request("POST", "https://example.com/item?id=1%27")
    assert request.request_line == "POST /item?id=1%27 HTTP/1.1"


def test_response_exposes_body_properties() -> None:
    response = Response(
        url="https://example.com/",
        status=200,
        headers={"content-type": "text/html; charset=utf-8"},
        body=b"hello",
        elapsed_ms=1.5,
    )
    assert response.text == "hello"
    assert response.content_type == "text/html; charset=utf-8"
    assert response.length == 5


def test_response_missing_content_type_is_empty() -> None:
    response = Response("https://example.com/", 204, {}, b"", 0.0)
    assert response.content_type == ""


def test_response_decodes_invalid_utf8_without_raising() -> None:
    response = Response("https://example.com/", 200, {}, b"\xff\xfe", 0.0)
    assert "\ufffd" in response.text


# -- budget -----------------------------------------------------------------


def test_budget_counts_and_reports_remaining() -> None:
    budget = RequestBudget(2)
    assert budget.remaining == 2
    assert budget.used == 0
    budget.take()
    budget.take()
    assert budget.used == 2
    assert budget.remaining == 0


def test_budget_refuses_past_the_limit() -> None:
    budget = RequestBudget(1)
    budget.take()
    with pytest.raises(BudgetExceeded, match="exhausted"):
        budget.take()


def test_budget_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        RequestBudget(0)


def test_budget_is_exact_under_concurrency() -> None:
    budget = RequestBudget(500)
    granted = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal granted
        while True:
            try:
                budget.take()
            except BudgetExceeded:
                return
            with lock:
                granted += 1

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert granted == 500
    assert budget.used == 500


# -- pacing -----------------------------------------------------------------


def test_rate_limiter_disabled_never_sleeps(no_sleep: list[float]) -> None:
    RateLimiter(0).acquire()
    RateLimiter(-1).acquire()
    assert no_sleep == []


def test_rate_limiter_spaces_successive_calls(no_sleep: list[float]) -> None:
    limiter = RateLimiter(2.0)  # one call every 0.5 s
    limiter.acquire()
    limiter.acquire()
    assert len(no_sleep) == 1
    assert no_sleep[0] == pytest.approx(0.5, abs=0.25)


# -- retry policy -----------------------------------------------------------


def test_retry_returns_first_success() -> None:
    inner = StubTransport([make_response(200)])
    transport = RetryingTransport(inner, retries=2)
    assert (
        transport.send(
            Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=True
        ).status
        == 200
    )
    assert len(inner.requests) == 1


def test_retry_retries_a_transport_error() -> None:
    inner = StubTransport([TransportError("reset"), make_response(200)])
    transport = RetryingTransport(inner, retries=1, backoff=0.0)
    assert (
        transport.send(
            Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
        ).status
        == 200
    )
    assert len(inner.requests) == 2


def test_retry_reraises_the_last_transport_error() -> None:
    inner = StubTransport([TransportError("first"), TransportError("second")])
    transport = RetryingTransport(inner, retries=1, backoff=0.0)
    with pytest.raises(TransportError, match="second"):
        transport.send(
            Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
        )
    assert len(inner.requests) == 2


def test_retry_never_retries_a_500() -> None:
    """A 500 is often the observable under test; retrying hides it."""
    inner = StubTransport([make_response(500), make_response(200)])
    transport = RetryingTransport(inner, retries=3, backoff=0.0)
    assert (
        transport.send(
            Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
        ).status
        == 500
    )
    assert len(inner.requests) == 1


@pytest.mark.parametrize("status", [502, 503, 504])
def test_retry_recovers_from_gateway_errors(status: int) -> None:
    inner = StubTransport([make_response(status), make_response(200)])
    transport = RetryingTransport(inner, retries=1, backoff=0.0)
    assert (
        transport.send(
            Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
        ).status
        == 200
    )
    assert len(inner.requests) == 2


def test_retry_returns_the_last_gateway_error_when_exhausted() -> None:
    inner = StubTransport([make_response(503), make_response(503)])
    transport = RetryingTransport(inner, retries=1, backoff=0.0)
    assert (
        transport.send(
            Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
        ).status
        == 503
    )
    assert len(inner.requests) == 2


def test_retry_with_zero_retries_makes_one_attempt() -> None:
    inner = StubTransport([make_response(503)])
    transport = RetryingTransport(inner, retries=0)
    assert (
        transport.send(
            Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
        ).status
        == 503
    )
    assert len(inner.requests) == 1


def test_retry_negative_retries_is_clamped_to_zero() -> None:
    inner = StubTransport([make_response(200)])
    transport = RetryingTransport(inner, retries=-4)
    transport.send(
        Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
    )
    assert len(inner.requests) == 1


def test_retry_close_delegates() -> None:
    inner = StubTransport([])
    RetryingTransport(inner, retries=0).close()
    assert inner.closed is True


# -- the send() gate --------------------------------------------------------


def test_send_charges_the_budget_before_the_transport() -> None:
    inner = StubTransport([])
    budget = RequestBudget(1)
    budget.take()
    with pytest.raises(BudgetExceeded):
        send(
            inner,
            Request("GET", "https://example.com/"),
            timeout=1.0,
            follow_redirects=False,
            budget=budget,
        )
    assert inner.requests == []


def test_send_passes_the_timeout_and_redirect_policy_through() -> None:
    seen: dict[str, object] = {}

    class Recorder(StubTransport):
        def send(
            self,
            request: Request,
            *,
            timeout: float,
            follow_redirects: bool,
        ) -> Response:
            seen["timeout"] = timeout
            seen["follow"] = follow_redirects
            return make_response(200)

    budget = RequestBudget(5)
    limiter = RateLimiter(0)
    send(
        Recorder([]),
        Request("GET", "https://example.com/"),
        timeout=2.5,
        follow_redirects=False,
        limiter=limiter,
        budget=budget,
    )

    assert seen == {"timeout": 2.5, "follow": False}
    assert budget.used == 1


# -- the real transport -----------------------------------------------------
#
# ``HttpxTransport`` is exercised through ``httpx.MockTransport``: the client
# configuration, the bounded body read and the error wrapping are all real,
# and no socket is opened.


def install_client(
    monkeypatch: pytest.MonkeyPatch, handler: object
) -> dict[str, object]:
    """Swap the client factory, keep the arguments it was handed.

    The real ``_build_client`` is the thing under test elsewhere; here the
    factory echoes its own arguments into the client so a request made through
    ``MockTransport`` shows the headers the transport actually asked for.
    """
    captured: dict[str, object] = {}

    def factory(**kwargs: Any) -> httpx.Client:
        captured.update(kwargs)
        return httpx.Client(
            transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
            headers=dict(kwargs.get("headers") or {}),
            cookies=dict(kwargs.get("cookies") or {}),
        )

    monkeypatch.setattr("sqliscan.http._build_client", factory)
    return captured


def test_httpx_transport_returns_the_body_and_the_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=b"hello",
        )

    install_client(monkeypatch, handler)
    transport = HttpxTransport(user_agent="sqliscan-test/1")

    response = transport.send(
        Request("GET", "https://example.com/x"), timeout=1.0, follow_redirects=False
    )

    assert response.status == 200
    assert response.text == "hello"
    assert response.content_type == "text/html; charset=utf-8"
    assert response.length == 5
    assert response.elapsed_ms >= 0
    transport.close()


def test_httpx_transport_caps_the_body_at_max_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000)

    install_client(monkeypatch, handler)
    transport = HttpxTransport(user_agent="sqliscan-test/1", max_body=64)

    response = transport.send(
        Request("GET", "https://example.com/big"), timeout=1.0, follow_redirects=False
    )

    assert response.length == 64


def test_httpx_transport_sends_the_configured_headers_and_cookies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, content=b"ok")

    captured = install_client(monkeypatch, handler)
    transport = HttpxTransport(
        user_agent="sqliscan-test/1",
        headers={"X-Scope": "engagement"},
        cookies={"sid": "abc"},
    )

    transport.send(
        Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
    )

    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["User-Agent"] == "sqliscan-test/1"
    assert headers["X-Scope"] == "engagement"
    assert captured["cookies"] == {"sid": "abc"}
    assert seen["user-agent"] == "sqliscan-test/1"
    assert seen["x-scope"] == "engagement"
    assert seen["cookie"] == "sid=abc"


def test_httpx_transport_follows_redirects_only_when_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/next":
            return httpx.Response(200, content=b"arrived")
        return httpx.Response(302, headers={"location": "/next"})

    install_client(monkeypatch, handler)
    transport = HttpxTransport(user_agent="sqliscan-test/1")

    stuck = transport.send(
        Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=False
    )
    moved = transport.send(
        Request("GET", "https://example.com/"), timeout=1.0, follow_redirects=True
    )

    assert stuck.status == 302
    assert moved.status == 200
    assert moved.url == "https://example.com/next"


def test_httpx_transport_wraps_a_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    install_client(monkeypatch, handler)
    transport = HttpxTransport(user_agent="sqliscan-test/1")

    with pytest.raises(TransportError, match="ConnectError"):
        transport.send(
            Request("GET", "https://example.com/"),
            timeout=1.0,
            follow_redirects=False,
        )


def test_build_client_ignores_the_environment_and_redirects() -> None:
    client = _build_client(
        verify=True,
        proxy=None,
        headers={"User-Agent": "sqliscan-test/1"},
        cookies={},
        max_connections=4,
    )
    try:
        assert client.trust_env is False
        assert client.follow_redirects is False
        assert client.headers["user-agent"] == "sqliscan-test/1"
    finally:
        client.close()
