"""HTTP transport, retries, pacing and the request budget.

The scanner never talks to ``httpx`` directly. It talks to :class:`Transport`,
which is a two-method protocol. That boundary is what lets the entire test
suite run without a network: tests swap in a scripted transport and assert on
the exact requests the detector would have sent.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

import httpx

DEFAULT_MAX_BODY = 2 * 1024 * 1024


class TransportError(RuntimeError):
    """A request could not be completed. Never conflated with an HTTP status."""


class BudgetExceeded(RuntimeError):
    """The per-scan request ceiling was reached."""


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    content: bytes | None = None

    @property
    def request_line(self) -> str:
        parts = urlsplit(self.url)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        return f"{self.method} {target} HTTP/1.1"


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes
    elapsed_ms: float

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def length(self) -> int:
        return len(self.body)


class Transport(Protocol):
    def send(
        self,
        request: Request,
        *,
        timeout: float,
        follow_redirects: bool,
    ) -> Response: ...

    def close(self) -> None: ...


def _build_client(
    *,
    verify: bool,
    proxy: str | None,
    headers: Mapping[str, str],
    cookies: Mapping[str, str],
    max_connections: int,
) -> httpx.Client:
    """The one place an ``httpx.Client`` is constructed.

    Kept as a module function so tests can swap in an ``httpx.MockTransport``
    without weakening the transport's own configuration.
    """
    return httpx.Client(
        verify=verify,
        trust_env=False,
        proxy=proxy,
        headers=dict(headers),
        cookies=dict(cookies),
        limits=httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_connections,
        ),
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=False,
    )


class HttpxTransport:
    """The real transport: one pooled client, one bounded read per response."""

    def __init__(
        self,
        *,
        user_agent: str,
        verify: bool = True,
        max_connections: int = 32,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        proxy: str | None = None,
        max_body: int = DEFAULT_MAX_BODY,
    ) -> None:
        baseline: dict[str, str] = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if headers:
            baseline.update(headers)

        # trust_env is off on purpose: a leftover HTTP_PROXY in the shell must
        # not silently route a scan through somebody else's box. --proxy exists
        # for the cases where a proxy is actually wanted.
        self._client = _build_client(
            verify=verify,
            proxy=proxy,
            headers=baseline,
            cookies=dict(cookies or {}),
            max_connections=max_connections,
        )
        self._max_body = max_body

    def send(
        self,
        request: Request,
        *,
        timeout: float,
        follow_redirects: bool,
    ) -> Response:
        started = time.monotonic()
        try:
            with self._client.stream(
                request.method,
                request.url,
                headers=dict(request.headers),
                content=request.content,
                timeout=timeout,
                follow_redirects=follow_redirects,
            ) as response:
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= self._max_body:
                        break
                body = b"".join(chunks)[: self._max_body]
                status = response.status_code
                headers = dict(response.headers)
                final_url = str(response.url)
        except httpx.HTTPError as exc:
            raise TransportError(f"{type(exc).__name__}: {exc}") from exc

        return Response(
            url=final_url,
            status=status,
            headers=headers,
            body=body,
            elapsed_ms=(time.monotonic() - started) * 1000.0,
        )

    def close(self) -> None:
        self._client.close()


class RetryingTransport:
    """Retries connection failures and gateway errors, never a bare 500.

    A 500 is frequently the observable the scanner is looking for; retrying it
    three times with backoff both hides it behind a different response and
    multiplies traffic against a host that is already unhappy.
    """

    RETRY_STATUS: tuple[int, ...] = (502, 503, 504)

    def __init__(
        self,
        inner: Transport,
        *,
        retries: int,
        backoff: float = 0.3,
        statuses: tuple[int, ...] = RETRY_STATUS,
    ) -> None:
        self._inner = inner
        self._retries = max(0, retries)
        self._backoff = backoff
        self._statuses = statuses

    def send(
        self,
        request: Request,
        *,
        timeout: float,
        follow_redirects: bool,
    ) -> Response:
        attempt = 0
        while True:
            final = attempt >= self._retries
            try:
                response = self._inner.send(
                    request,
                    timeout=timeout,
                    follow_redirects=follow_redirects,
                )
            except TransportError:
                if final:
                    raise
            else:
                if final or response.status not in self._statuses:
                    return response
            time.sleep(self._backoff * (2**attempt) + random.uniform(0, 0.05))
            attempt += 1

    def close(self) -> None:
        self._inner.close()


class RateLimiter:
    """A shared token bucket. ``per_second <= 0`` disables pacing."""

    def __init__(self, per_second: float) -> None:
        self._interval = 1.0 / per_second if per_second > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next - now)
            self._next = max(now, self._next) + self._interval
        if wait > 0:
            time.sleep(wait)


class RequestBudget:
    """A hard ceiling on requests for the whole run, shared across threads."""

    def __init__(self, limit: int) -> None:
        if limit <= 0:
            raise ValueError("budget must be positive")
        self._limit = limit
        self._used = 0
        self._lock = threading.Lock()

    def take(self) -> None:
        with self._lock:
            if self._used >= self._limit:
                raise BudgetExceeded(
                    f"request budget of {self._limit} exhausted; "
                    "raise --max-requests to continue"
                )
            self._used += 1

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self._limit - self._used)


def send(
    transport: Transport,
    request: Request,
    *,
    timeout: float,
    follow_redirects: bool,
    limiter: RateLimiter | None = None,
    budget: RequestBudget | None = None,
) -> Response:
    """Send one request through the pacing and budget gates."""
    if budget is not None:
        budget.take()
    if limiter is not None:
        limiter.acquire()
    return transport.send(
        request,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
