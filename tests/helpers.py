"""Builders shared by the test suite.

Tests import from here rather than from ``conftest``: pytest makes the test
directory importable, and a plain module keeps the imports explicit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Callable

from sqliscan.http import Request, Response, Transport
from sqliscan.models import (
    Confidence,
    Evidence,
    Finding,
    InjectionPoint,
    Location,
    Method,
)

Predicate = Callable[[Request], bool]
Responder = Callable[[Request], Response]


def response(
    url: str = "https://example.com/",
    body: bytes | str = b"<html><body>ok</body></html>",
    *,
    status: int = 200,
    content_type: str = "text/html; charset=utf-8",
    elapsed_ms: float = 4.0,
    headers: Mapping[str, str] | None = None,
) -> Response:
    payload = body.encode() if isinstance(body, str) else body
    merged = {"content-type": content_type}
    if headers:
        merged.update(headers)
    return Response(
        url=url,
        status=status,
        headers=merged,
        body=payload,
        elapsed_ms=elapsed_ms,
    )


class ScriptedTransport(Transport):
    """A transport that answers from a route table and records every request."""

    def __init__(self, default: Response | None = None) -> None:
        self.requests: list[Request] = []
        self.routes: list[tuple[Predicate, Responder]] = []
        self.closed = False
        self.default: Responder | None = (
            (lambda _request: default) if default is not None else None
        )

    def add(self, predicate: Predicate, responder: Responder) -> None:
        self.routes.append((predicate, responder))

    def add_url(self, fragment: str, body: str, **kwargs: object) -> None:
        self.add(
            lambda request: fragment in request.url,
            lambda request: response(request.url, body, **kwargs),  # type: ignore[arg-type]
        )

    def set_default_body(self, body: str, **kwargs: object) -> None:
        """Answer anything unmatched with ``body``, keeping the requested URL."""
        self.default = lambda request: response(request.url, body, **kwargs)  # type: ignore[arg-type]

    def send(
        self,
        request: Request,
        *,
        timeout: float,
        follow_redirects: bool,
    ) -> Response:
        self.requests.append(request)
        for predicate, responder in self.routes:
            if predicate(request):
                return responder(request)
        if self.default is not None:
            return self.default(request)
        return response(request.url)

    def close(self) -> None:
        self.closed = True

    @property
    def urls(self) -> list[str]:
        return [item.url for item in self.requests]


def point(
    *,
    url: str = "https://example.com/item?id=1",
    parameter: str = "id",
    value: str = "1",
    method: Method = Method.GET,
    location: Location = Location.QUERY,
    fields: Sequence[tuple[str, str]] = (),
) -> InjectionPoint:
    return InjectionPoint(
        method=method,
        url=url,
        location=location,
        parameter=parameter,
        value=value,
        fields=tuple(fields),
    )


def finding(
    *,
    confidence: Confidence = Confidence.CONFIRMED,
    payload: str = "'",
    dbms: str = "MySQL",
) -> Finding:
    return Finding(
        point=point(),
        kind="error",
        confidence=confidence,
        dbms=dbms,
        payload=payload,
        rationale="test",
        evidence=(
            Evidence(
                request_line="GET /item?id=1' HTTP/1.1",
                payload=payload,
                status=500,
                length=1234,
                content_type="text/html",
                elapsed_ms=12.5,
                matched=("You have an error in your SQL syntax",),
                excerpt="You have an error in your SQL syntax",
            ),
        ),
    )
