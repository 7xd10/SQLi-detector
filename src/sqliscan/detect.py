"""The detector: baseline, probe, control, confirm, fingerprint.

The whole design is one idea repeated: **a difference only counts if it is
absent from a control**. Three controls are used, each of which kills a
different class of false positive.

* Baseline subtraction kills pages that already contain the error text.
* The escaped control kills reflection: ``'`` versus ``''`` trips the same
  signature on a server that echoes input.
* A repeat request kills flaky responses: a page that errors one request in
  three is not a finding.

What survives all three is reported. What fails one of them is downgraded to
``LIKELY`` rather than dropped, and the report says which control it failed.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .http import (
    RateLimiter,
    Request,
    RequestBudget,
    Response,
    Transport,
    TransportError,
    send,
)
from .models import (
    Confidence,
    Evidence,
    Finding,
    InjectionPoint,
    Location,
)
from .payloads import (
    ERROR_PAYLOADS,
    boolean_pairs,
    control_for,
    first_excerpt,
    infer_context,
    match_signatures,
    name_dbms,
    time_payloads,
)

_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

Pattern = tuple[str, str]


@dataclass(frozen=True)
class DetectSettings:
    timeout: float = 10.0
    follow_redirects: bool = True
    time_based: bool = False
    time_delay: int = 5
    bool_tolerance: float = 0.02
    repeats: int = 1


class Detector:
    """Tests injection points against one target, one point at a time."""

    def __init__(
        self,
        transport: Transport,
        *,
        limiter: RateLimiter | None = None,
        budget: RequestBudget | None = None,
        settings: DetectSettings | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._transport = transport
        self._limiter = limiter
        self._budget = budget
        self._settings = settings or DetectSettings()
        self._clock = clock

    # -- request construction ------------------------------------------------

    def build(self, point: InjectionPoint, value: str) -> Request:
        """The exact request a browser would send with ``value`` substituted."""
        if point.location is Location.QUERY:
            url = _replace_query(point.url, point.parameter, value)
            return Request(point.method.value, url)
        body = urlencode(_replace_field(point.fields, point.parameter, value))
        return Request(
            point.method.value,
            point.url,
            headers={"Content-Type": _FORM_CONTENT_TYPE},
            content=body.encode(),
        )

    # -- one point -----------------------------------------------------------

    def scan_point(self, point: InjectionPoint) -> list[Finding]:
        settings = self._settings
        baseline = self._send(point, point.value)
        findings: list[Finding] = []

        error_finding = self._error_based(point, baseline)
        if error_finding is not None:
            findings.append(error_finding)
        else:
            boolean = self._boolean_based(point, baseline)
            if boolean is not None:
                findings.append(boolean)

        if settings.time_based and not findings:
            timed = self._time_based(point, baseline)
            if timed is not None:
                findings.append(timed)
        return findings

    def _error_based(self, point: InjectionPoint, baseline: Response) -> Finding | None:
        settings = self._settings
        baseline_patterns = _patterns(baseline)

        for payload in ERROR_PAYLOADS:
            probe = self._send(point, point.value + payload)
            fresh = _patterns(probe) - baseline_patterns
            if not fresh:
                continue

            control_value = point.value + control_for(payload)
            control = self._send(point, control_value)
            if _patterns(control) & fresh:
                # The escaped form trips the same signature: the response is
                # reflecting input, not failing to parse SQL.
                continue

            confidence = Confidence.LIKELY
            evidence = [
                self._evidence(point, point.value + payload, probe, fresh),
                self._evidence(point, control_value, control, set()),
            ]
            for _ in range(settings.repeats):
                repeat = self._send(point, point.value + payload)
                if _patterns(repeat) & fresh:
                    confidence = Confidence.CONFIRMED
                else:
                    confidence = Confidence.LIKELY
                    break
                evidence.append(
                    self._evidence(point, point.value + payload, repeat, fresh)
                )

            return Finding(
                point=point,
                kind="error",
                confidence=confidence,
                dbms=name_dbms(_group(fresh)),
                payload=payload,
                rationale=(
                    "An error signature appeared only after the payload was "
                    "applied, did not appear for the escaped control, and "
                    + (
                        "reproduced on a repeat request."
                        if confidence is Confidence.CONFIRMED
                        else "did not reproduce on a repeat request."
                    )
                ),
                evidence=tuple(evidence),
            )
        return None

    def _boolean_based(
        self, point: InjectionPoint, baseline: Response
    ) -> Finding | None:
        settings = self._settings
        context = infer_context(point.value)
        for truthy, falsy in boolean_pairs(context):
            true_response = self._send(point, point.value + truthy)
            if not _same(true_response, baseline, settings.bool_tolerance):
                continue
            false_response = self._send(point, point.value + falsy)
            if _same(false_response, baseline, settings.bool_tolerance):
                continue
            return Finding(
                point=point,
                kind="boolean",
                confidence=Confidence.SUSPECTED,
                dbms="unknown",
                payload=truthy,
                rationale=(
                    "A true condition returned the baseline response and the "
                    "matching false condition did not. Length-and-status "
                    "evidence only: this is a blind-injection candidate, not "
                    "a parsed error."
                ),
                evidence=(
                    self._evidence(point, point.value + truthy, true_response, set()),
                    self._evidence(point, point.value + falsy, false_response, set()),
                ),
            )
        return None

    def _time_based(self, point: InjectionPoint, baseline: Response) -> Finding | None:
        settings = self._settings
        samples = [baseline.elapsed_ms, self._send(point, point.value).elapsed_ms]
        reference = statistics.median(samples)
        threshold = reference + settings.time_delay * 1000 * 0.8 + 200

        for dbms, payload in time_payloads(settings.time_delay).items():
            first = self._send(point, point.value + payload)
            if first.elapsed_ms < threshold:
                continue
            # A single slow response is a flaky signal, not evidence. Ask again
            # and let the repeat decide the rung, exactly as the error path does.
            second = self._send(point, point.value + payload)
            reproduced = second.elapsed_ms >= threshold
            return Finding(
                point=point,
                kind="time",
                confidence=Confidence.CONFIRMED if reproduced else Confidence.LIKELY,
                dbms=dbms,
                payload=payload,
                rationale=(
                    f"The response was delayed by {first.elapsed_ms:.0f} ms "
                    f"against a {reference:.0f} ms reference, using a "
                    f"{dbms} sleep primitive"
                    + (
                        ", and the delay reproduced on a repeat request."
                        if reproduced
                        else ", but the repeat request did not reproduce it."
                    )
                ),
                evidence=(
                    self._evidence(point, point.value + payload, first, set()),
                    self._evidence(point, point.value + payload, second, set()),
                ),
            )
        return None

    # -- transport -----------------------------------------------------------

    def _send(self, point: InjectionPoint, value: str) -> Response:
        return send(
            self._transport,
            self.build(point, value),
            timeout=self._settings.timeout,
            follow_redirects=self._settings.follow_redirects,
            limiter=self._limiter,
            budget=self._budget,
        )

    def _evidence(
        self,
        point: InjectionPoint,
        value: str,
        response: Response,
        matched: set[Pattern],
    ) -> Evidence:
        return Evidence(
            request_line=self.build(point, value).request_line,
            payload=value,
            status=response.status,
            length=response.length,
            content_type=response.content_type,
            elapsed_ms=response.elapsed_ms,
            matched=tuple(sorted(pattern for _dbms, pattern in matched)),
            excerpt=first_excerpt(response.text) or "",
        )


def _replace_query(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    # Replace every occurrence: a backend that reads the last duplicate still
    # sees the payload, and a backend that reads the first does too.
    updated = [
        (name, value if name == parameter else current) for name, current in pairs
    ]
    if not any(name == parameter for name, _ in pairs):
        updated.append((parameter, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), ""))


def _replace_field(
    fields: Sequence[tuple[str, str]], parameter: str, value: str
) -> list[tuple[str, str]]:
    updated = [
        (name, value if name == parameter else current) for name, current in fields
    ]
    if not any(name == parameter for name, _ in fields):
        updated.append((parameter, value))
    return updated


def _patterns(response: Response) -> set[Pattern]:
    """Every (dbms, pattern) that fired, as a set for subtraction."""
    return {
        (dbms, pattern)
        for dbms, patterns in match_signatures(response.text).items()
        for pattern in patterns
    }


def _group(patterns: set[Pattern]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for dbms, pattern in patterns:
        grouped.setdefault(dbms, []).append(pattern)
    return {dbms: tuple(values) for dbms, values in grouped.items()}


def _same(left: Response, right: Response, tolerance: float) -> bool:
    """Status equal and body length within a relative tolerance.

    Length is a blunt instrument, deliberately: bodies carry CSRF tokens and
    timestamps, so a hash comparison would never match and a diff would always
    match. Length plus status is the standard boolean-injection heuristic, and
    the finding is labelled SUSPECTED because of it.
    """
    if left.status != right.status:
        return False
    scale = max(left.length, right.length, 1)
    return abs(left.length - right.length) <= tolerance * scale


def scan_points(
    points: Sequence[InjectionPoint],
    detector: Detector,
    *,
    on_finding: Callable[[Finding], None] | None = None,
) -> list[Finding]:
    """Test every point, in order, tolerating per-point transport failures."""
    findings: list[Finding] = []
    for point in points:
        try:
            produced = detector.scan_point(point)
        except TransportError:
            continue
        for finding in produced:
            findings.append(finding)
            if on_finding is not None:
                on_finding(finding)
    return findings
