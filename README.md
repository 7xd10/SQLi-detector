# sqliscan

A SQL injection scanner that distinguishes *"the server echoed my quote"* from
*"the parser failed"* — and says which evidence it used.

`sqliscan` crawls a target you are authorised to test, collects every parameter
it can reach (query string and, with `--forms`, same-origin HTML forms), sends
one probe per parameter with a baseline request first, and reports findings on a
three-rung confidence ladder with the request and response that produced them.

```
sqliscan https://example.com/product.php?id=1
```

Against a local test target, one injectable parameter and nothing else:

```
sqliscan
target   http://127.0.0.1:46007/product?id=1
started  2026-11-12T10:11:53.424Z
finished 2026-11-12T10:11:53.607Z
pages    1 page fetched, 0 failed, 0 forms
points   1 injection point tested

findings
 1. CONFIRMED              MySQL       id @ http://127.0.0.1:46007/product?id=1
    kind error  payload "'"
    why An error signature appeared only after the payload was applied, did not appear for the escaped control, and reproduced on a repeat request.
    > GET /product?id=1%27 HTTP/1.1 -> 500 174B 44ms
      <html><body>You have an error in your SQL syntax; check the manual that correspo
    > GET /product?id=1%27%27 HTTP/1.1 -> 200 37B 43ms
    > GET /product?id=1%27 HTTP/1.1 -> 500 174B 44ms
      <html><body>You have an error in your SQL syntax; check the manual that correspo

summary  1 confirmed | 0 likely | 0 suspected
```

That output is pasted from a real run, with one `why` line and one excerpt line
that the terminal would wrap — the table is left exactly as the tool printed it.

---

## Install

```sh
pip install .              # from a checkout
pip install -e ".[dev]"    # with pytest, ruff and mypy
```

Python 3.9 or newer. The only runtime dependency is `httpx`.

```sh
sqliscan --version
python -m sqliscan --version   # equivalent
```

Docker:

```sh
docker build -t sqliscan .
docker run --rm sqliscan --dry-run https://example.com/item?id=1
```

---

## Why the verdict has three rungs

The 1.x scanner reported `VULNERABLE` or `SAFE` from one substring match
against a table of DBMS error strings. That produced two classes of wrong
answer, both common:

- **False positive.** Any page that *mentions* the phrase — documentation, a
  blog post about SQL, the application's own error handler — matched.
- **False negative.** Any injection that does not print its error to the page,
  which is most modern deployments. The time-based payload was in the list and
  never measured, so blind injection was invisible.

2.0 answers a narrower question, more carefully: *did this specific probe cause
this specific response, and does it happen again?*

| Rung | What it means |
| --- | --- |
| `CONFIRMED` | The signature was absent from the baseline, absent from the escaped control, and reproduced on a repeat request. |
| `LIKELY` | Baseline and control are clean, but the repeat did not reproduce. Flaky — check it by hand. |
| `SUSPECTED` | A boolean pair differs in the way an injection would, with no error text. Blind. Needs a human or a `--time-based` run. |

Nothing is ever reported as a bare boolean. A `SUSPECTED` is not a bug yet; it
is a place to look.

### The three requests that make a finding

For each parameter, on the first error payload:

1. **Baseline** — the request with the *original* value, unmodified. Any
   signature already present here is recorded and subtracted. A page that
   always says "SQL syntax error" produces nothing.
2. **Probe** — the value replaced by a payload that breaks out of a quoted or
   unquoted literal (`'`, `"`, `')`, `'))`, `';`, `")`).
3. **Control** — the *escaped form of the same character* (`'` → `''`). If the
   control trips the same signature, the input is being reflected, not parsed
   as SQL, and the pair is discarded.

Then, only for a probe that fired: a **repeat** of the same probe. Reproduced →
`CONFIRMED`; not reproduced → `LIKELY`.

Boolean probing runs after the error sweep comes back empty. A numeric pair
(`AND 1=1` / `AND 1=2`) and a string pair (`AND '1'='1` / `AND '1'='2`) are
sent; a pair counts as an oracle only when the truthy response matches the
baseline *and* the falsy one diverges from it by more than 2% of body length
and differs in status.

### Request arithmetic

| Phase | Requests per parameter |
| --- | --- |
| Baseline + 6 error payloads | 7 |
| Control + repeat, only if a probe fired | +2 |
| Boolean pairs, only if no error fired | 2–4 |
| Time-based, only if `--time-based` and nothing else fired | 1–9 |

`--max-requests` (default 2000) is the real ceiling and is charged *before* the
socket opens. `--max-urls` (default 200) bounds the crawl only.

---

## Usage

```
sqliscan TARGET [options]
```

`TARGET` is a host or a URL. A bare host gets `https://`, and the seed URL's
query parameters are the first injection points.

### Crawl

| Flag | Default | Meaning |
| --- | --- | --- |
| `--depth N` | `3` | Maximum link depth from the seed. |
| `--max-urls N` | `200` | Pages fetched per target. |
| `--forms` | off | Also submit same-origin HTML forms. Off by default because a form is usually a write. |
| `--max-forms N` | `50` | Forms submitted per target. |
| `--no-robots` | respected | Ignore `robots.txt`. |
| `--include-subdomains` | off | Allow hosts under the seed host. |
| `--allow-host HOST` | — | Additional in-scope host. Repeatable. |
| `--exclude REGEX` | — | Path pattern never to request. Repeatable. |

Paths that change state on a GET — `/logout`, `/signout`, `/delete`, `/remove`,
`/destroy`, `/unsubscribe`, `/deactivate`, `/revoke`, `/checkout`, `/purchase`,
`/shutdown` — are denied by default, before `--exclude` is applied. Scope is
compared on the lowercased hostname and ignores the port, so `https://…:443/`
and `http://…` stay in scope while `example.com.evil.test` does not.

### Network

| Flag | Default | Meaning |
| --- | --- | --- |
| `--timeout S` | `10` | Per-request timeout in seconds. Float. |
| `--retries N` | `1` | Retries for connection failures and `502`/`503`/`504`. |
| `--workers N` | `8` | Concurrent *crawl* fetches. Detection is serial. |
| `--rate-limit N` | `10` | Requests per second across the whole scan. `0` disables pacing. |
| `--max-requests N` | `2000` | Hard request ceiling per target. |
| `--insecure` | off | Do not verify TLS certificates. |
| `--proxy URL` | — | Route every request through one proxy. |
| `--user-agent STRING` | `sqliscan/2.0 (+…)` | Override the default. |
| `--header 'K: V'` | — | Extra request header. Repeatable. |
| `--cookie 'a=1; b=2'` | — | Cookie header for the whole scan. |

A `500` is **not** retried. It is frequently the observable under test, and a
retry hides it. `trust_env` is off: a stray `HTTP_PROXY` in the shell will not
silently route your scan through somebody else's box — `--proxy` is the only
way to use one.

### Detection

| Flag | Default | Meaning |
| --- | --- | --- |
| `--time-based` | off | Also try DBMS sleep payloads. Slow: up to 9 extra requests per parameter. |
| `--time-delay S` | `5` | Seconds the sleep payloads ask for. |
| `--fail-on-finding {none,suspected,likely,confirmed}` | `none` | Exit `1` when a finding reaches this rung. |

### Output

| Flag | Meaning |
| --- | --- |
| `-f, --format {console,json,ndjson,csv,md}` | Report format. Default `console`. |
| `-o, --output PATH` | Write to `PATH` atomically. `-` is stdout. |
| `-q, --quiet` | Suppress the console report. A machine format asked for by name still reaches stdout. |
| `--no-colour` | Disable ANSI even on a TTY. |
| `--dry-run` | Print the resolved plan and send zero requests. It returns before any report is written, so `-o` is ignored. |
| `-v`, `--verbose` | Repeat for debug logging. Streams progress and findings to stderr. |
| `--log-file PATH` | Also write logs to `PATH`. |
| `--version` | Print the version and exit `0`. |

The report is written to a temp file in the destination directory and moved
into place with `os.replace`. A failed write leaves the previous report intact
and exits `2`. Colour is off automatically when stdout is not a TTY, and is
never written to a file.

Routing, in full:

| You asked for | It goes |
| --- | --- |
| nothing | the console report on stdout |
| `-q` | nothing |
| `-f json` (or `csv`/`md`/`ndjson`) | that format on stdout |
| `-o report.json -f json` | JSON in the file, nothing on stdout |
| `-o - -f json` | JSON on stdout |
| `-o report.txt` | the plain console report in the file |

`--dry-run` returns before any of this: it prints the plan to stdout and writes
no report, whatever `-f`/`-o` say.

`ndjson` is the streaming shape: one `meta` line, one `finding` line per
finding, one `summary` line. It is meant for `jq` and for pipelines that want
results before the scan ends.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The scan ran to completion. Findings may or may not exist. |
| `1` | `--fail-on-finding` was tripped. |
| `2` | Usage or input error — bad flag, bad target, unwritable report. |
| `3` | Internal error. |
| `130` | Interrupted with Ctrl-C. |

`0` means *the scan finished*. It does not mean *the target is clean*. If you
need the second question answered by the exit code, pass
`--fail-on-finding suspected`.

---

## Examples

**One parameter, one request, no crawl.**

```sh
sqliscan 'https://example.com/product.php?id=1' --depth 0
```

**Crawl two levels, submit forms, keep the traffic low.**

```sh
sqliscan example.com --forms --depth 2 --max-urls 50 --rate-limit 5
```

**CI gate: fail the build on anything at `LIKELY` or above.**

```sh
sqliscan "$TARGET" -f json -o scan.json --fail-on-finding likely
```

**Blind-injection sweep, with a longer delay budget.**

```sh
sqliscan example.com --time-based --time-delay 7 --max-requests 400
```

**Authenticated engagement, scoped to one host, writing Markdown.**

```sh
sqliscan https://app.example.com \
  --cookie 'session=...' \
  --header 'X-Engagement: 2026-11' \
  --allow-host api.example.com \
  --exclude '/admin' --exclude '/billing' \
  -f md -o report.md
```

**Read the plan before sending anything.**

```sh
sqliscan --dry-run example.com --forms --depth 4
```

```
sqliscan plan
  seed            https://example.com/
  depth           4
  max pages       200
  max requests    2000
  rate limit      10 req/s
  workers         8
  forms           yes
  time-based      no
  robots.txt      respected
  format          console
  ceiling check   ~1200 probe requests for 200 pages
  no request has been sent
```

---

## Using it against a programme

The tool exists for engagements you are authorised for. It sends SQL
metacharacters to every parameter it finds; doing that without permission is
illegal in most jurisdictions. The MIT licence disclaims all liability.

What the tool gives you to stay inside a programme's rules:

- `--rate-limit` — one shared token bucket for the whole scan, not one per
  thread. Set it to the programme's requests-per-second ceiling.
- `--max-requests` — a hard cap, counted before the socket opens. It does not
  depend on how many pages the crawl found.
- `--max-urls` — bounds the crawl so a big site cannot become a big scan.
- `--exclude` plus the built-in deny list — keeps state-changing GETs out.
- `--user-agent` — set the header a programme requires so your traffic is
  identifiable.
- `--dry-run` — see the plan, send nothing.

`sqliscan` does not exploit a finding and does not shell out to `sqlmap`. It
gives you the request, the response, the matched signature and the byte length;
whether that is an injectable parameter is a judgement you make.

---

## Library use

Every network call goes through a two-method `Transport` protocol, which is
also why the test suite never opens a socket.

```python
from sqliscan import ScanConfig, Scanner
from sqliscan.http import HttpxTransport, RetryingTransport

transport = RetryingTransport(HttpxTransport(user_agent="sqliscan/2.0"), retries=1)
try:
    report = Scanner(
        ScanConfig(target="https://example.com/item?id=1", depth=0),
        transport=transport,
    ).run()
finally:
    transport.close()

for finding in report.findings:
    print(finding.confidence.value, finding.point.parameter, finding.dbms)
```

`Scanner` never closes a transport it did not build. Drop down one more level
and `sqliscan.detect.Detector` will test a single `InjectionPoint`, or
`sqliscan.crawl.crawl` will give you pages without detecting anything.

Types are shipped (`py.typed`) and the package is checked with mypy `--strict`.

---

## Report shapes

`-f json` (real output, values trimmed for length)

```json
{
  "meta": {
    "target": "https://example.com/product?id=1",
    "tool": "sqliscan",
    "version": "2.0.0",
    "started_at": "2026-11-12T10:06:15.137Z",
    "finished_at": "2026-11-12T10:06:15.323Z",
    "options": {
      "depth": 0,
      "max_urls": 200,
      "max_requests": 2000,
      "rate_limit": 10.0,
      "forms": false,
      "time_based": false,
      "time_delay": 5,
      "respect_robots": true,
      "include_subdomains": false,
      "allow_hosts": [],
      "exclude": []
    }
  },
  "stats": {
    "pages_fetched": 1,
    "pages_failed": 0,
    "urls_discovered": 0,
    "forms_discovered": 0,
    "parameters_found": 1,
    "robots_disallowed": 0,
    "truncated": false
  },
  "summary": {
    "findings": 1,
    "confirmed": 1,
    "likely": 0,
    "suspected": 0,
    "points_tested": 1
  },
  "findings": [
    {
      "confidence": "confirmed",
      "kind": "error",
      "dbms": "MySQL",
      "payload": "'",
      "rationale": "An error signature appeared only after the payload was applied, did not appear for the escaped control, and reproduced on a repeat request.",
      "point": {
        "method": "GET",
        "url": "https://example.com/product?id=1",
        "location": "query",
        "parameter": "id",
        "value": "1"
      },
      "evidence": [
        {
          "request": "GET /product?id=1%27 HTTP/1.1",
          "payload": "1'",
          "status": 500,
          "length": 174,
          "content_type": "text/html; charset=utf-8",
          "elapsed_ms": 43.873,
          "matched": [
            "You have an error in your SQL syntax",
            "check the manual that corresponds to your (?:MariaDB|MySQL) server version"
          ],
          "excerpt": "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right s"
        },
        {
          "request": "GET /product?id=1%27%27 HTTP/1.1",
          "payload": "1''",
          "status": 200,
          "length": 37,
          "content_type": "text/html; charset=utf-8",
          "elapsed_ms": 43.299,
          "matched": [],
          "excerpt": ""
        }
      ]
    }
  ],
  "points": [
    {
      "method": "GET",
      "url": "https://example.com/product?id=1",
      "location": "query",
      "parameter": "id",
      "value": "1"
    }
  ]
}
```

`evidence` carries every request the verdict rests on: the probe, the escaped
control, and the repeat. An error-based `CONFIRMED` finding therefore always
shows two entries with a `matched` signature and one without.

`-f csv` columns, in this order:

```
confidence,kind,dbms,method,url,location,parameter,payload,status,length,excerpt
```

`-f ndjson` emits three shapes, one JSON object per line: `{"meta": …}`,
`{"finding": …}` (repeated), and a final
`{"summary": {"findings": …, "points_tested": …, "stats": {…}}}`.

Renaming a JSON key or a CSV column is a breaking change and is noted in
`CHANGELOG.md`.

---

## Development

```sh
python -m pip install -e ".[dev]"
pytest -q --cov=sqliscan --cov-report=term-missing
ruff check src tests sqli.py
mypy
```

`make check` runs all three. There are 339 tests and no test opens a socket:
`tests/helpers.py` provides a scripted `Transport`, and `HttpxTransport` itself
is exercised through `httpx.MockTransport`, so the client configuration, the
bounded body read and the error wrapping are real while the wire is not.

The `sqli.py` file at the repository root is a compatibility shim for the pre-2.0
command line. It translates `-d/--domain`, `--max-depth`, `--threads`,
`--verify-ssl` and `--log-level` onto the packaged CLI, warns on stderr, and
will not receive new flags. Use `sqliscan`.

## Licence

MIT — see `LICENSE`.

Security reports: `SECURITY.md`. Contributing: `CONTRIBUTING.md`.
Changelog, including every defect the rewrite fixed: `CHANGELOG.md`.
