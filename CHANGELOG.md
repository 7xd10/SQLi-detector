# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version
numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] — 2026-11-12

The 1.x scanner was a single 631-line file that reported a two-state
`VULNERABLE` / `SAFE` verdict from a substring match. That verdict was wrong
often enough to be worse than no verdict at all. 2.0 is a rewrite: a typed
package, a real detection model, and a test suite that never opens a socket.

### Why 1.x findings could not be trusted

Every defect below was read out of `sqli.py` at commit `bc5d7e5` before the
rewrite. They are listed because someone may still have a 2.0-era report and
wonder what changed underneath it.

**Detection**

- **No baseline request.** `_check_for_sql_errors` searched the response body
  for a signature and returned `VULNERABLE` on the first match. A documentation
  page, a blog post, or an error page that happened to contain the phrase
  "You have an error in your SQL syntax" was reported as an injection. There
  was no unmodified control to subtract against. *2.0 sends the request with
  the original value first and discards any signature that was already there.*
  The two committed screenshots from the 1.x README show the class of wrong
  answer this produced: `Response Code: 200` printed next to `VULNERABLE`, and
  the same `test` parameter reported `SAFE` for `;` and `VULNERABLE` for `';`
  one line apart —
  [`docs/legacy-false-positive-1.png`](docs/legacy-false-positive-1.png),
  [`docs/legacy-false-positive-2.png`](docs/legacy-false-positive-2.png).
- **No reflection control.** A page that echoed the payload back — a search
  result, a 400 page with the query in it — tripped the signature and was
  reported. *2.0 sends the escaped form of the same character (`'` → `''`) and
  discards the pair when the control trips the same signature.*
- **No repeat request.** A single flaky response was a finding. *2.0 re-sends
  the probe and downgrades `CONFIRMED` to `LIKELY` when it does not reproduce.*
- **Payloads were string-concatenated onto the original value.**
  `test_params[param_name] = [original_value + payload]`, so `1' AND '1'='1`
  against `id=1` became `id=11' AND '1'='1` — a syntax error at best, never the
  tautology the payload intended. `'))`, `\';` and the escaped-quote entry were
  mangled the same way. *2.0 substitutes the value, and boolean probes are
  emitted as complete expressions.*
- **The time-based payload could never fire.** `"1' AND SLEEP(5)--"` sat in
  `SQLI_PAYLOADS` with the comment `# Time-based (for future enhancement)`.
  Nothing measured elapsed time, so a successful blind injection looked
  identical to a normal response. *2.0 measures the response against a baseline
  and only reports a delay the repeat request also shows.*
- **`parse_qs` dropped blank values and collapsed repeats.** `?q=` produced no
  parameter to test; `?id=1&id=2` tested only `id=1`. *2.0 uses `parse_qsl`,
  keeps blanks, and substitutes every occurrence.*
- **`netloc` scope check was case- and port-sensitive.** `if parsed.netloc !=
  urlparse(self.base_url).netloc` rejected `HTTPS://EXAMPLE.COM/Path` and
  `https://example.com:443/`, and accepted nothing it should not have. *2.0
  compares lowercased hostnames, ignores the port, and is anchored so
  `example.com.evil.test` is out of scope.*

**Crawl**

- **The frontier was keyed on the full query string.** `visited_urls` held
  complete URLs, so `?page=1`, `?page=2`, `?sort=a` … were each a new page and
  a single site could produce thousands of fetches. There was no `--max-urls`.
- **Forms were collected and never submitted.** `BeautifulSoup` pulled `form`
  elements out of the page and `_scan_url` only ever looked at `urlparse(url)
  .query`. A login form or a POST search box was invisible to the scanner.
  *2.0 has `--forms`, which builds a real body per parameter, skips forms that
  upload files, and refuses out-of-scope actions.*
- **Redirect handling was inconsistent.** One request used
  `allow_redirects=False` and another `allow_redirects=True`, so the URL in the
  report and the URL that was tested could be different documents.
- **No rate limit.** `time.sleep(0.1)` per payload per parameter is not a
  request budget; it is a fixed delay that a `--threads` value could multiply
  past any programme's traffic ceiling. *2.0 paces the whole scan with a
  shared token-bucket `--rate-limit` and refuses requests past
  `--max-requests` before the socket opens.*

**Concurrency**

- **`--threads` was silently clamped.** `for i in range(min(self.max_threads,
  20))` started at most 20 threads, but the banner printed `self.max_threads`,
  so `--threads 100` reported 100 and ran 20.
- **`queue.join()` could block forever.** `_crawl_worker` called
  `task_done()` after `_crawl_page`, so an exception between the two left the
  unfinished-task count permanently non-zero; a shutdown request drained the
  queue without marking anything done. `self.urls_to_crawl.join()` then waited
  on a count that could never reach zero. *2.0 uses a bounded
  `ThreadPoolExecutor` and never joins an unbounded queue.*

**Lifecycle**

- **`logging.basicConfig` and `FileHandler('sql_scanner.log')` ran at import.**
  Importing the module to call one function created a log file in the current
  directory and reconfigured the root logger of whatever imported it.
  `colorama.init(autoreset=True)` ran at import too, which wraps `sys.stdout`
  globally.
- **`signal.signal(SIGINT, ...)` was installed from `__init__`.** A library
  constructing a scanner owned the process's Ctrl-C behaviour.
- **`except KeyboardInterrupt` was unreachable.** The installed signal handler
  set a flag and returned instead of raising, so the handler at the bottom of
  `main` never ran and `exit 130` was dead code.
- **`exit 1` conflated "found something" with "crashed".**
  `sys.exit(0 if total_vulnerabilities == 0 else 1)` and the bare
  `except Exception: sys.exit(1)` were the same code. *2.0 has five codes:
  `0` ran, `1` threshold tripped, `2` bad input, `3` internal error, `130`
  interrupted.*
- **The report filename came from the raw domain.** `scan_report_
  {self.domain.replace('://','_').replace('/','_')}.json` leaves the `:` in
  `https:__example.com`, which is an illegal filename character on Windows —
  the scan completed and then failed to save.
- **`pages_crawled` was an arbitrary slice of a set.**
  `list(self.visited_urls)[:100]` reports whichever hundred URLs hash first,
  in no particular order, as if they were the first hundred.
- **`--timeout` was typed `int`**, so `--timeout 2.5` was a parse error and
  every sub-second timeout was unreachable.

**Packaging**

- No `pyproject.toml`, no version, no console script, no license, no tests.
- `requirements.txt` pinned nothing and listed `PyYAML`, which the code never
  imported.
- The README documented `python sql_scanner.py` (a filename that does not exist
  in the repository), a `git clone` from `yourusername/advanced-sql-scanner`,
  and flags whose descriptions did not match the code.

### Added

- `sqliscan` package with a `sqliscan` console script and `python -m sqliscan`.
- Confidence ladder — `CONFIRMED`, `LIKELY`, `SUSPECTED` — carried through
  every report format. Nothing is reported as a bare boolean.
- Baseline subtraction, same-shape escaped control, and repeat-request
  confirmation for error-based detection.
- Boolean-based probing with numeric and string pairs, gated on the truthy
  response matching the baseline and diverging from the falsy one.
- Optional time-based probing (`--time-based`, `--time-delay`) that measures
  against a baseline and requires the delay to reproduce.
- Evidence capture per finding: request line, payload, status, byte length,
  content type, elapsed time, matched signatures, and a bounded body excerpt.
- Report formats: `console`, `json`, `ndjson`, `csv`, `md`.
- Atomic report writing — a temp file in the destination directory, then
  `os.replace`. A failed write leaves the previous report intact.
- `--dry-run`, which prints the resolved plan and sends zero requests.
- `--fail-on-finding {none,suspected,likely,confirmed}` for CI.
- `--exclude`, `--allow-host`, `--include-subdomains` for scope control, and a
  built-in deny list for paths that change state on a GET.
- `--rate-limit`, `--max-requests`, `--max-urls`, `--workers`.
- `py.typed` and a strict mypy configuration.
- 339 tests, no network access. Coverage is 99%, every statement covered.

### Changed

- Minimum Python is 3.9. The only runtime dependency is `httpx>=0.27,<0.29`.
- `sqli.py` is now a 100-line shim that translates the 1.x flags
  (`-d/--domain`, `--max-depth`, `--threads`, `--verify-ssl`, `--log-level`)
  onto the packaged CLI and warns on stderr. It is not the implementation.
- Any finding the 1.x scanner reported should be re-run. A 1.x `VULNERABLE`
  verdict with no baseline and no control is not evidence.
- `-q` suppresses the console report only. A machine format asked for by name
  (`-f json`, `-f csv`, `-f md`, `-f ndjson`) still reaches stdout, and
  `-o PATH` writes whichever format was asked for. Previously `-q` with no
  `-o` printed nothing at all, which made every non-console format unusable
  from a pipeline.
- `stats.parameters_found` is the number of distinct parameter names the scan
  actually tested, not just the form fields the crawl stumbled over. A seed URL
  with a query string used to report `parameters_found: 0` while reporting
  `points_tested: 1`.
- Colour is attached to the console report only when it goes to a TTY; a
  console report written to a file is plain.

---

## [1.0.0] — 2024

Single-file `sqli.py`. Recursive crawl, nine payloads, substring match against
a table of DBMS error strings, JSON export. No tests, no packaging.
