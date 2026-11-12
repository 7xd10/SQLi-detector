# Security policy

## Reporting a vulnerability in sqliscan

Email **alaouihichamiyoussef@gmail.com** with a subject line starting
`sqliscan security`. Do not open a public issue for a vulnerability.

Include the affected version (`sqliscan --version`), a minimal reproduction,
and the impact you believe it has. Expect an acknowledgement within 72 hours.
There is no bug bounty for this project; credit is given in the changelog
unless you ask otherwise.

Areas that count as a vulnerability in the scanner:

- Memory exhaustion or an unbounded thread count reachable from normal
  command-line input or from a hostile target's HTML.
- A crafted response (chunked encoding, huge `Content-Length`, a redirect loop)
  that crashes the process instead of being recorded as a failed request.
- Path traversal or arbitrary file overwrite through `-o/--output`.
- Terminal escape injection from an untrusted response body. Response text is
  attacker-controlled bytes and is rendered into a terminal.
- Request smuggling or a credential leak across hosts: the scanner must never
  resend your `--header` / `--cookie` values to a host outside the scan scope.
- Reading a report written by one user as another user through a predictable
  temporary file name.

A finding *by* the scanner against a third-party site is not a vulnerability
in the scanner.

## Using sqliscan against systems you do not own

`sqliscan` sends SQL metacharacters to every parameter it finds. Doing that
without authorisation is illegal in most jurisdictions and is grounds for
account termination with most hosting providers. The MIT licence disclaims all
liability; the responsibility is yours.

The tool supports the constraints a real engagement imposes:

- `--rate-limit N` caps requests per second across the whole scan.
- `--max-requests N` is a hard ceiling on total requests, counted before the
  socket opens.
- `--max-urls N` bounds the crawl, so a large site cannot turn into a wide
  scan by accident.
- `--exclude PATTERN` and the built-in deny list keep the crawler away from
  paths that change state on a GET (`/logout`, `/delete`, `/checkout`, ...).
- `--dry-run` prints exactly what would be requested and sends nothing.
- `--fail-on-finding` lets CI fail a run without parsing the report.

The scanner does not execute `sqlmap` and does not exploit a finding. It
reports the evidence a human needs to decide whether the injection is real.

## Supported versions

The latest minor release receives fixes. `1.x` (the single-file `sqli.py`) is
unsupported and will not receive security patches; upgrade to `2.x`.
