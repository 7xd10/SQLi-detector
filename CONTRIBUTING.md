# Contributing

Thanks for looking. This is a small, single-maintainer project, so the most
useful contribution is a **reproduction**: a URL shape that the detector
misreads, the body it returned, and what it should have said instead.

## Before you start

```sh
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
pytest -q
```

`make check` runs the same three things CI runs: ruff, mypy strict, pytest.

## What this project will not accept

- A detection change that trades away the escaped control. The control request
  is the reason a page containing the words "SQL syntax error" is not a
  finding, and removing it makes the whole tool worse.
- A feature that reports a bare `VULNERABLE` / `SAFE` boolean. The confidence
  ladder (`CONFIRMED` / `LIKELY` / `SUSPECTED`) exists because "the server
  echoed a quote character" is not the same fact as "the parser failed".
- New runtime dependencies without a conversation first. The package has
  exactly one (`httpx`) and the crawl, HTML parse, robots handling and report
  writers are all standard library on purpose.
- Tests that open a socket. Every test in `tests/` talks to a scripted
  `Transport`; see `tests/helpers.py`.

## Design rules that are load-bearing

1. **Baseline first.** No signature counts unless it was absent from the
   unmodified request. `sqliscan.detect` subtracts; `sqliscan.payloads` only
   supplies patterns.
2. **Every error probe has a same-shape escaped control.** If the control trips
   the same signature, the input is being reflected and the pair is discarded.
3. **`Transport` is the only boundary to the network.** If you need a new HTTP
   behaviour, add it behind the protocol so the suite stays offline.
4. **Fail closed.** A failed read produces nothing, never stale data. A
   corrupted length is a refused request, not a hang.
5. **Exit codes are a contract.** `0` ran, `1` threshold tripped, `2` bad
   input, `3` internal error, `130` interrupted. Do not add a sixth.
6. **The report is a public interface.** Renaming a JSON key or a CSV column
   is a breaking change; note it in `CHANGELOG.md` under `### Changed`.

## Style

Ruff and mypy strict are not advisory here. `line-length = 88`,
`target-version = py39`, and `--strict` typing with no `Any` escaping into the
public surface. Comments explain *why* — the constraint, the failed case a
guard catches, where a constant came from. They do not restate the code.

Tests are named for the behaviour, not the function:
`test_error_based_discards_a_reflection`, not `test_detect_3`.

## Commits

Conventional commit prefixes, one topic per commit:

```
feat(detect): confirm time-based findings with a repeat request
fix(crawl): treat a redirect to a new path as the seed URL
docs(readme): document the exit-code contract
```

## Security issues

Do not open a public issue. See `SECURITY.md`.

## Licence

Contributions are MIT, matching the project.
