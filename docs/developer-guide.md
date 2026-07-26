# Developer guide

## Layout

- `sentinel/cli.py` provides the Typer interface.
- `sentinel/scanner.py` schedules modules in traffic-aware stages.
- `sentinel/modules/` contains independently testable non-destructive checks.
- `sentinel/http_client.py` enforces same-host HTTP scope, rate limiting, bounded retries, and redirect checks.
- `sentinel/reports/` owns all report renderers.
- `tests/` contains no-network unit tests.

## Development workflow

```bash
python -m pip install -e '.[dev]'
make format
make check
```

Modules subclass `ScanModule`, set a stable `name`, and return `ModuleResult`. They must not raise for expected target/network conditions; the base class turns unexpected exceptions into module-local errors so partial reports remain useful.

All new traffic must go through `SafeHttpClient` or be explicitly bounded and documented (as with the TCP-connect module). Do not add authentication attempts, state-changing requests, WAF bypasses, credential testing, browser automation that changes state, or exploit validation.

## Test policy

Tests must not scan external systems. Mock the HTTP client, DNS resolver, socket operations, and third-party data. Add a regression test with each bug fix and keep code compatible with the configured Ruff, Black, and mypy checks.

