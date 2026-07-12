# PLATO Security Audit Room

> Automated security auditing as a **PLATO engine block** — the second room in the SuperInstance ecosystem.

[![Tests](https://github.com/SuperInstance/plato-room-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/SuperInstance/plato-room-security-audit/actions/workflows/ci.yml)

## What is this?

A **PLATO Room** that runs security audits on code changes. It follows the PLATO architecture:

| Concept | In this room | |
|---------|-------------|---|
| **Sensors** | Diff vulnerability patterns, secret detection, dependency scan, file risk scoring | Pull data from GitHub on each tick |
| **Actuators** | Post security review, block merge, apply security labels | Push decisions back to GitHub |
| **Tick loop** | Configurable rate (default 0.1 Hz = every 10s) | Polls for PR state changes |
| **Alarms** | `sql_injection`, `xss_detected`, `path_traversal`, `hardcoded_secrets`, `command_injection`, `critical_eval` | Fire on policy conditions |
| **History** | Ring buffer of last 1000 ticks | Full audit trail via `history N` command |
| **Policies** | FLUX bytecode rules in `policies/` | Declarative, versioned, reviewable |

The room exposes the standard **PLATO wire protocol** — any PLATO client can connect, read sensors, check alarms, and trigger actuators.

## Quick Start

### Standalone (single audit)

```bash
export GITHUB_TOKEN=ghp_your_token_here
python -m plato_room_security_audit.room --repo owner/repo --pr 42 --once
```

Prints a formatted security audit and exits.

### Long-lived server

```bash
export GITHUB_TOKEN=ghp_your_token_here
python -m plato_room_security_audit.room --repo owner/repo --watch --port 1235
```

Then connect with any PLATO client:

```python
from plato_core.protocol import PlatoClient

with PlatoClient.connect("localhost", 1235) as client:
    welcome = client.recv_response()
    print(f"Connected to {welcome.room_id}")

    client.send("tick")
    tick = client.recv_response()
    print(f"Security state: {tick.data}")

    client.send("alarm list")
    alarms = client.recv_response()
    for a in alarms.alarms:
        print(f"  {a.id}: {a.state}")
```

### GitHub Action

```yaml
# .github/workflows/security-audit.yml
name: PLATO Security Audit
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install plato-core plato-room-security-audit
      - run: |
          python -m plato_room_security_audit.room \
            --repo ${{ github.repository }} \
            --pr ${{ github.event.pull_request.number }} \
            --once
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Security Checks

All checks are **heuristic** (no LLM, no AST parsing) — fast, deterministic, and auditable.

| Check | What it catches | Severity |
|-------|----------------|----------|
| `sql_injection` | String concatenation in SQL execute() calls, f-string queries | critical |
| `xss` | Unescaped output in templates, `innerHTML` with variables | critical |
| `path_traversal` | `../` patterns in file paths, unsanitized `open()` calls | critical |
| `hardcoded_secrets` | AWS keys, API keys, private keys, JWTs, Slack tokens, DB URLs | critical |
| `command_injection` | `os.system()`, `subprocess` with `shell=True`, `eval()` with user input | critical |
| `insecure_random` | `random` module for security-sensitive contexts | error |
| `insecure_crypto` | MD5, SHA1, DES, ECB mode for crypto operations | error |
| `debug_enabled` | `DEBUG = True` in settings files | warning |
| `http_not_https` | HTTP (not HTTPS) URLs in source code | warning |
| `disabled_security` | Comments disabling security checks, `# noqa`, `@SuppressWarnings` | warning |
| `sensitive_file_exposure` | Changes to `.env`, secrets files, key files | error |
| `weak_password_hash` | `hashlib.md5`/`sha1` for password hashing | error |

### Adding a check

```python
# auditor.py
@check
def check_insecure_deserialization(diff: str) -> CheckResult:
    """Detect unsafe deserialization patterns."""
    for line in diff.splitlines():
        if line.startswith("+") and "pickle.loads" in line:
            return CheckResult(
                check_id="insecure_deserialization",
                name="Insecure Deserialization",
                passed=False,
                message="pickle.loads() can execute arbitrary code",
                severity="critical",
            )
    return CheckResult(
        check_id="insecure_deserialization",
        name="Insecure Deserialization",
        passed=True,
        message="No unsafe deserialization detected.",
    )
```

The `@check` decorator registers it automatically.

## Audit Reports

The `report.py` module generates structured markdown reports with severity ratings:

```python
from plato_room_security_audit.auditor import run_all_checks
from plato_room_security_audit.report import generate_report, generate_short_summary

results = run_all_checks(diff)

# Full markdown report with CVSS-style severity ratings
report = generate_report(results, repo="owner/repo", pr_number=42, author="alice")

# One-line summary for status checks
summary = generate_short_summary(results)
# → "PLATO Security: 10/12 checks passed — BLOCK_MERGE"
```

## Configuration

Configure checks via `plato-security.yml` in your repo root:

```yaml
checks:
  sql_injection: enabled
  xss: enabled
  path_traversal: enabled
  hardcoded_secrets: enabled
  command_injection: enabled
  insecure_random: enabled
  insecure_crypto: enabled
  debug_enabled: warn
  http_not_https: warn
  disabled_security: warn
  sensitive_file_exposure: enabled
  weak_password_hash: enabled
```

Options: `enabled`, `disabled`, `warn` (report but don't block).

## FLUX Policies

Policies live in `policies/*.flx`:

```flux
POLICY no_sql_injection {
    SENSE  sql_injection_count
    GUARD   sql_injection_count > 0
    ALARM   severity=critical
    ACTUATE block_merge
    EMIT    "SQL injection vulnerability detected"
}
```

### Policy files

| File | Triggers when |
|------|--------------|
| `no_sql_injection.flx` | SQL injection patterns detected in diff |
| `no_command_injection.flx` | `os.system()`, `eval()`, `shell=True` with interpolation |
| `no_hardcoded_secrets.flx` | Secret-like patterns in added lines |
| `no_path_traversal.flx` | Path traversal patterns in file operations |

## Architecture

```
                    PLATO Wire Protocol
                    (TCP, JSON lines)
                           │
          ┌────────────────┼────────────────┐
          │                │                │
     tick command     alarm list      actuator cmd
          │                │                │
          ▼                ▼                ▼
    ┌─────────────────────────────────────────────┐
    │           Security Audit Room               │
    │                                             │
    │  Sensors              Actuators             │
    │  ├─ vuln_patterns     ├─ post_audit         │
    │  ├─ secret_scan       ├─ block_merge        │
    │  ├─ risk_score        └─ apply_label        │
    │  └─ dependency_check                        │
    │                                             │
    │  Alarms                                    │
    │  ├─ sql_injection (sql_injection_count > 0)│
    │  ├─ xss_detected (xss_count > 0)           │
    │  ├─ path_traversal (traversal_count > 0)   │
    │  ├─ hardcoded_secrets (secret_count > 0)   │
    │  ├─ command_injection (cmd_injection > 0)  │
    │  └─ critical_eval (eval_count > 0)         │
    │                                             │
    │  History (1000-tick ring buffer)            │
    └─────────────────────────────────────────────┘
                           │
                    GitHub API
                           │
          ┌────────────────┼────────────────┐
          │                │                │
     Fetch diff      Fetch metadata    Post audit
     Scan patterns   Fetch file list   Block merge
```

## Testing

```bash
pip install -e ".[test]"
pytest tests/ -v
```

All tests use simulated data — no GitHub API calls needed.

## License

MIT — see [LICENSE](LICENSE).

## Part of

[SuperInstance](https://github.com/SuperInstance) — the PLATO ecosystem.
