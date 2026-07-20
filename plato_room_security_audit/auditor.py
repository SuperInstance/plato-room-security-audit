"""
Security audit heuristics for the Security Audit Room.

Each check is a pure function that takes the PR diff text and returns a
CheckResult.  Checks are intentionally simple — no LLM, no AST parsing.
They catch the 80% of security issues that pattern matching handles well.

To add a new check: write a function decorated with @check, or append
to _ALL_CHECKS manually.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class CheckResult:
    """Result of a single security check."""
    check_id: str
    name: str
    passed: bool
    message: str
    severity: str = "info"  # info, warning, error, critical
    file_hints: list[str] = field(default_factory=list)
    cwe: str = ""  # CWE reference (e.g., "CWE-89")


CheckFunc = Callable[[str], CheckResult]
_ALL_CHECKS: list[CheckFunc] = []


def check(func: CheckFunc) -> CheckFunc:
    """Register a check function."""
    _ALL_CHECKS.append(func)
    return func


# ─── Vulnerability patterns ──────────────────────────────────

# SQL injection patterns
_SQL_INJECTION_PATTERNS = [
    re.compile(r"execute\s*\(\s*['\"].*\+.*['\"]\s*\)", re.IGNORECASE),
    re.compile(r"execute\s*\(\s*f['\"]", re.IGNORECASE),
    re.compile(r"\%\s*\(.*\)\s*.*execute", re.IGNORECASE),
    re.compile(r"cursor\.execute.*\+.*request", re.IGNORECASE),
    re.compile(r"query\s*=\s*['\"].*select.*\+.*['\"]", re.IGNORECASE),
    re.compile(r"query\s*=\s*['\"].*insert.*\+.*['\"]", re.IGNORECASE),
    re.compile(r"query\s*=\s*['\"].*update.*\+.*['\"]", re.IGNORECASE),
    re.compile(r"query\s*=\s*['\"].*delete.*\+.*['\"]", re.IGNORECASE),
]

# XSS patterns
_XSS_PATTERNS = [
    re.compile(r"innerHTML\s*=\s*['\"]?\s*[{(]", re.IGNORECASE),
    re.compile(r"innerHTML\s*=\s*.*\+", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(\s*.*request", re.IGNORECASE),
    re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
    re.compile(r"\{\{.*\|.*safe\s*\}\}", re.IGNORECASE),  # Jinja2 unsafe filter
    re.compile(r"<script.*>.*\{.*\}", re.IGNORECASE),
    re.compile(r"outerHTML\s*=", re.IGNORECASE),
    re.compile(r"insertAdjacentHTML\s*\(", re.IGNORECASE),
]

# Path traversal patterns
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r'\.\./\.\./', re.IGNORECASE),
    re.compile(r'\.\.\\\\\.\.\\\\', re.IGNORECASE),
    re.compile(r'open\s*\(\s*.*request\.', re.IGNORECASE),
    re.compile(r'open\s*\(\s*.*input\.', re.IGNORECASE),
    re.compile(r'open\s*\(\s*.*\+', re.IGNORECASE),
    re.compile(r'read_file\s*\(\s*.*request\.', re.IGNORECASE),
    re.compile(r'os\.path\.join\s*\(\s*.*request\.', re.IGNORECASE),
    re.compile(r'\.\./.*passwd', re.IGNORECASE),
    re.compile(r'\.\./.*shadow', re.IGNORECASE),
    re.compile(r'\.\./.*etc/', re.IGNORECASE),
]

# Command injection patterns
_COMMAND_INJECTION_PATTERNS = [
    re.compile(r"os\.system\s*\(.*\+", re.IGNORECASE),
    re.compile(r"os\.system\s*\(.*request\.", re.IGNORECASE),
    re.compile(r"os\.system\s*\(.*input", re.IGNORECASE),
    re.compile(r"os\.system\s*\(.*f['\"]", re.IGNORECASE),
    re.compile(r"subprocess\..*shell\s*=\s*True", re.IGNORECASE),
    re.compile(r"subprocess\.call\s*\(.*\+", re.IGNORECASE),
    re.compile(r"subprocess\.run\s*\(.*\+", re.IGNORECASE),
    re.compile(r"Popen\s*\(.*shell\s*=\s*True", re.IGNORECASE),
    re.compile(r"commands\.getoutput\s*\(", re.IGNORECASE),
    re.compile(r"popen\s*\(.*\+", re.IGNORECASE),
]

# Critical eval patterns (user input reaching eval/exec)
_EVAL_PATTERNS = [
    re.compile(r'\beval\s*\(\s*.*request\.', re.IGNORECASE),
    re.compile(r'\beval\s*\(\s*.*input', re.IGNORECASE),
    re.compile(r'\beval\s*\(\s*[^\'"]*\+', re.IGNORECASE),  # eval with concatenation (not inside string)
    re.compile(r'\bexec\s*\(\s*.*request\.', re.IGNORECASE),
    re.compile(r'\bexec\s*\(\s*.*input', re.IGNORECASE),
    re.compile(r'\bexec\s*\(\s*.*\+', re.IGNORECASE),
    re.compile(r'\beval\s*\(\s*open\s*\(', re.IGNORECASE),
]

# Secret patterns (comprehensive)
_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "CWE-798"),
    (re.compile(r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]"), "AWS Secret Key", "CWE-798"),
    (re.compile(r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"][-A-Za-z0-9_/+=]{16,}['\"]"), "API Key / Token", "CWE-798"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key block", "CWE-321"),
    (re.compile(r"(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"), "DB connection string with credentials", "CWE-798"),
    (re.compile(r"xox[bpoa]-[0-9A-Za-z-]{10,48}"), "Slack token", "CWE-798"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"), "GitHub token", "CWE-798"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT token", "CWE-798"),
    (re.compile(r"(?i)password\s*[:=]\s*['\"][^\s'\"]{6,}['\"]"), "Hardcoded password", "CWE-259"),
    (re.compile(r"(?i)secret\s*[:=]\s*['\"][^\s'\"]{6,}['\"]"), "Hardcoded secret", "CWE-798"),
]

# Insecure crypto patterns
_INSECURE_CRYPTO_PATTERNS = [
    re.compile(r"hashlib\.md5\s*\(", re.IGNORECASE),
    re.compile(r"hashlib\.sha1\s*\(", re.IGNORECASE),
    re.compile(r"\bDES\b.*encrypt", re.IGNORECASE),
    re.compile(r"\bECB\b.*mode", re.IGNORECASE),
    re.compile(r"Cipher.*DES", re.IGNORECASE),
    re.compile(r"random\.random\s*\(\s*\).*token", re.IGNORECASE),
    re.compile(r"\brandom\b.*password", re.IGNORECASE),
    re.compile(r"\brandom\b.*secret", re.IGNORECASE),
    re.compile(r"\brandom\b.*key", re.IGNORECASE),
]

# Insecure random
_INSECURE_RANDOM_PATTERNS = [
    re.compile(r"\brandom\.random\b", re.IGNORECASE),
    re.compile(r"\brandom\.randint\b", re.IGNORECASE),
    re.compile(r"\brandom\.choice\b", re.IGNORECASE),
    re.compile(r"Math\.random", re.IGNORECASE),
]

# Debug enabled
_DEBUG_PATTERNS = [
    re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"app\.debug\s*=\s*True", re.IGNORECASE),
    re.compile(r"app\.run\s*\(.*debug\s*=\s*True", re.IGNORECASE),
]

# HTTP (not HTTPS)
_HTTP_PATTERNS = [
    re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com)", re.IGNORECASE),
]

# Disabled security controls
_DISABLED_SECURITY_PATTERNS = [
    re.compile(r"#\s*noqa.*security", re.IGNORECASE),
    re.compile(r"#\s*type:\s*ignore", re.IGNORECASE),
    re.compile(r"@SuppressWarnings", re.IGNORECASE),
    re.compile(r"#\s*pylint:\s*disable=.*security", re.IGNORECASE),
    re.compile(r"#\s*bandit:\s*disable", re.IGNORECASE),
    re.compile(r"#\s*nosec", re.IGNORECASE),
    re.compile(r"#\s*nosecB\d+", re.IGNORECASE),
]

# Sensitive file patterns
_SENSITIVE_FILES = [
    ".env", "secrets", "id_rsa", "id_ed25519", ".pem", ".key",
    ".crt", ".p12", ".pfx", "credentials", "password", "token",
    ".htpasswd", "shadow", "sudoers",
]

# Weak password hash
_WEAK_HASH_PATTERNS = [
    re.compile(r"hashlib\.md5\s*\(.*password", re.IGNORECASE),
    re.compile(r"hashlib\.sha1\s*\(.*password", re.IGNORECASE),
    re.compile(r"\.crypt\s*\(", re.IGNORECASE),
    re.compile(r"crypt\.crypt\s*\(", re.IGNORECASE),
]


# ─── Helper ──────────────────────────────────────────────────

def _get_current_file(line: str, current: str | None) -> str | None:
    """Extract filename from diff --git line."""
    if line.startswith("diff --git"):
        parts = line.split()
        if len(parts) >= 4:
            return parts[-1].lstrip("b/")
    return current


# ─── Checks ──────────────────────────────────────────────────

@check
def check_sql_injection(diff: str) -> CheckResult:
    """Detect SQL injection vulnerabilities."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _SQL_INJECTION_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="sql_injection",
            name="SQL Injection",
            passed=False,
            message=f"{len(findings)} SQL injection pattern(s) detected. "
                    f"Use parameterized queries instead of string concatenation.",
            severity="critical",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-89",
        )
    return CheckResult(
        check_id="sql_injection",
        name="SQL Injection",
        passed=True,
        message="No SQL injection patterns detected.",
    )


@check
def check_xss(diff: str) -> CheckResult:
    """Detect Cross-Site Scripting (XSS) vulnerabilities."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _XSS_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="xss",
            name="Cross-Site Scripting (XSS)",
            passed=False,
            message=f"{len(findings)} XSS pattern(s) detected. "
                    f"Sanitize/escape user input before rendering.",
            severity="critical",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-79",
        )
    return CheckResult(
        check_id="xss",
        name="Cross-Site Scripting (XSS)",
        passed=True,
        message="No XSS patterns detected.",
    )


@check
def check_path_traversal(diff: str) -> CheckResult:
    """Detect path traversal vulnerabilities."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _PATH_TRAVERSAL_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="path_traversal",
            name="Path Traversal",
            passed=False,
            message=f"{len(findings)} path traversal pattern(s) detected. "
                    f"Validate and sanitize file paths.",
            severity="critical",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-22",
        )
    return CheckResult(
        check_id="path_traversal",
        name="Path Traversal",
        passed=True,
        message="No path traversal patterns detected.",
    )


@check
def check_hardcoded_secrets(diff: str) -> CheckResult:
    """Detect hardcoded secrets and credentials."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern, label, cwe in _SECRET_PATTERNS:
                match = pattern.search(content)
                if match:
                    masked = content[:match.start()] + "***REDACTED***" + content[match.end():]
                    findings.append((current_file or "?", label, masked.strip(), cwe))

    if findings:
        unique_labels = {f[1] for f in findings}
        return CheckResult(
            check_id="hardcoded_secrets",
            name="Hardcoded Secrets",
            passed=False,
            message=f"Potential secrets detected ({', '.join(unique_labels)}). "
                    f"Use environment variables or a secrets manager.",
            severity="critical",
            file_hints=list({f[0] for f in findings})[:5],
            cwe="CWE-798",
        )
    return CheckResult(
        check_id="hardcoded_secrets",
        name="Hardcoded Secrets",
        passed=True,
        message="No secret-like patterns detected.",
    )


@check
def check_command_injection(diff: str) -> CheckResult:
    """Detect command injection vulnerabilities."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _COMMAND_INJECTION_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="command_injection",
            name="Command Injection",
            passed=False,
            message=f"{len(findings)} command injection pattern(s) detected. "
                    f"Avoid os.system/shell=True with user input.",
            severity="critical",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-78",
        )
    return CheckResult(
        check_id="command_injection",
        name="Command Injection",
        passed=True,
        message="No command injection patterns detected.",
    )


@check
def check_critical_eval(diff: str) -> CheckResult:
    """Detect critical eval/exec usage with user input."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _EVAL_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="critical_eval",
            name="Critical eval()/exec() Usage",
            passed=False,
            message=f"{len(findings)} dangerous eval/exec pattern(s) detected. "
                    f"eval() and exec() with user input enable arbitrary code execution.",
            severity="critical",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-95",
        )
    return CheckResult(
        check_id="critical_eval",
        name="Critical eval()/exec() Usage",
        passed=True,
        message="No dangerous eval/exec patterns detected.",
    )


@check
def check_insecure_random(diff: str) -> CheckResult:
    """Detect use of insecure random number generators in security context."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            # Only flag when random is used in security context
            context_lower = content.lower()
            is_security_context = any(
                kw in context_lower for kw in
                ["token", "password", "secret", "key", "session", "csrf", "auth", "nonce", "salt"]
            )
            if is_security_context:
                for pattern in _INSECURE_RANDOM_PATTERNS:
                    if pattern.search(content):
                        findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="insecure_random",
            name="Insecure Random Number Generator",
            passed=False,
            message=f"{len(findings)} insecure random usage in security context. "
                    f"Use `secrets` module or `os.urandom()`.",
            severity="error",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-330",
        )
    return CheckResult(
        check_id="insecure_random",
        name="Insecure Random Number Generator",
        passed=True,
        message="No insecure random usage in security contexts.",
    )


@check
def check_insecure_crypto(diff: str) -> CheckResult:
    """Detect insecure cryptographic algorithms."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _INSECURE_CRYPTO_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="insecure_crypto",
            name="Insecure Cryptography",
            passed=False,
            message=f"{len(findings)} insecure crypto pattern(s) detected. "
                    f"Use SHA-256+, AES-GCM, and `secrets` for security-sensitive operations.",
            severity="error",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-327",
        )
    return CheckResult(
        check_id="insecure_crypto",
        name="Insecure Cryptography",
        passed=True,
        message="No insecure crypto patterns detected.",
    )


@check
def check_debug_enabled(diff: str) -> CheckResult:
    """Detect DEBUG=True in settings."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _DEBUG_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="debug_enabled",
            name="Debug Mode Enabled",
            passed=False,
            message=f"{len(findings)} DEBUG=True pattern(s) detected. "
                    f"Disable debug in production.",
            severity="warning",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-489",
        )
    return CheckResult(
        check_id="debug_enabled",
        name="Debug Mode Enabled",
        passed=True,
        message="No debug mode patterns detected.",
    )


@check
def check_http_not_https(diff: str) -> CheckResult:
    """Detect HTTP URLs that should use HTTPS."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            # Skip comments
            stripped = content.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern in _HTTP_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="http_not_https",
            name="HTTP Instead of HTTPS",
            passed=False,
            message=f"{len(findings)} insecure HTTP URL(s) detected. "
                    f"Use HTTPS for production endpoints.",
            severity="warning",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-319",
        )
    return CheckResult(
        check_id="http_not_https",
        name="HTTP Instead of HTTPS",
        passed=True,
        message="No insecure HTTP URLs detected.",
    )


@check
def check_disabled_security(diff: str) -> CheckResult:
    """Detect disabled security controls and linter suppressions."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _DISABLED_SECURITY_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="disabled_security",
            name="Disabled Security Controls",
            passed=False,
            message=f"{len(findings)} security control suppression(s) detected. "
                    f"Review whether suppression is justified.",
            severity="warning",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-693",
        )
    return CheckResult(
        check_id="disabled_security",
        name="Disabled Security Controls",
        passed=True,
        message="No security control suppressions detected.",
    )


@check
def check_sensitive_file_exposure(diff: str) -> CheckResult:
    """Detect changes to sensitive files (keys, credentials, configs)."""
    touched = []
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                fname = parts[-1].lstrip("b/")
                for sensitive in _SENSITIVE_FILES:
                    if sensitive in fname.lower():
                        touched.append(fname)
                        break

    if touched:
        return CheckResult(
            check_id="sensitive_file_exposure",
            name="Sensitive File Exposure",
            passed=False,
            message=f"Sensitive file(s) modified: {', '.join(touched)}. "
                    f"Ensure no secrets are committed.",
            severity="error",
            file_hints=touched,
            cwe="CWE-200",
        )
    return CheckResult(
        check_id="sensitive_file_exposure",
        name="Sensitive File Exposure",
        passed=True,
        message="No sensitive files in diff.",
    )


@check
def check_weak_password_hash(diff: str) -> CheckResult:
    """Detect weak password hashing algorithms."""
    findings = []
    current_file = None
    for line in diff.splitlines():
        current_file = _get_current_file(line, current_file)
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            for pattern in _WEAK_HASH_PATTERNS:
                if pattern.search(content):
                    findings.append(f"{current_file}: `{content.strip()[:80]}`")

    if findings:
        return CheckResult(
            check_id="weak_password_hash",
            name="Weak Password Hashing",
            passed=False,
            message=f"{len(findings)} weak hash pattern(s) for passwords. "
                    f"Use bcrypt, scrypt, or Argon2.",
            severity="error",
            file_hints=[f.split(":")[0] for f in findings][:5],
            cwe="CWE-916",
        )
    return CheckResult(
        check_id="weak_password_hash",
        name="Weak Password Hashing",
        passed=True,
        message="No weak password hashing detected.",
    )


# ─── Orchestration ───────────────────────────────────────────

def run_all_checks(diff: str) -> list[CheckResult]:
    """Run all registered security checks and return results."""
    results = []
    for func in _ALL_CHECKS:
        try:
            result = func(diff)
            if not isinstance(result, CheckResult):
                # Check returned None or invalid type - create error result
                results.append(CheckResult(
                    check_id=func.__name__,
                    name=func.__name__,
                    passed=False,  # Failed-safe: block on check crash
                    message=f"Check returned invalid result: {type(result).__name__}",
                    severity="info",
                ))
            else:
                results.append(result)
        except Exception as exc:
            results.append(CheckResult(
                check_id=func.__name__,
                name=func.__name__,
                passed=False,  # Failed-safe: block on check crash
                message=f"Check errored: {exc}",
                severity="info",
            ))
    return results


def run_check(check_id: str, diff: str) -> CheckResult | None:
    """Run a single check by ID. Returns None if check_id not found."""
    for func in _ALL_CHECKS:
        try:
            result = func(diff)
            if isinstance(result, CheckResult) and result.check_id == check_id:
                return result
            # If check returned None or invalid type but has matching name, try next
            if hasattr(func, '__name__') and func.__name__ == check_id:
                # Found the check but it returned invalid result
                return CheckResult(
                    check_id=check_id,
                    name=check_id,
                    passed=True,
                    message=f"Check returned invalid result type",
                    severity="info",
                )
        except Exception as exc:
            # Check if this was the requested check by name
            if hasattr(func, '__name__') and func.__name__ == check_id:
                # Found the check but it crashed - return error instead of None
                return CheckResult(
                    check_id=check_id,
                    name=check_id,
                    passed=False,  # Failed-safe: block on check crash
                    message=f"Check errored: {exc}",
                    severity="info",
                )
    return None
