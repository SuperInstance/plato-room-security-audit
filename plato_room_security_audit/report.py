"""
Security audit report generator for the PLATO Security Audit Room.

Takes a list of CheckResult objects and produces a structured markdown report
with summary, per-check details, severity ratings, and an overall recommendation.
"""

from __future__ import annotations

from typing import Sequence

try:
    from .auditor import CheckResult
except ImportError:
    from auditor import CheckResult


# Severity ordering for recommendations
_SEVERITY_WEIGHT = {"critical": 4, "error": 3, "warning": 2, "info": 1}

# CVSS-style severity icons
_SEVERITY_ICON = {
    "critical": "🔴",
    "error": "🟠",
    "warning": "🟡",
    "info": "🔵",
}


def _recommendation(results: Sequence[CheckResult]) -> str:
    """Determine overall recommendation from check results."""
    failing = [r for r in results if not r.passed]
    if not failing:
        return "APPROVE"

    # Any critical → BLOCK_MERGE
    has_critical = any(r.severity == "critical" for r in failing)
    if has_critical:
        return "BLOCK_MERGE"

    # Any error → REQUEST_CHANGES
    has_error = any(r.severity == "error" for r in failing)
    if has_error:
        return "REQUEST_CHANGES"

    return "COMMENT"


def _icon(result: CheckResult) -> str:
    """Status icon for a check result."""
    if result.passed:
        return "✅"
    return _SEVERITY_ICON.get(result.severity, "❓")


def _risk_level(results: Sequence[CheckResult]) -> str:
    """Overall risk level based on findings."""
    failing = [r for r in results if not r.passed]
    if not failing:
        return "NONE"
    if any(r.severity == "critical" for r in failing):
        return "CRITICAL"
    if any(r.severity == "error" for r in failing):
        return "HIGH"
    if any(r.severity == "warning" for r in failing):
        return "MEDIUM"
    return "LOW"


def generate_report(
    results: Sequence[CheckResult],
    *,
    repo: str = "",
    pr_number: int | None = None,
    author: str = "",
) -> str:
    """Generate a full markdown security audit report.

    Args:
        results: List of CheckResult from run_all_checks().
        repo: Repository name (owner/repo) for the header.
        pr_number: PR number for the header.
        author: PR author for the header.

    Returns:
        Markdown-formatted report string.
    """
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    recommendation = _recommendation(results)
    risk_level = _risk_level(results)

    lines: list[str] = []

    # ── Header ──────────────────────────────────────────────
    lines.append("## 🔒 PLATO Security Audit Report\n")

    if repo or pr_number:
        header_parts = []
        if repo:
            header_parts.append(f"**Repo:** `{repo}`")
        if pr_number:
            header_parts.append(f"**PR:** #{pr_number}")
        if author:
            header_parts.append(f"**Author:** @{author}")
        lines.append(" | ".join(header_parts))
        lines.append("")

    # ── Risk badge ───────────────────────────────────────────
    risk_badges = {
        "CRITICAL": "🔴 **CRITICAL**",
        "HIGH": "🟠 **HIGH**",
        "MEDIUM": "🟡 **MEDIUM**",
        "LOW": "🔵 **LOW**",
        "NONE": "🟢 **NONE**",
    }
    lines.append(f"**Risk Level:** {risk_badges.get(risk_level, risk_level)}\n")

    # ── Summary ─────────────────────────────────────────────
    rec_icon = {"APPROVE": "✅", "BLOCK_MERGE": "🚫", "REQUEST_CHANGES": "⚠️", "COMMENT": "💬"}
    lines.append("### Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Checks Run | {total} |")
    lines.append(f"| Passed | {passed} ✅ |")
    lines.append(f"| Failed | {failed} ❌ |")
    lines.append(f"| Risk Level | {risk_level} |")
    lines.append(f"| Recommendation | {rec_icon.get(recommendation, '💬')} **{recommendation}** |")
    lines.append("")

    # ── Findings by severity ─────────────────────────────────
    failing = [r for r in results if not r.passed]
    if failing:
        lines.append("### Findings by Severity\n")

        for severity in ("critical", "error", "warning", "info"):
            sev_findings = [r for r in failing if r.severity == severity]
            if sev_findings:
                icon = _SEVERITY_ICON.get(severity, "❓")
                lines.append(f"#### {icon} {severity.upper()}\n")
                for r in sev_findings:
                    cwe_str = f" `{r.cwe}`" if r.cwe else ""
                    lines.append(f"- **{r.name}**{cwe_str}: {r.message}")
                    if r.file_hints:
                        hint_list = ", ".join(f"`{h}`" for h in r.file_hints)
                        lines.append(f"  - Files: {hint_list}")
                lines.append("")

    # ─── Detailed Results ────────────────────────────────────
    lines.append("### Detailed Results\n")

    sorted_results = sorted(
        results,
        key=lambda r: (
            r.passed,
            -_SEVERITY_WEIGHT.get(r.severity, 0),
        ),
    )

    for r in sorted_results:
        icon = _icon(r)
        lines.append(f"#### {icon} {r.name}")
        lines.append(f"\n- **Check ID:** `{r.check_id}`")
        lines.append(f"- **Status:** {'PASSED' if r.passed else 'FAILED'}")
        lines.append(f"- **Severity:** `{r.severity}`")
        if r.cwe:
            lines.append(f"- **CWE:** `{r.cwe}`")
        lines.append(f"- **Message:** {r.message}")
        if r.file_hints:
            hint_list = ", ".join(f"`{h}`" for h in r.file_hints)
            lines.append(f"- **Files:** {hint_list}")
        lines.append("")

    # ── Footer ──────────────────────────────────────────────
    lines.append("---")
    lines.append(
        "_Generated by [PLATO Security Audit Room]"
        "(https://github.com/SuperInstance/plato-room-security-audit)_"
    )

    return "\n".join(lines)


def generate_short_summary(results: Sequence[CheckResult]) -> str:
    """Generate a one-line summary suitable for PR status checks.

    Example: "PLATO Security: 10/12 checks passed — BLOCK_MERGE"
    """
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    rec = _recommendation(results)
    return f"PLATO Security: {passed}/{total} checks passed — {rec}"
