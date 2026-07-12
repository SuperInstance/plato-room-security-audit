"""
PLATO Room Security Audit — package init.
"""

# Support both package-relative and standalone imports
try:
    from .room import SecurityAuditRoom, BaseRoom
    from .auditor import run_all_checks, CheckResult
    from .github_client import GitHubClient
    from .report import generate_report, generate_short_summary
except ImportError:
    from room import SecurityAuditRoom, BaseRoom
    from auditor import run_all_checks, CheckResult
    from github_client import GitHubClient
    from report import generate_report, generate_short_summary

__version__ = "0.1.0"
__all__ = [
    "SecurityAuditRoom",
    "BaseRoom",
    "run_all_checks",
    "CheckResult",
    "GitHubClient",
    "generate_report",
    "generate_short_summary",
]
