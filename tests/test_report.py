"""
Tests for the security audit report generator.

Run: python -m pytest tests/test_report.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plato_room_security_audit.auditor import CheckResult, run_all_checks
from plato_room_security_audit.report import generate_report, generate_short_summary
from plato_room_security_audit.github_client import GitHubClient


# ─── Fixtures ────────────────────────────────────────────────

SAMPLE_RESULTS_ALL_PASS = [
    CheckResult(check_id="test_check", name="Test Check", passed=True,
                message="All good", severity="info"),
    CheckResult(check_id="another", name="Another", passed=True,
                message="Fine", severity="info"),
]

SAMPLE_RESULTS_WITH_CRITICAL = [
    CheckResult(check_id="sql_injection", name="SQL Injection", passed=False,
                message="SQL injection detected", severity="critical",
                file_hints=["app/db.py"], cwe="CWE-89"),
    CheckResult(check_id="secrets", name="Hardcoded Secrets", passed=False,
                message="AWS key found", severity="critical",
                file_hints=["app/config.py"], cwe="CWE-798"),
    CheckResult(check_id="debug", name="Debug Enabled", passed=False,
                message="DEBUG=True found", severity="warning",
                file_hints=["settings.py"], cwe="CWE-489"),
    CheckResult(check_id="types", name="Type Hints", passed=True,
                message="OK", severity="info"),
]

SAMPLE_RESULTS_WARNINGS_ONLY = [
    CheckResult(check_id="http", name="HTTP URL", passed=False,
                message="Use HTTPS", severity="warning", cwe="CWE-319"),
    CheckResult(check_id="ok", name="OK Check", passed=True,
                message="Fine", severity="info"),
]

SAMPLE_FROM_VULNERABLE_DIFF = run_all_checks(
    GitHubClient(token="").fetch_pr_diff("owner", "repo", 1)
)


# ─── Tests ───────────────────────────────────────────────────

class TestGenerateReport:
    def test_returns_string(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert isinstance(report, str)

    def test_contains_header(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "PLATO Security Audit Report" in report

    def test_contains_summary_section(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "Summary" in report
        assert "Checks Run" in report

    def test_contains_risk_level(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "Risk Level" in report
        assert "CRITICAL" in report

    def test_risk_none_when_all_pass(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "NONE" in report

    def test_correct_pass_fail_counts(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "4" in report  # total
        assert "1" in report  # passed
        assert "3" in report  # failed

    def test_contains_findings_by_severity(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "Findings by Severity" in report
        assert "CRITICAL" in report

    def test_contains_cwe_references(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "CWE-89" in report
        assert "CWE-798" in report

    def test_contains_detailed_results(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "Detailed Results" in report
        assert "SQL Injection" in report

    def test_includes_file_hints(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "app/db.py" in report
        assert "app/config.py" in report

    def test_recommendation_approve_when_all_pass(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "APPROVE" in report

    def test_recommendation_block_merge_on_critical(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "BLOCK_MERGE" in report

    def test_recommendation_comment_on_warnings_only(self):
        report = generate_report(SAMPLE_RESULTS_WARNINGS_ONLY)
        assert "COMMENT" in report

    def test_includes_repo_and_pr_info(self):
        report = generate_report(
            SAMPLE_RESULTS_ALL_PASS,
            repo="owner/repo",
            pr_number=42,
            author="alice",
        )
        assert "owner/repo" in report
        assert "#42" in report
        assert "@alice" in report

    def test_works_with_vulnerable_diff_results(self):
        report = generate_report(SAMPLE_FROM_VULNERABLE_DIFF)
        assert "PLATO Security Audit Report" in report
        assert "Summary" in report

    def test_empty_results_dont_crash(self):
        report = generate_report([])
        assert isinstance(report, str)

    def test_failing_checks_sorted_before_passing(self):
        report = generate_report(SAMPLE_RESULTS_WITH_CRITICAL)
        pos_sql = report.find("SQL Injection")
        pos_types = report.find("Type Hints")
        assert pos_sql < pos_types

    def test_contains_footer(self):
        report = generate_report(SAMPLE_RESULTS_ALL_PASS)
        assert "PLATO Security Audit Room" in report
        assert "github.com/SuperInstance" in report


class TestGenerateShortSummary:
    def test_all_passed_summary(self):
        summary = generate_short_summary(SAMPLE_RESULTS_ALL_PASS)
        assert "2/2" in summary
        assert "APPROVE" in summary

    def test_with_critical_summary(self):
        summary = generate_short_summary(SAMPLE_RESULTS_WITH_CRITICAL)
        assert "1/4" in summary
        assert "BLOCK_MERGE" in summary

    def test_warnings_only_summary(self):
        summary = generate_short_summary(SAMPLE_RESULTS_WARNINGS_ONLY)
        assert "1/2" in summary
        assert "COMMENT" in summary

    def test_empty_results(self):
        summary = generate_short_summary([])
        assert "0/0" in summary
