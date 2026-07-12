"""
Tests for the Security Audit Room's auditor heuristics.

Run: python -m pytest tests/test_auditor.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plato_room_security_audit.auditor import (
    run_all_checks,
    check_sql_injection,
    check_xss,
    check_path_traversal,
    check_hardcoded_secrets,
    check_command_injection,
    check_critical_eval,
    check_insecure_random,
    check_insecure_crypto,
    check_debug_enabled,
    check_http_not_https,
    check_disabled_security,
    check_sensitive_file_exposure,
    check_weak_password_hash,
)


# ─── Sample diffs ────────────────────────────────────────────

CLEAN_DIFF = """\
diff --git a/src/utils.py b/src/utils.py
index 1111111..2222222 100644
--- a/src/utils.py
+++ b/src/utils.py
@@ -10,6 +10,9 @@ def helper(x: int) -> str:
+def format_name(name: str) -> str:
+    return name.strip().title()
+
diff --git a/tests/test_utils.py b/tests/test_utils.py
new file mode 100644
--- /dev/null
+++ b/tests/test_utils.py
@@ -0,0 +1,5 @@
+def test_format_name():
+    assert format_name("  hello  ") == "Hello"
"""

VULNERABLE_DIFF = """\
diff --git a/app/auth.py b/app/auth.py
new file mode 100644
--- /dev/null
+++ b/app/auth.py
@@ -0,0 +1,25 @@
+import sqlite3
+import os
+import hashlib
+
+def login(username, password):
+    conn = sqlite3.connect("users.db")
+    cursor = conn.cursor()
+    query = "SELECT * FROM users WHERE username='" + username + "'"
+    cursor.execute(query)
+    return cursor.fetchone()
+
+API_KEY = "sk-1234567890abcdef1234567890abcdef"
+
+def run_command(user_input):
+    os.system("echo " + user_input)
+    eval(user_input)
+
+def hash_password(password):
+    return hashlib.md5(password.encode()).hexdigest()
+
+def read_file(filename):
+    return open("../../etc/passwd" + filename).read()
+
+SECRET_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
diff --git a/templates/profile.html b/templates/profile.html
new file mode 100644
--- /dev/null
+++ b/templates/profile.html
@@ -0,0 +1,5 @@
+<div id="profile">
+  <script>document.innerHTML = "{{ user_bio }}"</script>
+  <a href="http://example.com">Insecure link</a>
+</div>
"""

EMPTY_DIFF = ""


# ─── Tests ───────────────────────────────────────────────────

class TestSQLInjection:
    def test_detects_string_concat(self):
        result = check_sql_injection(VULNERABLE_DIFF)
        assert not result.passed
        assert result.severity == "critical"
        assert result.cwe == "CWE-89"

    def test_clean_diff_ok(self):
        result = check_sql_injection(CLEAN_DIFF)
        assert result.passed

    def test_empty_diff_ok(self):
        result = check_sql_injection(EMPTY_DIFF)
        assert result.passed

    def test_detects_fstring_query(self):
        diff = '+cursor.execute(f"SELECT * FROM users WHERE id={user_id}")\n'
        result = check_sql_injection(diff)
        assert not result.passed


class TestXSS:
    def test_detects_innerhtml(self):
        result = check_xss(VULNERABLE_DIFF)
        assert not result.passed
        assert result.severity == "critical"
        assert result.cwe == "CWE-79"

    def test_clean_diff_ok(self):
        result = check_xss(CLEAN_DIFF)
        assert result.passed

    def test_detects_dangerously_set_inner_html(self):
        diff = '+<div dangerouslySetInnerHTML={{__html: rawHtml}} />\n'
        result = check_xss(diff)
        assert not result.passed

    def test_detects_document_write(self):
        diff = '+document.write(userInput);\n'
        result = check_xss(diff)
        assert not result.passed


class TestPathTraversal:
    def test_detects_dot_dot(self):
        result = check_path_traversal(VULNERABLE_DIFF)
        assert not result.passed
        assert result.severity == "critical"
        assert result.cwe == "CWE-22"

    def test_clean_diff_ok(self):
        result = check_path_traversal(CLEAN_DIFF)
        assert result.passed

    def test_detects_etc_passwd(self):
        diff = '+data = open("../../etc/passwd").read()\n'
        result = check_path_traversal(diff)
        assert not result.passed


class TestHardcodedSecrets:
    def test_detects_api_key(self):
        result = check_hardcoded_secrets(VULNERABLE_DIFF)
        assert not result.passed
        assert result.severity == "critical"

    def test_clean_diff_ok(self):
        result = check_hardcoded_secrets(CLEAN_DIFF)
        assert result.passed

    def test_detects_aws_key(self):
        diff = "+key = 'AKIAIOSFODNN7EXAMPLE'\n"
        result = check_hardcoded_secrets(diff)
        assert not result.passed

    def test_detects_private_key(self):
        diff = "+-----BEGIN RSA PRIVATE KEY-----\n+MIIEpAIBAAKCAQEA...\n"
        result = check_hardcoded_secrets(diff)
        assert not result.passed

    def test_detects_github_token(self):
        diff = "+token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz1234'\n"
        result = check_hardcoded_secrets(diff)
        assert not result.passed


class TestCommandInjection:
    def test_detects_os_system_concat(self):
        result = check_command_injection(VULNERABLE_DIFF)
        assert not result.passed
        assert result.severity == "critical"
        assert result.cwe == "CWE-78"

    def test_clean_diff_ok(self):
        result = check_command_injection(CLEAN_DIFF)
        assert result.passed

    def test_detects_shell_true(self):
        diff = "+subprocess.run(cmd, shell=True)\n"
        result = check_command_injection(diff)
        assert not result.passed


class TestCriticalEval:
    def test_detects_eval_with_input(self):
        result = check_critical_eval(VULNERABLE_DIFF)
        assert not result.passed
        assert result.severity == "critical"
        assert result.cwe == "CWE-95"

    def test_clean_diff_ok(self):
        result = check_critical_eval(CLEAN_DIFF)
        assert result.passed

    def test_eval_alone_is_ok(self):
        diff = "+result = eval('1 + 1')\n"
        result = check_critical_eval(diff)
        assert result.passed  # eval without user input is not flagged

    def test_detects_exec_with_input(self):
        diff = "+exec(user_input)\n"
        result = check_critical_eval(diff)
        assert not result.passed


class TestInsecureRandom:
    def test_detects_random_in_security_context(self):
        diff = '+token = "".join(str(random.randint(0, 9)) for _ in range(10))\n'
        result = check_insecure_random(diff)
        assert not result.passed
        assert result.severity == "error"

    def test_clean_diff_ok(self):
        result = check_insecure_random(CLEAN_DIFF)
        assert result.passed

    def test_random_without_security_context_ok(self):
        diff = '+val = random.randint(1, 100)\n'
        result = check_insecure_random(diff)
        assert result.passed


class TestInsecureCrypto:
    def test_detects_md5(self):
        diff = "+h = hashlib.md5(data).hexdigest()\n"
        result = check_insecure_crypto(diff)
        assert not result.passed
        assert result.severity == "error"

    def test_detects_sha1(self):
        diff = "+h = hashlib.sha1(data).hexdigest()\n"
        result = check_insecure_crypto(diff)
        assert not result.passed

    def test_clean_diff_ok(self):
        result = check_insecure_crypto(CLEAN_DIFF)
        assert result.passed


class TestDebugEnabled:
    def test_detects_debug_true(self):
        diff = "+DEBUG = True\n"
        result = check_debug_enabled(diff)
        assert not result.passed
        assert result.severity == "warning"

    def test_detects_flask_debug(self):
        diff = '+app.run(debug=True)\n'
        result = check_debug_enabled(diff)
        assert not result.passed

    def test_clean_diff_ok(self):
        result = check_debug_enabled(CLEAN_DIFF)
        assert result.passed


class TestHttpNotHttps:
    def test_detects_http_url(self):
        diff = '+url = "http://api.production.example.com/endpoint"\n'
        result = check_http_not_https(diff)
        assert not result.passed
        assert result.severity == "warning"

    def test_localhost_is_ok(self):
        diff = '+url = "http://localhost:8080/api"\n'
        result = check_http_not_https(diff)
        assert result.passed

    def test_clean_diff_ok(self):
        result = check_http_not_https(CLEAN_DIFF)
        assert result.passed


class TestDisabledSecurity:
    def test_detects_nosec(self):
        diff = "+# nosec\n"
        result = check_disabled_security(diff)
        assert not result.passed

    def test_detects_type_ignore(self):
        diff = "+# type: ignore\n"
        result = check_disabled_security(diff)
        assert not result.passed

    def test_clean_diff_ok(self):
        result = check_disabled_security(CLEAN_DIFF)
        assert result.passed


class TestSensitiveFileExposure:
    def test_detects_env_file(self):
        diff = "diff --git a/.env b/.env\nnew file mode 100644\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1,2 @@\n+SECRET=hello\n"
        result = check_sensitive_file_exposure(diff)
        assert not result.passed
        assert result.severity == "error"

    def test_detects_key_file(self):
        diff = "diff --git a/id_rsa b/id_rsa\nnew file mode 100644\n--- /dev/null\n+++ b/id_rsa\n@@ -0,0 +1,2 @@\n+keydata\n"
        result = check_sensitive_file_exposure(diff)
        assert not result.passed

    def test_clean_diff_ok(self):
        result = check_sensitive_file_exposure(CLEAN_DIFF)
        assert result.passed


class TestWeakPasswordHash:
    def test_detects_md5_password(self):
        diff = "+h = hashlib.md5(password.encode()).hexdigest()\n"
        result = check_weak_password_hash(diff)
        assert not result.passed
        assert result.severity == "error"

    def test_detects_sha1_password(self):
        diff = "+h = hashlib.sha1(password.encode()).hexdigest()\n"
        result = check_weak_password_hash(diff)
        assert not result.passed

    def test_clean_diff_ok(self):
        result = check_weak_password_hash(CLEAN_DIFF)
        assert result.passed

    def test_md5_without_password_ok(self):
        diff = "+h = hashlib.md5(data).hexdigest()\n"
        result = check_weak_password_hash(diff)
        assert result.passed


# ─── Orchestration tests ─────────────────────────────────────

class TestRunAllChecks:
    def test_returns_results_for_all_checks(self):
        results = run_all_checks(VULNERABLE_DIFF)
        check_ids = {r.check_id for r in results}
        assert "sql_injection" in check_ids
        assert "xss" in check_ids
        assert "path_traversal" in check_ids
        assert "hardcoded_secrets" in check_ids
        assert "command_injection" in check_ids
        assert "critical_eval" in check_ids
        assert "insecure_random" in check_ids
        assert "insecure_crypto" in check_ids
        assert "debug_enabled" in check_ids
        assert "http_not_https" in check_ids
        assert "disabled_security" in check_ids
        assert "sensitive_file_exposure" in check_ids
        assert "weak_password_hash" in check_ids

    def test_clean_diff_mostly_passes(self):
        results = run_all_checks(CLEAN_DIFF)
        failed = [r for r in results if not r.passed]
        non_info_failures = [r for r in failed if r.severity not in ("info",)]
        assert len(non_info_failures) == 0, f"Unexpected failures: {[r.name for r in non_info_failures]}"

    def test_vulnerable_diff_has_multiple_failures(self):
        results = run_all_checks(VULNERABLE_DIFF)
        failed = [r for r in results if not r.passed]
        assert len(failed) >= 6, f"Expected >= 6 failures, got {len(failed)}: {[r.name for r in failed]}"

    def test_vulnerable_diff_has_critical_severity(self):
        results = run_all_checks(VULNERABLE_DIFF)
        critical = [r for r in results if not r.passed and r.severity == "critical"]
        assert len(critical) >= 4, f"Expected >= 4 critical findings"

    def test_empty_diff_doesnt_crash(self):
        results = run_all_checks(EMPTY_DIFF)
        assert len(results) > 0

    def test_all_results_have_cwe_when_failing(self):
        """Failing results should include CWE references where applicable."""
        results = run_all_checks(VULNERABLE_DIFF)
        failing_with_cwe = [r for r in results if not r.passed and r.cwe]
        assert len(failing_with_cwe) >= 5, "Expected at least 5 findings with CWE references"
