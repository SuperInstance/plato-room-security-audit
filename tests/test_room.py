"""
Tests for the GitHub client's simulation mode and the SecurityAuditRoom lifecycle.

Run: python -m pytest tests/test_room.py -v
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plato_room_security_audit.github_client import GitHubClient
from plato_room_security_audit.room import SecurityAuditRoom, BaseRoom, AlarmDef
from plato_room_security_audit.auditor import run_all_checks


class TestGitHubClientSimulation:
    """GitHub client works without a token (simulation mode)."""

    def test_not_configured_without_token(self):
        client = GitHubClient(token="")
        assert not client.configured

    def test_fetch_diff_returns_sample(self):
        client = GitHubClient(token="")
        diff = client.fetch_pr_diff("owner", "repo", 1)
        assert "diff --git" in diff

    def test_fetch_metadata_returns_sample(self):
        client = GitHubClient(token="")
        meta = client.fetch_pr_metadata("owner", "repo", 1)
        assert meta["state"] == "open"
        assert meta["changed_files"] == 2

    def test_fetch_ci_status_returns_sample(self):
        client = GitHubClient(token="")
        status = client.fetch_ci_status("owner", "repo", 1)
        assert status["passed"] == 3
        assert status["failed"] == 0

    def test_post_review_simulated(self):
        client = GitHubClient(token="")
        result = client.post_review("owner", "repo", 1, "Audit", "COMMENT")
        assert result.get("simulated") is True

    def test_apply_label_simulated(self):
        client = GitHubClient(token="")
        result = client.apply_label("owner", "repo", 1, "security-critical")
        assert result.get("simulated") is True


class TestRoomBasics:
    """Test the BaseRoom."""

    def test_base_room_registers_sensors(self):
        room = BaseRoom()
        room.register_sensor("test", lambda r: {"val": 1.0})
        assert "test" in room._sensors

    def test_base_room_registers_alarms(self):
        room = BaseRoom()
        room.register_alarm("overheat", sensor="temp", operator=">", threshold=90.0)
        assert "overheat" in room._alarms

    def test_alarm_evaluation(self):
        alarm = AlarmDef("test", "val > 5", "val", ">", 5)
        assert alarm.evaluate({"val": 10.0}) is True
        assert alarm.evaluate({"val": 3.0}) is False
        assert alarm.evaluate({}) is False

    def test_alarm_operators(self):
        for op, val, threshold, expected in [
            ("<", 3, 5, True), ("<", 7, 5, False),
            (">", 7, 5, True), (">", 3, 5, False),
            ("<=", 5, 5, True), (">=", 5, 5, True),
            ("==", 5, 5, True), ("!=", 5, 5, False),
        ]:
            alarm = AlarmDef("t", f"v {op} {threshold}", "v", op, threshold)
            assert alarm.evaluate({"v": val}) is expected

    def test_tick_executes_sensors(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"temp": 42.0})
        data = room.tick()
        assert data["temp"] == 42.0
        assert len(room._history) == 1

    def test_tick_evaluates_alarms(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"temp": 100.0})
        room.register_alarm("hot", sensor="temp", operator=">", threshold=90.0)
        room.tick()
        assert room._alarms["hot"].state == "triggered"

    def test_tick_records_history(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"x": float(r._seq)})
        for _ in range(5):
            room.tick()
        assert len(room._history) == 5
        assert room._history[-1]["seq"] == 5

    def test_handle_tick_command(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"x": 1.0})
        resp = json.loads(room.handle_command("tick"))
        assert resp["type"] == "tick"
        assert "x" in resp["data"]

    def test_handle_history_command(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"x": 1.0})
        room.tick()
        room.tick()
        resp = json.loads(room.handle_command("history 2"))
        assert resp["type"] == "history"
        assert resp["count"] == 2

    def test_handle_alarm_list_command(self):
        room = BaseRoom()
        room.register_alarm("a1", sensor="s", operator=">", threshold=5)
        resp = json.loads(room.handle_command("alarm list"))
        assert resp["type"] == "alarm_list"
        assert resp["alarms"][0]["id"] == "a1"

    def test_handle_actuator_command(self):
        room = BaseRoom()
        called = []
        room.register_actuator("do_thing", lambda r, v: called.append(v))
        resp = json.loads(room.handle_command("actuator do_thing 3"))
        assert resp["type"] == "ack"
        assert called == [3.0]


class TestSecurityAuditRoom:
    """Test the SecurityAuditRoom specifically."""

    def test_setup_registers_all_sensors(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 1, port=0)
        assert "vuln_patterns" in room._sensors
        assert "secret_scan" in room._sensors
        assert "risk_score" in room._sensors

    def test_setup_registers_all_actuators(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 1, port=0)
        assert "post_audit" in room._actuators
        assert "block_merge" in room._actuators
        assert "apply_label" in room._actuators

    def test_setup_registers_all_alarms(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 1, port=0)
        assert "sql_injection" in room._alarms
        assert "xss_detected" in room._alarms
        assert "path_traversal" in room._alarms
        assert "hardcoded_secrets" in room._alarms
        assert "command_injection" in room._alarms
        assert "critical_eval" in room._alarms

    def test_tick_with_sample_data(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 42, port=0)
        data = room.tick()
        # Sample diff has SQL injection, secrets, command injection, eval
        assert data["sql_injection_count"] > 0
        assert data["secret_count"] > 0
        assert data["cmd_injection_count"] > 0
        assert data["eval_count"] > 0
        assert data["risk_score"] > 0
        # Alarms should fire
        assert room._alarms["sql_injection"].state == "triggered"
        assert room._alarms["hardcoded_secrets"].state == "triggered"
        assert room._alarms["command_injection"].state == "triggered"
        assert room._alarms["critical_eval"].state == "triggered"

    def test_tick_without_pr_number(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 0, port=0)
        data = room.tick()
        assert data["sql_injection_count"] == 0
        assert data["secret_count"] == 0
        assert data["risk_score"] == 0

    def test_room_id(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 1, port=0)
        assert room.room_id == "security-audit-room"

    def test_history_records_all_ticks(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 42, port=0)
        for _ in range(3):
            room.tick()
        assert len(room._history) == 3
        # Each tick should have vulnerability data
        for record in room._history:
            assert "sql_injection_count" in record["data"]

    def test_handle_help_command(self):
        gh = GitHubClient(token="")
        room = SecurityAuditRoom(gh, "owner", "repo", 1, port=0)
        resp = json.loads(room.handle_command("help"))
        assert resp["type"] == "help"
        assert "tick" in resp["commands"]
        assert "alarm list" in resp["commands"]
