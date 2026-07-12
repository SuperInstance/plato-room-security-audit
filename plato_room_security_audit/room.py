"""
PLATO Security Audit Room — an engine block that orchestrates automated security auditing.

Sensors pull PR state from GitHub and scan for vulnerability patterns.
Alarms fire on critical security conditions.  Actuators post audits back.

Deploy as a standalone bot or inside a GitHub Action.

Usage:
    python -m plato_room_security_audit.room --repo owner/repo --pr 42

    # or run as a long-lived server (polls periodically)
    python -m plato_room_security_audit.room --repo owner/repo --watch
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import socketserver
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

try:
    from plato_core.protocol import PROTOCOL_VERSION
except ImportError:
    PROTOCOL_VERSION = "0.1"

try:
    from .auditor import run_all_checks, CheckResult
    from .github_client import GitHubClient
except ImportError:
    from auditor import run_all_checks, CheckResult
    from github_client import GitHubClient

logger = logging.getLogger("plato.room.security_audit")

# ─── Core room primitives ─────────────────────────────────────

SensorFunc = Callable[["BaseRoom"], dict[str, float]]
ActuatorFunc = Callable[["BaseRoom", float], None]


@dataclass
class AlarmDef:
    """Declarative alarm definition."""
    alarm_id: str
    condition: str
    sensor: str
    operator: str
    threshold: float
    cooldown_sec: int = 300
    last_triggered: float = 0.0
    state: str = "idle"

    def evaluate(self, sensor_values: dict[str, float]) -> bool:
        """Return True if the alarm should fire."""
        val = sensor_values.get(self.sensor)
        if val is None:
            return False
        ops = {
            "<":  lambda a, b: a < b,
            ">":  lambda a, b: a > b,
            "<=": lambda a, b: a <= b,
            ">=": lambda a, b: a >= b,
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
        }
        op = ops.get(self.operator)
        if op is None:
            return False
        return op(val, self.threshold)


class BaseRoom:
    """
    Base PLATO room — a TCP server that implements the wire protocol.

    Subclasses register sensors, actuators, and alarms in setup().
    The tick loop calls each sensor, stores values, evaluates alarms,
    and notifies subscribers.
    """

    tick_hz: float = 0.2
    room_id: str = "base-room"

    def __init__(self, host: str = "0.0.0.0", port: int = 1235):
        self.host = host
        self.port = port
        self._sensors: dict[str, SensorFunc] = {}
        self._actuators: dict[str, ActuatorFunc] = {}
        self._alarms: dict[str, AlarmDef] = {}
        self._history: deque[dict] = deque(maxlen=1000)
        self._subscribers: list[socket.socket] = []
        self._lock = threading.Lock()
        self._seq = 0
        self._running = False
        self._latest: dict[str, float] = {}

    def register_sensor(self, name: str, func: SensorFunc) -> None:
        self._sensors[name] = func

    def register_actuator(self, name: str, func: ActuatorFunc) -> None:
        self._actuators[name] = func

    def register_alarm(
        self,
        alarm_id: str,
        sensor: str,
        operator: str,
        threshold: float,
        cooldown_sec: int = 300,
    ) -> None:
        condition = f"{sensor} {operator} {threshold}"
        self._alarms[alarm_id] = AlarmDef(
            alarm_id=alarm_id,
            condition=condition,
            sensor=sensor,
            operator=operator,
            threshold=threshold,
            cooldown_sec=cooldown_sec,
        )

    def tick(self) -> dict[str, float]:
        """Execute one tick: read all sensors, evaluate alarms."""
        self._seq += 1
        values: dict[str, float] = {}
        for name, func in self._sensors.items():
            try:
                result = func(self)
                if isinstance(result, dict):
                    values.update(result)
            except Exception as exc:
                logger.warning("sensor %s error: %s", name, exc)
                values[f"{name}_error"] = 1.0

        self._latest = values
        ts = time.time()
        tick_record = {"t": ts, "seq": self._seq, "data": values}
        self._history.append(tick_record)

        for alarm in self._alarms.values():
            if alarm.evaluate(values):
                if ts - alarm.last_triggered >= alarm.cooldown_sec:
                    alarm.last_triggered = ts
                    alarm.state = "triggered"
                    self._on_alarm(alarm, values, ts)
                else:
                    alarm.state = "cooling"
            else:
                alarm.state = "idle"

        self._notify_subscribers(tick_record)
        return values

    def _on_alarm(self, alarm: AlarmDef, data: dict[str, float], ts: float) -> None:
        """Override in subclass for custom alarm handling."""
        logger.info("ALARM %s fired: %s", alarm.alarm_id, alarm.condition)

    def _notify_subscribers(self, tick_record: dict) -> None:
        msg = json.dumps({"type": "tick", **tick_record}) + "\n"
        dead: list[socket.socket] = []
        with self._lock:
            for sub in self._subscribers:
                try:
                    sub.sendall(msg.encode())
                except Exception:
                    dead.append(sub)
            for d in dead:
                self._subscribers.remove(d)

    def actuate(self, name: str, value: float = 1.0) -> None:
        func = self._actuators.get(name)
        if func:
            func(self, value)
        else:
            logger.warning("unknown actuator: %s", name)

    def handle_command(self, line: str) -> str:
        """Handle one protocol command line, return response JSON."""
        parts = line.strip().split()
        if not parts:
            return json.dumps(asdict(ErrorResponse(message="empty command")))

        cmd = parts[0]

        if cmd == "tick":
            data = self.tick()
            return json.dumps({"type": "tick", "t": time.time(),
                               "seq": self._seq, "data": data})

        if cmd == "history":
            n = int(parts[1]) if len(parts) > 1 else 10
            ticks = list(self._history)[-n:]
            return json.dumps({"type": "history", "count": len(ticks),
                               "ticks": ticks})

        if cmd == "actuator" and len(parts) >= 2:
            name = parts[1]
            value = float(parts[2]) if len(parts) > 2 else 1.0
            self.actuate(name, value)
            return json.dumps({"type": "ack", "command": "actuator",
                               "name": name, "value": value})

        if cmd == "alarm" and len(parts) >= 2:
            sub = parts[1]
            if sub == "list":
                alarms = [
                    {"id": a.alarm_id, "condition": a.condition,
                     "cooldown_sec": a.cooldown_sec,
                     "last_triggered": a.last_triggered,
                     "state": a.state}
                    for a in self._alarms.values()
                ]
                return json.dumps({"type": "alarm_list", "alarms": alarms})
            if sub == "set" and len(parts) >= 5:
                aid = parts[2]
                condition = parts[3]
                cooldown = int(parts[4])
                tokens = condition.split()
                if len(tokens) == 3:
                    self.register_alarm(aid, tokens[0], tokens[1],
                                        float(tokens[2]), cooldown)
                return json.dumps({"type": "ack", "command": "alarm set",
                                   "id": aid})

        if cmd == "subscribe":
            return json.dumps({"type": "subscribed", "tick_hz": self.tick_hz})

        if cmd == "unsubscribe":
            return json.dumps({"type": "unsubscribed"})

        if cmd == "help":
            return json.dumps({"type": "help", "commands": [
                "tick", "history N", "actuator NAME [VALUE]",
                "alarm list", "alarm set ID CONDITION COOLDOWN",
                "subscribe", "unsubscribe", "help", "quit",
            ]})

        if cmd == "quit":
            return json.dumps({"type": "bye"})

        return json.dumps(asdict(ErrorResponse(
            message=f"unknown command: {cmd}")))

    def serve(self) -> None:
        """Run the TCP server + tick loop."""
        self._running = True

        tick_thread = threading.Thread(target=self._tick_loop, daemon=True)
        tick_thread.start()

        server = socketserver.ThreadingTCPServer(
            (self.host, self.port), _RoomHandlerFactory(self))
        server.daemon_threads = True
        logger.info("Room %s listening on %s:%d", self.room_id, self.host, self.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self._running = False
            server.shutdown()

    def _tick_loop(self) -> None:
        interval = 1.0 / self.tick_hz if self.tick_hz > 0 else 5.0
        while self._running:
            try:
                self.tick()
            except Exception as exc:
                logger.error("tick error: %s", exc)
            time.sleep(interval)


def _RoomHandlerFactory(room: BaseRoom):
    """Create a RequestHandler class bound to a specific room."""

    class _RoomHandler(socketserver.StreamRequestHandler):
        def handle(self):
            welcome = json.dumps({
                "type": "welcome",
                "room_id": room.room_id,
                "tick_hz": room.tick_hz,
                "sensors": list(room._sensors.keys()),
                "format": "json",
                "protocol_version": PROTOCOL_VERSION,
            }) + "\n"
            self.wfile.write(welcome.encode())

            for line in self.rfile:
                line_str = line.decode().strip()
                if not line_str:
                    continue
                response = room.handle_command(line_str)
                self.wfile.write((response + "\n").encode())

                if line_str.startswith("subscribe"):
                    with room._lock:
                        room._subscribers.append(self.request)
                elif line_str.startswith("unsubscribe"):
                    with room._lock:
                        if self.request in room._subscribers:
                            room._subscribers.remove(self.request)
                elif line_str.strip() == "quit":
                    break

    return _RoomHandler


# ─── Security Audit Room ─────────────────────────────────────

class SecurityAuditRoom(BaseRoom):
    """
    A PLATO room that runs security audits on GitHub PRs.

    Sensors:
        vuln_patterns   — Counts of each vulnerability class in the diff
        secret_scan     — Secret-like strings detected
        risk_score      — Overall risk score (0-100, higher = worse)

    Actuators:
        post_audit   — Post a security review (APPROVE / REQUEST_CHANGES / COMMENT)
        block_merge  — Block the merge (REQUEST_CHANGES with critical findings)
        apply_label  — Apply a security label to the PR

    Alarms:
        sql_injection      — fires when sql_injection_count > 0
        xss_detected       — fires when xss_count > 0
        path_traversal     — fires when traversal_count > 0
        hardcoded_secrets  — fires when secret_count > 0
        command_injection  — fires when cmd_injection_count > 0
        critical_eval      — fires when eval_count > 0
    """

    room_id = "security-audit-room"
    tick_hz = 0.1  # every 10 seconds

    def __init__(
        self,
        github_client: GitHubClient,
        owner: str,
        repo: str,
        pr_number: int = 0,
        host: str = "0.0.0.0",
        port: int = 1235,
    ):
        super().__init__(host=host, port=port)
        self.gh = github_client
        self.owner = owner
        self.repo = repo
        self.pr_number = pr_number
        self._last_audit: Optional[dict] = None
        self.setup()

    def setup(self) -> None:
        """Register sensors, actuators, and alarms."""
        # ── Sensors ─────────────────────────────────────────
        self.register_sensor("vuln_patterns", _sensor_vuln_patterns)
        self.register_sensor("secret_scan", _sensor_secret_scan)
        self.register_sensor("risk_score", _sensor_risk_score)

        # ── Actuators ───────────────────────────────────────
        self.register_actuator("post_audit", _actuator_post_audit)
        self.register_actuator("block_merge", _actuator_block_merge)
        self.register_actuator("apply_label", _actuator_apply_label)

        # ── Alarms ──────────────────────────────────────────
        self.register_alarm("sql_injection", sensor="sql_injection_count",
                            operator=">", threshold=0, cooldown_sec=60)
        self.register_alarm("xss_detected", sensor="xss_count",
                            operator=">", threshold=0, cooldown_sec=60)
        self.register_alarm("path_traversal", sensor="traversal_count",
                            operator=">", threshold=0, cooldown_sec=60)
        self.register_alarm("hardcoded_secrets", sensor="secret_count",
                            operator=">", threshold=0, cooldown_sec=60)
        self.register_alarm("command_injection", sensor="cmd_injection_count",
                            operator=">", threshold=0, cooldown_sec=60)
        self.register_alarm("critical_eval", sensor="eval_count",
                            operator=">", threshold=0, cooldown_sec=60)

    def _on_alarm(self, alarm: AlarmDef, data: dict[str, float], ts: float) -> None:
        """Custom alarm handler — triggers security actions."""
        logger.warning("Security alarm %s triggered (data=%s)", alarm.alarm_id, data)

        if alarm.alarm_id in ("sql_injection", "command_injection",
                              "critical_eval", "hardcoded_secrets"):
            self.actuate("block_merge", 2.0)  # REQUEST_CHANGES
        elif alarm.alarm_id in ("xss_detected", "path_traversal"):
            self.actuate("post_audit", 1.0)  # COMMENT
        else:
            self.actuate("apply_label", 5.0)  # label "security-review"


# ─── Sensor functions ────────────────────────────────────────

def _sensor_vuln_patterns(room: SecurityAuditRoom) -> dict[str, float]:
    """Scan diff for vulnerability patterns and expose counts."""
    if not room.pr_number:
        return {k: 0.0 for k in (
            "sql_injection_count", "xss_count", "traversal_count",
            "cmd_injection_count", "eval_count",
        )}

    diff = room.gh.fetch_pr_diff(room.owner, room.repo, room.pr_number)
    results = run_all_checks(diff)

    counts = {}
    mapping = {
        "sql_injection": "sql_injection_count",
        "xss": "xss_count",
        "path_traversal": "traversal_count",
        "command_injection": "cmd_injection_count",
        "critical_eval": "eval_count",
    }
    for check_id, sensor_name in mapping.items():
        count = sum(1 for r in results if r.check_id == check_id and not r.passed)
        counts[sensor_name] = float(count)

    return counts


def _sensor_secret_scan(room: SecurityAuditRoom) -> dict[str, float]:
    """Scan for hardcoded secrets."""
    if not room.pr_number:
        return {"secret_count": 0.0, "sensitive_file_count": 0.0}

    diff = room.gh.fetch_pr_diff(room.owner, room.repo, room.pr_number)
    results = run_all_checks(diff)

    secret_count = sum(1 for r in results if r.check_id == "hardcoded_secrets" and not r.passed)
    sensitive_files = sum(1 for r in results if r.check_id == "sensitive_file_exposure" and not r.passed)

    return {
        "secret_count": float(secret_count),
        "sensitive_file_count": float(sensitive_files),
    }


def _sensor_risk_score(room: SecurityAuditRoom) -> dict[str, float]:
    """Calculate overall risk score (0-100)."""
    if not room.pr_number:
        return {"risk_score": 0.0, "critical_count": 0.0, "error_count": 0.0}

    diff = room.gh.fetch_pr_diff(room.owner, room.repo, room.pr_number)
    results = run_all_checks(diff)

    failing = [r for r in results if not r.passed]
    critical = sum(1 for r in failing if r.severity == "critical")
    error = sum(1 for r in failing if r.severity == "error")
    warning = sum(1 for r in failing if r.severity == "warning")
    info = sum(1 for r in failing if r.severity == "info")

    # Weighted risk score
    score = min(100, critical * 30 + error * 15 + warning * 5 + info * 1)

    return {
        "risk_score": float(score),
        "critical_count": float(critical),
        "error_count": float(error),
    }


# ─── Actuator functions ──────────────────────────────────────

def _actuator_post_audit(room: SecurityAuditRoom, value: float) -> None:
    """Post a security audit review. value: 0=COMMENT, 1=COMMENT, 2=REQUEST_CHANGES, 3=APPROVE."""
    event_map = {0: "COMMENT", 1: "COMMENT", 2: "REQUEST_CHANGES", 3: "APPROVE"}
    event = event_map.get(int(value), "COMMENT")

    diff = room.gh.fetch_pr_diff(room.owner, room.repo, room.pr_number)
    results = run_all_checks(diff)
    body = _format_audit_body(results, event)

    room.gh.post_review(room.owner, room.repo, room.pr_number, body, event)
    room._last_audit = {"event": event, "body": body, "ts": time.time()}


def _actuator_block_merge(room: SecurityAuditRoom, value: float) -> None:
    """Block merge by posting REQUEST_CHANGES review."""
    diff = room.gh.fetch_pr_diff(room.owner, room.repo, room.pr_number)
    results = run_all_checks(diff)

    critical = [r for r in results if not r.passed and r.severity == "critical"]
    body = _format_audit_body(results, "REQUEST_CHANGES", critical_findings=critical)

    room.gh.post_review(room.owner, room.repo, room.pr_number, body, "REQUEST_CHANGES")
    room._last_audit = {"event": "REQUEST_CHANGES", "body": body, "ts": time.time()}


def _actuator_apply_label(room: SecurityAuditRoom, value: float) -> None:
    """Apply a security label to the PR."""
    label_map = {
        1: "needs-security-review",
        2: "security-critical",
        3: "secrets-detected",
        4: "vulnerability-detected",
        5: "security-review",
    }
    label = label_map.get(int(value), "security-audited")
    room.gh.apply_label(room.owner, room.repo, room.pr_number, label)


# ─── Helpers ─────────────────────────────────────────────────

def _format_audit_body(
    results: list[CheckResult],
    event: str,
    critical_findings: list[CheckResult] | None = None,
) -> str:
    """Format check results into a markdown audit body."""
    lines = ["## 🔒 PLATO Security Audit\n"]
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    if failed == 0:
        lines.append("All security checks passed. ✅\n")
    else:
        lines.append(f"**{failed} security check(s) need attention:**\n")

    if critical_findings:
        lines.append("### 🚨 Critical Findings\n")
        for r in critical_findings:
            cwe_str = f" `{r.cwe}`" if r.cwe else ""
            lines.append(f"- **{r.name}**{cwe_str}: {r.message}")
        lines.append("")

    # Group by severity
    for severity in ("critical", "error", "warning", "info"):
        sev_results = [r for r in results if not r.passed and r.severity == severity]
        if sev_results:
            icon = {"critical": "🔴", "error": "🟠", "warning": "🟡", "info": "🔵"}[severity]
            lines.append(f"### {icon} {severity.upper()}\n")
            for r in sev_results:
                cwe_str = f" `{r.cwe}`" if r.cwe else ""
                lines.append(f"- {cwe_str} **{r.name}**: {r.message}")
            lines.append("")

    if event == "REQUEST_CHANGES":
        lines.append("⚠️ Changes requested due to security findings.")
    elif event == "APPROVE":
        lines.append("✅ Approved — all security checks passed.")

    return "\n".join(lines)


# ─── CLI ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PLATO Security Audit Room")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--pr", type=int, default=0, help="PR number to audit")
    parser.add_argument("--watch", action="store_true", help="Run as long-lived server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=1235)
    parser.add_argument("--token-env", default="GITHUB_TOKEN", help="Env var for GitHub token")
    parser.add_argument("--once", action="store_true", help="Audit once and exit")
    args = parser.parse_args()

    import os
    token = os.environ.get(args.token_env, "")
    owner, repo = args.repo.split("/")

    gh = GitHubClient(token)
    room = SecurityAuditRoom(gh, owner, repo, args.pr, args.host, args.port)

    if args.once and args.pr:
        diff = gh.fetch_pr_diff(owner, repo, args.pr)
        results = run_all_checks(diff)
        body = _format_audit_body(results, "COMMENT")
        print(body)
        return

    if args.watch:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")
        room.serve()
    else:
        print(f"Room {room.room_id} configured. Use --watch to start, --once to audit PR #{args.pr}")


if __name__ == "__main__":
    main()
