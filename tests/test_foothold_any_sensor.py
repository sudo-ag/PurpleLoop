"""Blue closes the surface on a foothold detected by ANY sensor, not only an
auth-log SSH login. See docs/superpowers/specs/2026-11-18-blue-foothold-any-sensor-design.md.
"""
import json

from src.agents import BlueAgent
from src.mock_executor import MockExecutor
from src.trajectory import Turn


def _blue():
    b = BlueAgent(executor=MockExecutor(), model="x")
    b.executor.control_source_ip = "192.168.64.1"
    b.executor.user = "vagrant"
    return b


def _logs_turn(**extra):
    d = {"tool": "investigate_logs", "suspicious_users": [], **extra}
    return Turn(0, "", {"function": {"name": "investigate_logs", "arguments": {}}}, json.dumps(d))


def _proc_turn(critical):
    d = {"tool": "investigate_processes", "critical_processes": critical}
    return Turn(0, "", {"function": {"name": "investigate_processes", "arguments": {}}}, json.dumps(d))


def _webshell_turn(**extra):
    d = {"tool": "investigate_webshells", "new_files": [], **extra}
    return Turn(0, "", {"function": {"name": "investigate_webshells", "arguments": {}}}, json.dumps(d))


def test_service_account_critical_process_is_a_foothold():
    b = _blue()
    b.history = [_proc_turn([{"user": "www-data", "command": "find / -name flag.txt", "critical": True}])]
    assert b._has_foothold() is True


def test_root_critical_process_is_a_foothold():
    b = _blue()
    b.history = [_proc_turn([{"user": "root", "command": "cat /root/flag.txt", "critical": True}])]
    assert b._has_foothold() is True


def test_webshell_breach_is_a_foothold():
    b = _blue()
    b.history = [_webshell_turn(assessment="BREACH")]
    assert b._has_foothold() is True


def test_auth_account_is_a_foothold():
    b = _blue()
    b.history = [_logs_turn(suspicious_users=["boba_fett"])]
    assert b._has_foothold() is True


def test_blue_own_recon_process_is_not_a_foothold():
    b = _blue()
    b.history = [_proc_turn([{"user": "vagrant", "command": "stat /root/flag.txt", "critical": True}])]
    assert b._has_foothold() is False


def test_recon_only_is_not_a_foothold():
    b = _blue()
    b.history = [_logs_turn(), _webshell_turn(assessment="CLEAN")]
    assert b._has_foothold() is False


def test_harden_fires_for_webrce_foothold_without_account():
    # Confirmed attacker + www-data foothold, no auth account: observe-mode
    # guidance must direct the surface close, not just document.
    b = _blue()
    b.history = [_proc_turn([{"user": "www-data", "command": "find / -name flag.txt", "critical": True}])]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_escalation_surface" in g


def test_recon_only_does_not_harden():
    b = _blue()
    b.history = [_logs_turn()]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_escalation_surface" not in g
