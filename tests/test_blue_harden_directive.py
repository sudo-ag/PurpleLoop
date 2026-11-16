"""Fix: once blue has cut the foothold account's group escalation, it must be
directed to CLOSE the broader privesc surface (investigate_escalation_paths +
remediate_finding), including in observe mode — otherwise the paintball loop
never fires (blue revokes groups, then only documents)."""
import json
from src.agents import BlueAgent
from src.trajectory import Turn
from src.mock_executor import MockExecutor


def _blue():
    b = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    b.executor.control_source_ip = "192.168.64.1"
    return b


def _turn(name):
    return Turn(0, "", {"function": {"name": name, "arguments": {}}}, "ok")


def _revoked_foothold_blue():
    """Confirmed attacker + foothold account boba_fett + group escalation already
    revoked (so IDENTIFY's urgent revoke is done), but no posture scan yet."""
    b = _blue()
    b.history = [
        Turn(0, "", {"function": {"name": "investigate_connections", "arguments": {}}},
             json.dumps({"tool": "investigate_connections", "port_scanners": ["192.168.64.11"],
                         "suspicious_ips": ["192.168.64.11"]})),
        Turn(1, "", {"function": {"name": "investigate_logs", "arguments": {}}},
             json.dumps({"tool": "investigate_logs", "failed_attempts": 0,
                         "suspicious_ips": ["192.168.64.11"], "suspicious_users": ["boba_fett"]})),
        _turn("revoke_escalation"),
    ]
    return b


def test_harden_directive_fires_after_revoke_in_observe():
    b = _revoked_foothold_blue()
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "investigate_escalation_paths" in g
    assert "remediate_finding" in g


def test_harden_directive_is_observe_only():
    # Non-observe keeps the contain-and-end flow; hardening (keep red in the game)
    # is the observe/training behaviour, so it must NOT preempt RESPOND.
    b = _revoked_foothold_blue()
    g = b.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_finding" not in g


def test_harden_directive_gone_once_scan_ran():
    b = _revoked_foothold_blue()
    b.history.append(_turn("investigate_escalation_paths"))
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_finding" not in g
