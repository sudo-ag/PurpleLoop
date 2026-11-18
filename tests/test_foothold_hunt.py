"""Blue hunts the foothold after confirming a scanner, instead of settling into
document-mode. See docs/superpowers/specs/2026-11-18-blue-foothold-hunt-design.md.
"""
import json

from src.agents import BlueAgent, BLUE_FOOTHOLD_HUNT
from src.mock_executor import MockExecutor
from src.trajectory import Turn


def _blue():
    b = BlueAgent(executor=MockExecutor(), model="x")
    b.executor.control_source_ip = "192.168.64.1"
    b.executor.user = "vagrant"
    return b


def _used_turn(name):
    out = json.dumps({"tool": name})
    return Turn(0, "", {"function": {"name": name, "arguments": {}}}, out)


def test_confirmed_scanner_no_foothold_hunts_webshells_first():
    b = _blue()
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "investigate_webshells" in g


def test_hunt_picks_least_recently_used_unrun_sensor():
    b = _blue()
    b.history = [_used_turn("investigate_webshells")]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "investigate_webshells" not in g
    assert any(s in g for s in ("investigate_file_access", "investigate_processes"))


def test_hunt_exhausted_falls_through_to_attribute():
    b = _blue()
    b.history = [_used_turn(s) for s in BLUE_FOOTHOLD_HUNT]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "ATTRIBUTE" in g


def test_hunt_does_not_fire_when_foothold_already_held():
    b = _blue()
    b.history = [Turn(0, "", {"function": {"name": "investigate_processes", "arguments": {}}},
                      json.dumps({"tool": "investigate_processes",
                                  "critical_processes": [{"user": "www-data", "critical": True}]}))]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_escalation_surface" in g


def test_non_observe_confirmed_no_foothold_still_responds():
    b = _blue()
    g = b.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "contain_attacker" in g
