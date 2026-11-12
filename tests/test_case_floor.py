"""Thin-evidence floor: block containment whose cited leads are one sensor."""
import json
from unittest.mock import MagicMock

from src.agents import Agent
from src.case import new_case, add_lead, add_hypothesis
from src.executor import ToolExecutor


def _blue(observe: bool = False) -> Agent:
    a = Agent("blue", MagicMock(spec=ToolExecutor), observe=observe)
    a.executor.contain_attacker.return_value = {
        "tool": "contain_attacker", "status": "ok", "contained": True,
    }
    return a


def test_contain_blocked_when_cited_leads_are_one_sensor():
    b = _blue(); b.case = new_case()
    add_lead(b.case, "investigate_connections", "x", "high", 1)
    add_lead(b.case, "investigate_connections", "y", "high", 2)
    add_hypothesis(b.case, "attacker", "high", [0, 1], 2)
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] == "blocked_thin_evidence"
    assert out.get("contained") is not True


def test_contain_allowed_when_cited_leads_span_two_sensors():
    b = _blue(); b.case = new_case()
    add_lead(b.case, "investigate_connections", "x", "high", 1)
    add_lead(b.case, "investigate_processes", "y", "high", 2)
    add_hypothesis(b.case, "attacker", "high", [0, 1], 2)
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] != "blocked_thin_evidence"


def test_contain_with_no_hypothesis_is_unchanged_backward_compat():
    b = _blue(); b.case = new_case()
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] != "blocked_thin_evidence"
