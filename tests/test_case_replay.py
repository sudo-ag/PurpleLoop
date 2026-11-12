"""The case rides into ep_NNN.json; observe-held containment keeps the counterfactual."""
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from src.agents import Agent
from src.arena import build_replay
from src.case import new_case, add_lead, add_hypothesis
from src.executor import ToolExecutor


def test_replay_carries_the_full_case_including_old_leads():
    case = new_case()
    for n in range(15):  # more than compact_view's default max_leads (12)
        add_lead(case, "investigate_logs", f"e{n}", "low", n)
    add_hypothesis(case, "noise", "low", [0], 15)
    state = SimpleNamespace(blue_case=case, turn=15, history=[])
    rep = build_replay(state, {"winner": None}, 1, {"observe": True})
    assert len(rep["blue_case"]["leads"]) == 15


def test_observe_contain_output_carries_ip_and_cited_leads():
    b = Agent("blue", MagicMock(spec=ToolExecutor), observe=True)
    b.case = new_case()
    add_lead(b.case, "investigate_connections", "x", "high", 1)
    add_lead(b.case, "investigate_processes", "y", "high", 2)
    add_hypothesis(b.case, "attacker", "high", [0, 1], 2)
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] == "observed"
    assert out["ip"] == "192.168.64.11" and out["cited_leads"] == [0, 1]
