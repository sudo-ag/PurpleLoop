"""Blue's eviction signal: blue_persistence_removed_turn is set when blue
successfully removes a planted key (removed: True), not on a refused/no-op call.
See docs/superpowers/specs/2026-11-18-persistence-scenario-design.md.
"""
import json
from unittest.mock import MagicMock

from src.orchestrator import Orchestrator


def _tool(name):
    return {"function": {"name": name, "arguments": {}}}


def _blue_step(removed: bool) -> Orchestrator:
    red, blue = MagicMock(), MagicMock()
    blue.act.return_value = [_tool("remove_persistence")]
    blue.process_tool_call.return_value = json.dumps(
        {"tool": "remove_persistence", "removed": removed, "target_user": "root"}
    )
    orch = Orchestrator(red, blue, max_tools_per_turn=1)
    orch.state.current_agent_role = "blue"
    orch.step()
    return orch


def test_removed_true_sets_eviction_turn():
    orch = _blue_step(removed=True)
    assert orch.state.blue_persistence_removed_turn is not None


def test_removed_false_does_not_set_eviction_turn():
    orch = _blue_step(removed=False)
    assert orch.state.blue_persistence_removed_turn is None


# --- Windows persistence scoring: credit task/service plant + windows eviction --

def _orch():
    return Orchestrator(MagicMock(), MagicMock(), max_tools_per_turn=1)


def test_red_windows_task_plant_credits_on_target():
    o = _orch()
    out = 'SUCCESS: The scheduled task "Svc" has successfully been created.'
    assert o._check_red_persistence_planted(_tool("execute_command"), out) is True
    # off-target (run_on_attacker) with a Windows signal does NOT credit
    assert o._check_red_persistence_planted(_tool("run_on_attacker"), out) is False


def test_blue_remove_persistence_windows_credits_eviction():
    o = _orch()
    yes = json.dumps({"tool": "remove_persistence_windows", "removed_entries": ["task|Svc"]})
    no = json.dumps({"tool": "remove_persistence_windows", "removed_entries": []})
    assert o._check_blue_persistence_removed(yes) is True
    assert o._check_blue_persistence_removed(no) is False
