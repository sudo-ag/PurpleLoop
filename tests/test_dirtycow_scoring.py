"""Rogue uid-0 detection: credited as a T3 defense + removal reflex."""
import json
from unittest.mock import MagicMock

from src.orchestrator import TIER_ROOT, Orchestrator

CALL = [{"function": {"name": "investigate_privileged_accounts", "arguments": {}}}]


def _orch(output: dict, observe: bool = False) -> tuple[Orchestrator, MagicMock]:
    red, blue = MagicMock(), MagicMock()
    red.act.return_value = "idle"
    blue.act.return_value = CALL
    blue.process_tool_call.return_value = json.dumps(output)
    orch = Orchestrator(red, blue, max_tools_per_turn=1, observe=observe)
    orch.state.current_agent_role = "blue"
    blue.executor.remove_privileged_account.return_value = {"removed": True}
    return orch, blue.executor.remove_privileged_account


def test_breach_credits_t3_and_removes_once():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"],
                          "assessment": "BREACH"})
    orch.step()
    assert TIER_ROOT in orch.state.blue_tier_detect
    remove.assert_called_once_with("toor")
    orch._auto_remove_rogue(json.dumps({"suspicious_users": ["toor"]}))
    remove.assert_called_once()  # idempotent
    assert orch.state.rogue_removed


def test_failed_removal_leaves_flag_unset_and_retries():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"]})
    remove.return_value = {"removed": False}
    orch.step()
    assert not orch.state.rogue_removed
    orch._auto_remove_rogue(json.dumps({"suspicious_users": ["toor"]}))
    assert remove.call_count == 2


def test_exception_does_not_propagate():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"]})
    remove.side_effect = OSError("ssh down")
    orch.step()
    assert not orch.state.rogue_removed


def test_all_rogues_removed_before_flag_set():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["a", "b"]})
    remove.side_effect = [{"removed": True}, {"removed": False}]
    orch.step()
    assert [c.args[0] for c in remove.call_args_list] == ["a", "b"]
    assert not orch.state.rogue_removed
    remove.side_effect = [{"removed": True}, {"removed": True}]
    orch._auto_remove_rogue(json.dumps({"suspicious_users": ["a", "b"]}))
    assert orch.state.rogue_removed


def test_partial_failure_retry_skips_done_and_latches():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["a", "b"]})
    detect = json.dumps({"suspicious_users": ["a", "b"]})
    remove.side_effect = [{"removed": True}, {"removed": False}]
    orch._auto_remove_rogue(detect)
    assert not orch.state.rogue_removed
    remove.side_effect = [{"removed": True}]  # only b is attempted; a would report False
    orch._auto_remove_rogue(detect)
    assert orch.state.rogue_removed
    assert [c.args[0] for c in remove.call_args_list] == ["a", "b", "b"]


def test_runs_in_observe_mode():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"]}, observe=True)
    orch.step()
    remove.assert_called_once_with("toor")


def test_clean_credits_and_removes_nothing():
    orch, remove = _orch({"flag_access_detected": False, "suspicious_users": []})
    orch.step()
    assert TIER_ROOT not in orch.state.blue_tier_detect
    remove.assert_not_called()
