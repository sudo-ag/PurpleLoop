"""Rogue uid-0 detection: credited as a T3 defense + stateless removal reflex."""
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


def _detect(*users: str) -> str:
    return json.dumps({"flag_access_detected": True, "suspicious_users": list(users)})


def test_breach_credits_t3_and_removes():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"],
                          "assessment": "BREACH"})
    orch.step()
    assert TIER_ROOT in orch.state.blue_tier_detect
    remove.assert_called_once_with("toor")


def test_clean_credits_and_removes_nothing():
    orch, remove = _orch({"flag_access_detected": False, "suspicious_users": []})
    orch.step()
    assert TIER_ROOT not in orch.state.blue_tier_detect
    remove.assert_not_called()


def test_all_reported_rogues_removed():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["a", "b"]})
    orch.step()
    assert [c.args[0] for c in remove.call_args_list] == ["a", "b"]


def test_exception_does_not_propagate_and_self_heals():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"]})
    remove.side_effect = OSError("ssh down")
    orch.step()  # must not raise
    remove.side_effect = None
    remove.return_value = {"removed": True}
    orch._auto_remove_rogue(_detect("toor"))  # next BREACH removes it again
    assert remove.call_count == 2


def test_failed_removal_retried_on_next_breach():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"]})
    remove.return_value = {"removed": False}
    orch._auto_remove_rogue(_detect("toor"))
    remove.return_value = {"removed": True}
    orch._auto_remove_rogue(_detect("toor"))
    assert remove.call_count == 2


def test_recreated_same_named_account_is_removed_again():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"]})
    orch._auto_remove_rogue(_detect("toor"))
    orch._auto_remove_rogue(_detect("toor"))  # red re-created it; must not be skipped
    assert remove.call_count == 2


def test_runs_in_observe_mode():
    orch, remove = _orch({"flag_access_detected": True, "suspicious_users": ["toor"]}, observe=True)
    orch.step()
    remove.assert_called_once_with("toor")
