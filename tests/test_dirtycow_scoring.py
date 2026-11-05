"""Rogue uid-0 detection: credited as a T3 defense + removal reflex."""
import json
from unittest.mock import MagicMock

from src.orchestrator import TIER_ROOT, Orchestrator

CALL = [{"function": {"name": "investigate_privileged_accounts", "arguments": {}}}]


def _orch(output: dict) -> tuple[Orchestrator, MagicMock]:
    red, blue = MagicMock(), MagicMock()
    red.act.return_value = "idle"
    blue.act.return_value = CALL
    blue.process_tool_call.return_value = json.dumps(output)
    orch = Orchestrator(red, blue, max_tools_per_turn=1)
    orch.state.current_agent_role = "blue"
    blue.executor.remove_privileged_account.return_value = {"assessment": "REMOVED"}
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


def test_clean_credits_and_removes_nothing():
    orch, remove = _orch({"flag_access_detected": False, "suspicious_users": []})
    orch.step()
    assert TIER_ROOT not in orch.state.blue_tier_detect
    remove.assert_not_called()
