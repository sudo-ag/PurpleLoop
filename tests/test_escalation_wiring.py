"""Blue wiring for the escalation-paths sensor + doctrine to chain findings."""
import json
from unittest.mock import MagicMock

from src.agents import Agent, BLUE_TOOL_PRIORITY, BLUE_SYSTEM_PROMPT
from src.executor import ToolExecutor


def _blue() -> Agent:
    return Agent("blue", MagicMock(spec=ToolExecutor))


def test_escalation_tool_is_dispatched_to_executor():
    b = _blue()
    b.executor.investigate_escalation_paths.return_value = {
        "tool": "investigate_escalation_paths", "findings": [], "assessment": "CLEAN",
    }
    out = json.loads(b.process_tool_call(
        {"function": {"name": "investigate_escalation_paths", "arguments": {}}}))
    assert out["tool"] == "investigate_escalation_paths"
    assert b.executor.investigate_escalation_paths.called


def test_escalation_is_in_breadth_rotation():
    assert "investigate_escalation_paths" in BLUE_TOOL_PRIORITY


def test_blue_doctrine_tells_it_to_chain_escalation_findings():
    assert "investigate_escalation_paths" in BLUE_SYSTEM_PROMPT
    assert "chain" in BLUE_SYSTEM_PROMPT.lower()
