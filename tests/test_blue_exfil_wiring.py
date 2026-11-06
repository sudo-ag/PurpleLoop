"""Wiring for the Family 3 Part 1 (exfil) sensor: investigate_web_requests
(Task 1) into the blue tool schema/dispatch/BLUE_TOOL_PRIORITY."""
import json
from unittest.mock import MagicMock

from src.agents import BLUE_TOOL_PRIORITY, BlueAgent


def test_priority_after_box_anomalies() -> None:
    i = BLUE_TOOL_PRIORITY.index("investigate_box_anomalies")
    assert "investigate_web_requests" in BLUE_TOOL_PRIORITY[i + 1:]


def test_web_requests_dispatch_routes_to_executor() -> None:
    ex = MagicMock()
    # No flag_access_detected key at all, per Task 1 interface (attribution only).
    ex.investigate_web_requests.return_value = {"tool": "investigate_web_requests", "bursts": []}
    blue = BlueAgent(executor=ex, model="llama3.2:latest")
    out = blue.process_tool_call({"function": {"name": "investigate_web_requests", "arguments": {}}})
    ex.investigate_web_requests.assert_called_once_with()
    result = json.loads(out)
    assert result["tool"] == "investigate_web_requests"
    assert "flag_access_detected" not in result


def test_web_requests_dispatch_error_is_caught() -> None:
    ex = MagicMock()
    ex.investigate_web_requests.side_effect = RuntimeError("boom")
    blue = BlueAgent(executor=ex, model="llama3.2:latest")
    out = blue.process_tool_call({"function": {"name": "investigate_web_requests", "arguments": {}}})
    result = json.loads(out)
    assert result["status"] == "error"


def test_schema_registered() -> None:
    src = open("src/agents.py").read()
    assert "'name': 'investigate_web_requests'" in src
