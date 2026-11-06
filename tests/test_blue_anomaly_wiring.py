"""Wiring for investigate_box_anomalies (Task 2's catch-all ports/users sensor)
into the blue tool schema/dispatch/priority list."""
import json
from unittest.mock import MagicMock

from src.agents import BLUE_TOOL_PRIORITY, BlueAgent


def test_priority_contains_box_anomalies() -> None:
    assert "investigate_box_anomalies" in BLUE_TOOL_PRIORITY


def test_box_anomalies_dispatch_routes_to_executor() -> None:
    ex = MagicMock()
    ex.investigate_box_anomalies.return_value = {"tool": "investigate_box_anomalies"}
    blue = BlueAgent(executor=ex, model="llama3.2:latest")
    out = blue.process_tool_call({"function": {"name": "investigate_box_anomalies", "arguments": {}}})
    ex.investigate_box_anomalies.assert_called_once_with()
    assert json.loads(out)["tool"] == "investigate_box_anomalies"


def test_schema_registered() -> None:
    src = open("src/agents.py").read()
    assert "'name': 'investigate_box_anomalies'" in src
