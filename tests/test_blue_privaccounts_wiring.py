"""Wiring for the privileged-accounts sensor and the remove-rogue response."""
import json
from unittest.mock import MagicMock

from src.agents import BLUE_TOOL_PRIORITY, BlueAgent
from src.executor import ToolExecutor
from src.mock_executor import MockExecutor


def _executor() -> ToolExecutor:
    ex = ToolExecutor.__new__(ToolExecutor)
    ex.user = "blue"
    ex.execute = MagicMock(return_value="PL_REMOVED")  # type: ignore[method-assign]
    return ex


def test_priority_after_docker() -> None:
    i = BLUE_TOOL_PRIORITY.index("investigate_docker")
    assert BLUE_TOOL_PRIORITY[i + 1] == "investigate_privileged_accounts"


def test_dispatch_routes_to_executor() -> None:
    ex = MagicMock()
    ex.investigate_privileged_accounts.return_value = {"tool": "investigate_privileged_accounts"}
    blue = BlueAgent(executor=ex, model="llama3.2:latest")
    out = blue.process_tool_call({"function": {"name": "investigate_privileged_accounts", "arguments": {}}})
    ex.investigate_privileged_accounts.assert_called_once_with()
    assert json.loads(out)["tool"] == "investigate_privileged_accounts"


def test_schema_registered() -> None:
    src = open("src/agents.py").read()
    assert "'name': 'investigate_privileged_accounts'" in src


def test_remove_refuses_protected() -> None:
    ex = _executor()
    for u in ("root", "vagrant", "blue", ""):
        assert not ex.remove_privileged_account(u)["removed"]
    ex.execute.assert_not_called()


def test_remove_runs_plain_deluser() -> None:
    ex = _executor()
    assert ex.remove_privileged_account("firefart")["removed"]
    cmd = ex.execute.call_args[0][0]
    assert "deluser firefart" in cmd and "--remove-home" not in cmd
