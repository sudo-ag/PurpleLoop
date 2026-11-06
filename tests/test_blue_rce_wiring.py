"""Wiring for the Family 2 (ProFTPD mod_copy RCE) sensors: investigate_webshells
(Task 1) and investigate_ftp_sessions (Task 2) into the blue tool schema/dispatch."""
import json
from unittest.mock import MagicMock

from src.agents import BLUE_TOOL_PRIORITY, BlueAgent


def test_priority_after_privileged_accounts() -> None:
    i = BLUE_TOOL_PRIORITY.index("investigate_privileged_accounts")
    assert "investigate_webshells" in BLUE_TOOL_PRIORITY[i + 1:]
    assert "investigate_ftp_sessions" in BLUE_TOOL_PRIORITY[i + 1:]


def test_webshells_dispatch_routes_to_executor() -> None:
    ex = MagicMock()
    ex.investigate_webshells.return_value = {"tool": "investigate_webshells"}
    blue = BlueAgent(executor=ex, model="llama3.2:latest")
    out = blue.process_tool_call({"function": {"name": "investigate_webshells", "arguments": {}}})
    ex.investigate_webshells.assert_called_once_with()
    assert json.loads(out)["tool"] == "investigate_webshells"


def test_ftp_sessions_dispatch_routes_to_executor() -> None:
    ex = MagicMock()
    # No flag_access_detected key at all, per Task 2 interface (attribution only).
    ex.investigate_ftp_sessions.return_value = {"tool": "investigate_ftp_sessions", "sessions": []}
    blue = BlueAgent(executor=ex, model="llama3.2:latest")
    out = blue.process_tool_call({"function": {"name": "investigate_ftp_sessions", "arguments": {}}})
    ex.investigate_ftp_sessions.assert_called_once_with()
    result = json.loads(out)
    assert result["tool"] == "investigate_ftp_sessions"
    assert "flag_access_detected" not in result


def test_schema_registered() -> None:
    src = open("src/agents.py").read()
    assert "'name': 'investigate_webshells'" in src
    assert "'name': 'investigate_ftp_sessions'" in src
