"""Task 2: blue can call remediate_finding; malformed args never crash."""
from unittest.mock import MagicMock
from src.agents import Agent


def test_dispatch_calls_executor_with_finding():
    ex = MagicMock()
    ex.remediate_finding.return_value = {
        "tool": "remediate_finding", "status": "closed", "target": "/opt/sinatra"}
    blue = Agent(role="blue", executor=ex)
    finding = {"category": "writable", "item": "/opt/sinatra"}
    out = blue.process_tool_call(
        {"function": {"name": "remediate_finding", "arguments": {"finding": finding}}})
    ex.remediate_finding.assert_called_once_with(finding)
    assert '"status": "closed"' in out


def test_malformed_args_return_error_payload():
    ex = MagicMock()
    blue = Agent(role="blue", executor=ex)
    out = blue.process_tool_call(
        {"function": {"name": "remediate_finding", "arguments": {}}})  # no finding
    assert '"status": "error"' in out
    ex.remediate_finding.assert_not_called()


def test_remediate_finding_is_in_blue_tools():
    blue = Agent(role="blue", executor=MagicMock())
    names = {t["function"]["name"] for t in blue.tools}
    assert "remediate_finding" in names


def test_dispatch_surface_calls_executor():
    ex = MagicMock()
    ex.remediate_escalation_surface.return_value = {
        "tool": "remediate_escalation_surface",
        "closed": [{"category": "writable", "item": "/opt/sinatra"}]}
    blue = Agent(role="blue", executor=ex)
    out = blue.process_tool_call(
        {"function": {"name": "remediate_escalation_surface", "arguments": {}}})
    ex.remediate_escalation_surface.assert_called_once_with()
    assert "remediate_escalation_surface" in out


def test_surface_in_blue_tools():
    blue = Agent(role="blue", executor=MagicMock())
    names = {t["function"]["name"] for t in blue.tools}
    assert "remediate_escalation_surface" in names
