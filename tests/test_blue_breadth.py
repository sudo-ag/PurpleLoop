"""Blue breadth steering rotates least-recently-used instead of sticking."""
from unittest.mock import MagicMock

from src.agents import Agent
from src.orchestrator import Orchestrator


def _orch() -> Orchestrator:
    return Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))


def _blue(name: str) -> dict:
    return {"role": "blue", "tool": {"function": {"name": name, "arguments": {}}}, "output": "ok"}


def test_breadth_rotates_to_least_recently_used():
    orch = _orch()
    # Every breadth tool used once (connections oldest, network newest), last = logs.
    orch.state.history = [
        _blue("investigate_connections"),
        _blue("investigate_file_access"),
        _blue("investigate_processes"),
        _blue("investigate_users"),
        _blue("investigate_cron"),
        _blue("investigate_network"),
        _blue("investigate_logs"),
    ]
    guidance = orch._blue_tool_guidance()
    # Oldest-used breadth tool is connections → that is what blue is steered to,
    # not the old default (investigate_file_access).
    assert "`investigate_connections`" in guidance
    assert "`investigate_file_access` —" not in guidance
