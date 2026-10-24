"""Blue breadth steering rotates least-recently-used instead of sticking.

The steering now lives on BlueAgent, computed from the agent's own history.
"""
from src.agents import BlueAgent
from src.trajectory import Turn
from src.mock_executor import MockExecutor


def _turn(name: str) -> Turn:
    return Turn(0, "", {"function": {"name": name, "arguments": {}}}, "ok")


def test_breadth_rotates_to_least_recently_used():
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    # Every breadth tool used once (connections oldest, network newest), last = logs.
    blue.history = [_turn(n) for n in (
        "investigate_connections",
        "investigate_file_access",
        "investigate_processes",
        "investigate_docker",
        "investigate_users",
        "investigate_cron",
        "investigate_network",
        "investigate_logs",
    )]
    guidance = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    # Oldest-used breadth tool is connections → that is what blue is steered to,
    # not the old default (investigate_file_access).
    assert "`investigate_connections`" in guidance
    assert "`investigate_file_access` —" not in guidance
