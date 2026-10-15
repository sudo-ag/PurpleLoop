"""Anti-loop nudge: fire only when an agent's whole last turn was repeats."""
from unittest.mock import MagicMock

from src.agents import Agent
from src.orchestrator import Orchestrator


def _orch() -> Orchestrator:
    return Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))


def _entry(role: str, turn: int, name: str, args: dict, out: str = "ok") -> dict:
    return {
        "role": role,
        "turn": turn,
        "tool": {"function": {"name": name, "arguments": args}},
        "output": out,
    }


def test_repeated_red_command_fires_nudge():
    orch = _orch()
    orch.state.history = [
        _entry("red", 6, "execute_command", {"command": "sudo -l"}),
        _entry("red", 8, "execute_command", {"command": "sudo -l"}),
    ]
    assert "Repetition check" in orch._repeat_nudge("red")


def test_novel_action_last_turn_no_nudge():
    orch = _orch()
    orch.state.history = [
        _entry("red", 6, "execute_command", {"command": "sudo -l"}),
        _entry("red", 8, "execute_command", {"command": "find / -perm -4000"}),
    ]
    assert orch._repeat_nudge("red") == ""


def test_partial_repeat_turn_no_nudge():
    # A turn mixing one old and one new command still counts as progress.
    orch = _orch()
    orch.state.history = [
        _entry("red", 6, "execute_command", {"command": "sudo -l"}),
        _entry("red", 8, "execute_command", {"command": "sudo -l"}),
        _entry("red", 8, "execute_command", {"command": "cat /etc/crontab"}),
    ]
    assert orch._repeat_nudge("red") == ""


def test_blue_logs_heartbeat_never_nudged():
    orch = _orch()
    orch.state.history = [
        _entry("blue", 1, "investigate_logs", {"log_type": "auth"}),
        _entry("blue", 3, "investigate_logs", {"log_type": "auth"}),
    ]
    assert orch._repeat_nudge("blue") == ""


def test_blue_repeated_breadth_tool_fires_nudge():
    orch = _orch()
    orch.state.history = [
        _entry("blue", 3, "investigate_file_access", {"file_path": "/root/flag.txt"}),
        _entry("blue", 5, "investigate_logs", {"log_type": "auth"}),
        _entry("blue", 5, "investigate_file_access", {"file_path": "/root/flag.txt"}),
    ]
    assert "Repetition check" in orch._repeat_nudge("blue")
