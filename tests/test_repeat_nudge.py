"""Anti-loop nudge: fire only when an agent's whole last turn was repeats.

The nudge now lives on the agent, reading its own history. Turns in one sim
turn share an observation, so we tag each Turn's observation with its turn.
"""
from src.agents import RedAgent, BlueAgent
from src.trajectory import Turn
from src.mock_executor import MockExecutor


def _turn(turn: int, name: str, args: dict, out: str = "ok") -> Turn:
    return Turn(turn, f"turn-{turn}", {"function": {"name": name, "arguments": args}}, out)


def _red() -> RedAgent:
    return RedAgent(executor=MockExecutor(), model="llama3.2:latest")


def _blue() -> BlueAgent:
    return BlueAgent(executor=MockExecutor(), model="llama3.2:latest")


def test_repeated_red_command_fires_nudge():
    red = _red()
    red.history = [
        _turn(6, "execute_command", {"command": "sudo -l"}),
        _turn(8, "execute_command", {"command": "sudo -l"}),
    ]
    assert "Repetition check" in red.repeat_nudge()


def test_novel_action_last_turn_no_nudge():
    red = _red()
    red.history = [
        _turn(6, "execute_command", {"command": "sudo -l"}),
        _turn(8, "execute_command", {"command": "find / -perm -4000"}),
    ]
    assert red.repeat_nudge() == ""


def test_partial_repeat_turn_no_nudge():
    # A turn mixing one old and one new command still counts as progress.
    red = _red()
    red.history = [
        _turn(6, "execute_command", {"command": "sudo -l"}),
        _turn(8, "execute_command", {"command": "sudo -l"}),
        _turn(8, "execute_command", {"command": "cat /etc/crontab"}),
    ]
    assert red.repeat_nudge() == ""


def test_blue_logs_heartbeat_never_nudged():
    blue = _blue()
    blue.history = [
        _turn(1, "investigate_logs", {"log_type": "auth"}),
        _turn(3, "investigate_logs", {"log_type": "auth"}),
    ]
    assert blue.repeat_nudge() == ""


def test_blue_repeated_breadth_tool_fires_nudge():
    blue = _blue()
    blue.history = [
        _turn(3, "investigate_file_access", {"file_path": "/root/flag.txt"}),
        _turn(5, "investigate_logs", {"log_type": "auth"}),
        _turn(5, "investigate_file_access", {"file_path": "/root/flag.txt"}),
    ]
    assert "Repetition check" in blue.repeat_nudge()
