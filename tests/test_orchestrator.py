import pytest
from unittest.mock import MagicMock
from src.orchestrator import Orchestrator, SimulationState
from src.agents import Agent
from src.executor import ToolExecutor

def test_turn_rotation():
    # Setup mocks
    mock_executor = MagicMock(spec=ToolExecutor)
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)

    # Red agent returns a simple string (no tool calls)
    red_agent.act.return_value = "Red is thinking"
    blue_agent.act.return_value = "Blue is thinking"

    orch = Orchestrator(red_agent, blue_agent)

    # Initial state
    assert orch.state.current_agent_role == "red"

    # Step 1: Red acts
    orch.step()
    assert orch.state.current_agent_role == "blue"
    assert orch.state.turn == 1

    # Step 2: Blue acts
    orch.step()
    assert orch.state.current_agent_role == "red"
    assert orch.state.turn == 2

def test_red_victory():
    mock_executor = MagicMock(spec=ToolExecutor)
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)

    # Red agent calls a tool that returns the flag
    red_agent.act.return_value = [
        {'function': {'name': 'execute_command', 'arguments': {'command': 'cat /root/flag.txt'}}}
    ]
    red_agent.process_tool_call.return_value = "FLAG{this_is_the_flag}"

    orch = Orchestrator(red_agent, blue_agent)
    winner = orch.step()

    assert winner == "red"
    assert orch.state.red_captured_flag is True

def test_blue_victory_stall():
    mock_executor = MagicMock(spec=ToolExecutor)
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)

    # Red agent always returns a string (stalling)
    red_agent.act.return_value = "I can't find anything"
    blue_agent.act.return_value = "I am monitoring"

    orch = Orchestrator(red_agent, blue_agent, stall_limit=2)

    # Turn 0: Red acts (stalls)
    orch.step() # Red acts, then rotate to Blue
    # Turn 1: Blue acts
    orch.step() # Blue acts, then rotate to Red
    # Turn 2: Red acts (stalls)
    winner = orch.step()

    assert winner == "blue"
    assert orch.state.blue_victory is True

def test_max_tools_per_turn():
    mock_executor = MagicMock(spec=ToolExecutor)
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)

    # Red agent keeps calling tools
    red_agent.act.side_effect = [
        [{'function': {'name': 'execute_command', 'arguments': {'command': 'ls'}}}],
        [{'function': {'name': 'execute_command', 'arguments': {'command': 'whoami'}}}],
        [{'function': {'name': 'execute_command', 'arguments': {'command': 'id'}}}],
        [{'function': {'name': 'execute_command', 'arguments': {'command': 'uname -a'}}}],
    ]
    red_agent.process_tool_call.return_value = "some output"

    orch = Orchestrator(red_agent, blue_agent, max_tools_per_turn=3)
    orch.step()

    # Red should have been limited to 3 tool calls
    # We can check the history
    red_tool_calls = [h for h in orch.state.history if h.get('role') == 'red' and 'tool' in h]
    assert len(red_tool_calls) == 3
