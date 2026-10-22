import pytest
import json
from unittest.mock import MagicMock
from src.orchestrator import Orchestrator, SimulationState, TIER_FOOTHOLD
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

    # Graded scoring: reading the flag no longer ends the sim instantly — it
    # records the access turn and opens blue's detection window.
    assert winner is None
    assert orch.state.red_captured_flag is True
    assert orch.state.red_access_turn == 0

def test_graded_blue_wins_when_detecting_within_window():
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), detect_within_turns=3)
    orch.state.red_access_turn = 4
    orch.state.blue_detect_turn = 6
    orch.state.turn = 6
    assert orch._resolve_outcome() == "blue"
    assert orch.state.blue_victory is True
    assert orch.detection_dwell() == 2

def _jump_red_orch(detect_within_turns=3):
    red_agent = MagicMock(spec=Agent)
    # Red reaches the target through a jump host, so the attacker IP is .11.
    red_agent.executor = MagicMock()
    red_agent.executor.jump_host = "192.168.64.11"
    blue_agent = MagicMock(spec=Agent)
    return Orchestrator(red_agent, blue_agent, detect_within_turns=detect_within_turns)


def test_containment_before_access_is_a_blue_win():
    orch = _jump_red_orch()
    orch.state.blue_contain_turn = 5
    orch.state.turn = 5
    # red never reached the objective (contained first)
    assert orch._resolve_outcome() == "blue"
    assert orch.state.blue_victory is True


def test_containment_after_access_is_too_late():
    orch = _jump_red_orch()
    orch.state.red_access_turn = 4
    orch.state.blue_contain_turn = 7   # contained, but red already read the flag
    orch.state.turn = 9                # window (3) elapsed with no in-time detect
    assert orch._resolve_outcome() == "red"


def test_containment_of_attacker_ip_is_recorded():
    orch = _jump_red_orch()
    orch.state.current_agent_role = "blue"
    tool_call = {'function': {'name': 'contain_attacker', 'arguments': {'ip': '192.168.64.11'}}}
    orch.blue_agent.act.return_value = [tool_call]
    orch.blue_agent.process_tool_call.return_value = json.dumps({
        "tool": "contain_attacker", "target_ip": "192.168.64.11",
        "contained": True, "assessment": "CONTAINED", "summary": "blocked",
    })
    winner = orch.step()
    assert winner == "blue"
    assert orch.state.blue_contain_turn is not None
    assert orch.state.contained_ip == "192.168.64.11"


def test_containment_of_wrong_ip_is_not_a_win():
    orch = _jump_red_orch()
    orch.state.current_agent_role = "blue"
    tool_call = {'function': {'name': 'contain_attacker', 'arguments': {'ip': '10.0.0.9'}}}
    orch.blue_agent.act.return_value = [tool_call]
    orch.blue_agent.process_tool_call.return_value = json.dumps({
        "tool": "contain_attacker", "target_ip": "10.0.0.9",
        "contained": True, "assessment": "CONTAINED", "summary": "blocked",
    })
    winner = orch.step()
    assert winner is None
    assert orch.state.blue_contain_turn is None


def test_graded_detection_without_access_is_not_a_blue_win():
    # Blue raising a detection with no actual red access is a false alarm, not a
    # win — blue cannot win by crying wolf (the tcpdump false-positive bug).
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), detect_within_turns=3)
    orch.state.blue_detect_turn = 2
    orch.state.turn = 2
    assert orch._resolve_outcome() is None
    assert orch.state.blue_victory is False


def test_graded_detection_before_access_is_not_a_catch():
    # A detection recorded before red actually accessed cannot be a catch of a
    # breach that had not happened yet.
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), detect_within_turns=3)
    orch.state.blue_detect_turn = 2
    orch.state.red_access_turn = 5
    orch.state.turn = 5
    assert orch._resolve_outcome() is None

def test_graded_red_wins_when_window_elapses_undetected():
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), detect_within_turns=3)
    orch.state.red_access_turn = 4
    orch.state.turn = 8  # 8 - 4 = 4 > 3, window closed with no detection
    assert orch._resolve_outcome() == "red"

def test_graded_late_detection_scores_red():
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), detect_within_turns=3)
    orch.state.red_access_turn = 4
    orch.state.blue_detect_turn = 9  # dwell 5 > 3
    orch.state.turn = 9
    assert orch._resolve_outcome() == "red"

def test_graded_window_still_open_is_undecided():
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), detect_within_turns=3)
    orch.state.red_access_turn = 4
    orch.state.turn = 6  # 6 - 4 = 2 <= 3, blue still has time
    assert orch._resolve_outcome() is None

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

def test_max_tools_per_turn_limits_single_tool_batch():
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    tool_calls = [
        {'function': {'name': 'execute_command', 'arguments': {'command': 'whoami'}}},
        {'function': {'name': 'execute_command', 'arguments': {'command': 'id'}}},
        {'function': {'name': 'execute_command', 'arguments': {'command': 'uname -a'}}},
        {'function': {'name': 'execute_command', 'arguments': {'command': 'hostname'}}},
        {'function': {'name': 'execute_command', 'arguments': {'command': 'pwd'}}},
    ]
    red_agent.act.return_value = tool_calls
    red_agent.process_tool_call.return_value = "some output"

    orch = Orchestrator(red_agent, blue_agent, max_tools_per_turn=3)
    orch.step()

    red_tool_calls = [h for h in orch.state.history if h.get("role") == "red" and "tool" in h]
    assert len(red_tool_calls) == 3
    processed_commands = [
        call.args[0]["function"]["arguments"]["command"]
        for call in red_agent.process_tool_call.call_args_list
    ]
    assert processed_commands == ["whoami", "id", "uname -a"]

def test_generate_report_shows_blue_winner_when_blue_victory():
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    orch = Orchestrator(red_agent, blue_agent)
    orch.state.blue_victory = True
    orch.state.current_agent_role = "red"

    report = orch.generate_report()

    assert "**Final Result:** Winner: BLUE" in report


def test_report_shows_graded_outcome_and_dwell():
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), detect_within_turns=3)
    orch.state.red_captured_flag = True   # red reached the flag...
    orch.state.red_access_turn = 4
    orch.state.blue_detect_turn = 6
    orch.state.blue_victory = True        # ...but blue detected in time
    orch.state.turn = 6

    report = orch.generate_report()

    assert "**Final Result:** Winner: BLUE" in report
    assert "Red reached objective:** turn 4" in report
    assert "Blue detected breach:** turn 6" in report
    assert "Detection dwell:** 2 turn(s)" in report

def test_duplicate_red_command_only_executes_once_per_turn():
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    repeated_call = {'function': {'name': 'execute_command', 'arguments': {'command': 'whoami'}}}
    red_agent.act.return_value = [repeated_call, repeated_call, repeated_call]
    red_agent.process_tool_call.return_value = "root"

    orch = Orchestrator(red_agent, blue_agent, max_tools_per_turn=3)
    orch.step()

    red_tool_calls = [h for h in orch.state.history if h.get("role") == "red" and "tool" in h]
    assert len(red_tool_calls) == 1
    red_agent.process_tool_call.assert_called_once_with(repeated_call)

def test_blue_compromise_evidence_wins_immediately():
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    tool_call = {
        'function': {
            'name': 'investigate_file_access',
            'arguments': {'file_path': '/root/flag.txt'},
        }
    }
    blue_agent.act.return_value = [tool_call]
    # A CONFIRMED in-window flag read (flag_access_detected True) — the only kind
    # of file-access finding that counts as catching the objective.
    blue_agent.process_tool_call.return_value = json.dumps({
        "tool": "investigate_file_access",
        "file_path": "/root/flag.txt",
        "file_exists": True,
        "flag_access_detected": True,
        "assessment": "BREACH",
        "summary": "CRITICAL: Sensitive file /root/flag.txt was read during this engagement.",
    })

    orch = Orchestrator(red_agent, blue_agent)
    orch.state.current_agent_role = "blue"
    winner = orch.step()

    assert winner == "blue"
    assert orch.state.blue_victory is True
    # Blue's confirmed flag detection corroborates that red accessed the objective.
    assert orch.state.red_access_turn is not None

def test_red_text_response_retries_for_tool_call():
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    tool_call = {'function': {'name': 'execute_command', 'arguments': {'command': 'whoami'}}}
    red_agent.act.side_effect = [
        "Here is a Python script that parses the report.",
        [tool_call],
    ]
    red_agent.process_tool_call.return_value = "vagrant"

    orch = Orchestrator(red_agent, blue_agent)
    orch.step()

    red_tool_calls = [h for h in orch.state.history if h.get("role") == "red" and "tool" in h]
    assert len(red_tool_calls) == 1
    red_agent.process_tool_call.assert_called_once_with(tool_call)

def test_blue_guidance_orders_containment_only_with_malice_evidence():
    from src.agents import BlueAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    blue.executor.control_source_ip = "192.168.64.1"

    # A bare foreign connection (no scan) must NOT trigger a containment order.
    blue.history = [Turn(0, "", {"function": {"name": "investigate_connections", "arguments": {}}},
        '{"tool": "investigate_connections", "foreign_ips": ["192.168.64.11"], "suspicious_ips": [], "port_scanners": []}')]
    assert "contain_attacker" not in blue.build_observation()

    # A port scan IS evidence of malice → blue is ordered to contain it.
    blue.history.append(Turn(1, "", {"function": {"name": "investigate_connections", "arguments": {}}},
        '{"tool": "investigate_connections", "port_scanners": ["192.168.64.11"], "suspicious_ips": ["192.168.64.11"]}'))
    summary = blue.build_observation()
    assert "contain_attacker" in summary
    assert "192.168.64.11" in summary


def test_blue_guidance_contains_on_brute_force_spike():
    from src.agents import BlueAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    blue.executor.control_source_ip = "192.168.64.1"
    blue.history = [Turn(0, "", {"function": {"name": "investigate_logs", "arguments": {}}},
        '{"tool": "investigate_logs", "failed_attempts": 12, "suspicious_ips": ["192.168.64.11"]}')]
    assert "contain_attacker" in blue.build_observation()


def test_blue_guidance_defaults_to_logs_heartbeat():
    # Whenever the last blue action was NOT investigate_logs, blue is steered
    # straight back to it — the only reliable flag-read detector.
    from src.agents import BlueAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    blue.history = [Turn(0, "", {"function": {"name": "investigate_processes", "arguments": {}}}, "{}")]

    summary = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)

    assert "Blue guidance:" in summary
    assert "Call `investigate_logs` now" in summary
    assert "Do NOT declare the system clean" in summary
    assert "Already run: investigate_processes" in summary


def test_blue_guidance_covers_breadth_right_after_a_logs_check():
    # Right after a logs check, spend one turn on breadth, then return to logs.
    from src.agents import BlueAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    blue.history = [Turn(0, "", {"function": {"name": "investigate_logs", "arguments": {}}}, "{}")]

    summary = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)

    # investigate_logs was last; steer to the top unused breadth tool
    # (investigate_connections — blue's network-recon visibility) and promise a
    # return to logs next turn.
    assert "investigate_connections" in summary
    assert "go back to `investigate_logs` next turn" in summary


def test_blue_guidance_returns_to_logs_after_full_sweep():
    # Even after every tool has run once, a non-logs last action sends blue back
    # to the logs heartbeat rather than stopping.
    from src.agents import BlueAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    blue.history = [
        Turn(0, "", {"function": {"name": name, "arguments": {}}}, "{}")
        for name in (
            "investigate_logs",
            "investigate_file_access",
            "investigate_processes",
            "investigate_users",
            "investigate_cron",
            "investigate_network",
        )
    ]

    summary = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)

    assert "Call `investigate_logs` now" in summary
    assert "Do NOT declare the system clean" in summary

def test_blue_suspicious_processes_do_not_confirm_victory():
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    tool_call = {'function': {'name': 'investigate_processes', 'arguments': {}}}
    blue_agent.act.return_value = [tool_call]
    blue_agent.process_tool_call.return_value = json.dumps({
        "tool": "investigate_processes",
        "assessment": "SUSPICIOUS",
        "suspicious_count": 2,
        "critical_count": 0,
        "summary": "Suspicious SSH-related processes detected.",
    })

    orch = Orchestrator(red_agent, blue_agent)
    orch.state.current_agent_role = "blue"
    winner = orch.step()

    assert winner is None
    assert orch.state.blue_victory is False

def test_process_breach_on_benign_service_is_not_a_victory():
    # The live false positive: investigate_processes returns assessment BREACH
    # because a benign baseline service (tcpdump) was flagged critical. With no
    # flag_access_detected, this must NOT confirm a blue win.
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    tool_call = {'function': {'name': 'investigate_processes', 'arguments': {}}}
    blue_agent.act.return_value = [tool_call]
    blue_agent.process_tool_call.return_value = json.dumps({
        "tool": "investigate_processes",
        "assessment": "BREACH",
        "suspicious_count": 1,
        "critical_count": 1,
        "summary": "CRITICAL: Suspicious processes that may indicate attacker activity.",
    })

    orch = Orchestrator(red_agent, blue_agent)
    orch.state.current_agent_role = "blue"
    winner = orch.step()

    assert winner is None
    assert orch.state.blue_victory is False
    assert orch.state.blue_detect_turn is None

def test_blue_text_response_before_confirmed_evidence_retries_for_tool_call():
    red_agent = MagicMock(spec=Agent)
    blue_agent = MagicMock(spec=Agent)
    tool_call = {'function': {'name': 'investigate_logs', 'arguments': {'log_type': 'auth'}}}
    blue_agent.act.side_effect = [
        "The process output is suspicious and should be investigated further.",
        [tool_call],
    ]
    blue_agent.process_tool_call.return_value = json.dumps({
        "tool": "investigate_logs",
        "assessment": "CLEAN",
        "suspicious_count": 0,
        "summary": "No confirmed compromise.",
    })

    orch = Orchestrator(red_agent, blue_agent)
    orch.state.current_agent_role = "blue"
    orch.step()

    blue_tool_calls = [h for h in orch.state.history if h.get("role") == "blue" and "tool" in h]
    assert len(blue_tool_calls) == 1
    blue_agent.process_tool_call.assert_called_once_with(tool_call)

def test_outcome_brief_red_containment_is_causal_and_factual():
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    orch.state.blue_victory = True
    orch.state.blue_contain_turn = 1
    orch.state.contained_ip = "192.168.64.11"

    red = orch._outcome_brief("red")
    assert "LOST" in red and "contained" in red and "turn 1" in red
    # No hint about WHICH action was loud — red must infer scan -> caught itself.
    assert "scan" not in red.lower() and "brute" not in red.lower()

    blue = orch._outcome_brief("blue")
    assert "WON" in blue and "turn 1" in blue

def test_outcome_brief_red_win_and_stalemate():
    orch = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    orch.state.red_captured_flag = True
    orch.state.red_access_turn = 7
    assert "WON" in orch._outcome_brief("red") and "turn 7" in orch._outcome_brief("red")
    assert "LOST" in orch._outcome_brief("blue")

    fresh = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    assert "Stalemate" in fresh._outcome_brief("red")

def test_observe_mode_holds_containment_no_real_drop():
    # Blue in observe mode must NOT fire the real iptables DROP — red keeps going.
    mock_executor = MagicMock(spec=ToolExecutor)
    blue = Agent(role="blue", executor=mock_executor, observe=True)
    out = json.loads(blue.process_tool_call(
        {'function': {'name': 'contain_attacker', 'arguments': {'ip': '192.168.64.11'}}}
    ))
    assert out["status"] == "observed" and out["contained"] is False
    mock_executor.contain_attacker.assert_not_called()

def test_observe_mode_suppresses_containment_order():
    from src.agents import BlueAgent
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    # Observe mode holds the order; aggressive mode still issues it.
    assert "CONTAIN" not in blue.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "CONTAIN" in blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)


# --- Task 4: red phase logic self-contained in RedAgent -------------------

def test_redagent_phase_guidance_matches_legacy_flag_discovery():
    from src.agents import RedAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.history = [
        Turn(0, "", {"function": {"name": "execute_command", "arguments": {"command": "whoami"}}}, "vagrant"),
        Turn(1, "", {"function": {"name": "execute_command", "arguments": {"command": "id"}}},
             "uid=900(vagrant) gid=900(vagrant) groups=900(vagrant),27(sudo)"),
    ]
    g = red.phase_guidance()
    assert "Red Phase: flag_discovery" in g
    assert "find / -maxdepth 4 -name flag.txt" in g


def test_redagent_unprivileged_foothold_goes_to_privilege_check():
    from src.agents import RedAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.has_foothold = True
    red.history = [
        Turn(0, "", {"function": {"name": "execute_command", "arguments": {"command": "id"}}},
             "uid=1120(lando_calrissian) gid=100(users) groups=100(users)"),
    ]
    g = red.phase_guidance()
    assert "Red Phase: privilege_check" in g
    assert "ESCALATE" in g


def test_redagent_flag_read_after_finding_path():
    from src.agents import RedAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.history = [
        Turn(0, "", {"function": {"name": "execute_command",
             "arguments": {"command": "find / -maxdepth 4 -name flag.txt 2>/dev/null"}}}, "/root/flag.txt"),
    ]
    g = red.phase_guidance()
    assert "Red Phase: flag_read" in g
    assert "sudo cat /root/flag.txt" in g
    assert "Discovered path(s): /root/flag.txt" in g


def test_redagent_flag_read_on_confirmed_root():
    from src.agents import RedAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.history = [
        Turn(0, "", {"function": {"name": "execute_command", "arguments": {"command": "sudo -n -l"}}},
             "User vagrant may run the following commands on ubuntu:\n    (ALL : ALL) NOPASSWD: ALL"),
    ]
    g = red.phase_guidance()
    assert "Red Phase: flag_read" in g
    assert "sudo cat /root/flag.txt" in g
    assert "passwordless root" in g


# --- Task 5: blue tool-steering self-contained in BlueAgent ---------------

def test_blueagent_tool_guidance_defaults_to_logs_heartbeat():
    from src.agents import BlueAgent
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    g = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "investigate_logs" in g


def test_blueagent_contain_order_on_confirmed_attacker():
    from src.agents import BlueAgent
    from src.mock_executor import MockExecutor
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "contain_attacker" in g and "192.168.64.11" in g


# --- Task 6: repeat-nudge self-contained in Agent -------------------------

def test_repeat_nudge_fires_on_repeated_tool_calls():
    from src.agents import RedAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    call = {"function": {"name": "execute_command", "arguments": {"command": "ls"}}}
    # Two different turns (distinct observations) issuing the SAME call → repeat.
    red.history = [Turn(0, "obs-turn-1", call, "a"), Turn(1, "obs-turn-2", call, "a")]
    assert "Repetition check" in red.repeat_nudge()


def test_repeat_nudge_silent_on_new_action():
    from src.agents import RedAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    c1 = {"function": {"name": "execute_command", "arguments": {"command": "ls"}}}
    c2 = {"function": {"name": "execute_command", "arguments": {"command": "whoami"}}}
    red.history = [Turn(0, "obs-turn-1", c1, "a"), Turn(1, "obs-turn-2", c2, "b")]
    assert red.repeat_nudge() == ""
