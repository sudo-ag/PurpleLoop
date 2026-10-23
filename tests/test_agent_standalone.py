"""Standalone-agent path: Trajectory vocabulary, Red/BlueAgent subclasses,
own-history, decide(), run(). Built incrementally across the Phase-1 plan.
"""
from src.trajectory import Turn, Trajectory
from src.agents import RedAgent, BlueAgent
from src.mock_executor import MockExecutor


def test_trajectory_dataclasses_hold_turns():
    t = Trajectory(role="red", turns=[Turn(n=0, observation="o", action=None, output="x")])
    assert t.objective_met is False
    assert t.turns[0].output == "x"


def test_red_blue_agents_are_agents_with_fixed_roles():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    assert red.role == "red" and blue.role == "blue"


def test_agent_records_its_own_turns():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.record_turn(observation="obs", action=[{"x": 1}], output="out")
    assert len(red.history) == 1
    assert red.history[0].observation == "obs"


def test_decide_on_empty_history_builds_initial_observation(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    captured = {}
    monkeypatch.setattr(red, "act", lambda obs: captured.setdefault("obs", obs))
    red.decide()
    assert "Red Phase: initial_enum" in captured["obs"]


def test_red_role_guidance_resurfaces_captured_cred():
    from src.trajectory import Turn
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.history = [Turn(0, "", {"function": {"name": "use_credential",
        "arguments": {"username": "han_solo", "password": "nerf_herder"}}},
        '{"tool": "use_credential", "status": "success", "user": "han_solo"}')]
    obs = red.build_observation()
    assert "nerf_herder" in obs and "sudo -S" in obs
    assert red.has_foothold is True


def test_agent_loads_empty_lessons_when_file_missing(tmp_path):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest",
                   knowledge_path=tmp_path / "nope.json")
    assert red.experience == []     # no crash, empty lessons


def test_reflect_persists_lesson(tmp_path, monkeypatch):
    import json
    kp = tmp_path / "k.json"
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", knowledge_path=kp)
    monkeypatch.setattr(red, "summarize_experience", lambda hist, outcome=None: "use --random-agent")
    red.reflect("neutral")
    assert "use --random-agent" in json.loads(kp.read_text())["red"]


def test_reset_episode_clears_per_episode_state_keeps_knowledge():
    from src.trajectory import Turn
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.experience = ["lesson A"]
    red.history = [Turn(0, "", {"function": {"name": "x", "arguments": {}}}, "y")]
    red.foothold_cred = {"user": "lando", "pwd": "x"}
    red.has_foothold = True
    red.phase = "flag_read"
    red.reset_episode()
    assert red.history == []
    assert red.foothold_cred is None
    assert red.has_foothold is False
    assert red.phase == "initial_enum"
    assert red.experience == ["lesson A"]   # knowledge survives the reset


# --- Task 10: standalone run() loop ---------------------------------------

def test_red_objective_met_on_flag_in_history():
    from src.trajectory import Turn
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.history = [Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}}, "FLAG{purple_loop_victory}")]
    assert red.objective_met() is True


def test_red_run_stops_at_max_turns_without_objective(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    monkeypatch.setattr(red, "decide", lambda: "noop")       # never wins
    traj = red.run(max_turns=3)
    assert isinstance(traj, Trajectory) and traj.objective_met is False
    assert len(traj.turns) <= 3


def test_run_survives_executor_error(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    def boom():
        raise RuntimeError("ssh died")
    monkeypatch.setattr(red, "decide", boom)                 # partial, no crash
    traj = red.run(max_turns=2)
    assert isinstance(traj, Trajectory)


def test_blue_monitor_terminates_at_max_turns(monkeypatch):
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    monkeypatch.setattr(blue, "decide", lambda: "watch")     # a monitor never "wins"
    traj = blue.run(max_turns=2)
    assert len(traj.turns) <= 2 and traj.objective_met is False


def test_run_records_dict_shaped_turns_its_brain_can_read(monkeypatch):
    # Regression (reviewer CRITICAL): run() must record one dict-action Turn per
    # tool call, or the agent's own steering (which filters isinstance(action,dict))
    # reads an empty history and self-steers with a dead brain.
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    calls = [{"function": {"name": "execute_command", "arguments": {"command": "id"}}}]
    monkeypatch.setattr(red, "act", lambda obs: calls)
    monkeypatch.setattr(red, "process_tool_call", lambda c: "uid=1120(lando)")
    traj = red.run(max_turns=1)
    assert red._tool_turns(), "run() must record dict-shaped tool turns the brain can read"
    assert traj.turns and isinstance(traj.turns[-1].action, dict)


def test_objective_met_is_case_insensitive():
    from src.trajectory import Turn
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.history = [Turn(0, "", {"function": {"name": "x", "arguments": {}}}, "flag{lowercase_read}")]
    assert red.objective_met() is True   # matches orchestrator's case-insensitive check


def test_reset_episode_clears_last_observation():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red._last_observation = "stale from last episode"
    red.reset_episode()
    assert red._last_observation == ""


# --- live tool-call objects are NOT dicts: normalize so the brain can read them

class _FakeFn:
    def __init__(self, name, arguments):
        self._d = {"name": name, "arguments": arguments}
    def get(self, k, default=None):
        return self._d.get(k, default)
    def __getitem__(self, k):
        return self._d[k]


class _FakeToolCall:
    """Mimics an ollama ToolCall: supports .get/[] but is NOT a dict."""
    def __init__(self, name, arguments):
        self._fn = _FakeFn(name, arguments)
    def get(self, k, default=None):
        return self._fn if k == "function" else default
    def __getitem__(self, k):
        if k == "function":
            return self._fn
        raise KeyError(k)


def test_record_turn_normalizes_toolcall_object_to_dict():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    tc = _FakeToolCall("execute_command", {"command": "id"})
    assert not isinstance(tc, dict)
    red.record_turn("obs", tc, "uid=1120(lando)")
    stored = red.history[0].action
    assert isinstance(stored, dict)
    assert stored["function"]["name"] == "execute_command"
    assert stored["function"]["arguments"] == {"command": "id"}
    assert red._tool_turns()   # steering can now read the turn


def test_run_executes_toolcall_actions_not_skips_them(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    tc = _FakeToolCall("execute_command", {"command": "id"})
    monkeypatch.setattr(red, "act", lambda obs: [tc])
    ran = {}
    monkeypatch.setattr(red, "process_tool_call", lambda c: ran.setdefault("ran", True) and "" or "uid=1120")
    traj = red.run(max_turns=1)
    assert ran.get("ran") is True                      # executed, not skipped by a dict guard
    assert isinstance(traj.turns[-1].action, dict)     # stored normalized
    assert red._tool_turns()                           # brain reads it
