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
