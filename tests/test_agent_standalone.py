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
