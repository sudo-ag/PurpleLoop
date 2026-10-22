"""The Learner runs one agent for N episodes against a target and lets it
accumulate lessons — the portable per-system learning loop, no adversary, no
scoring."""
from src.learner import Learner
from src.agents import RedAgent
from src.mock_executor import MockExecutor


def test_learner_runs_n_episodes_and_reflects(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    monkeypatch.setattr(red, "decide", lambda: "noop")
    monkeypatch.setattr(red, "reflect", lambda outcome=None: red.experience.append("lesson"))
    trajs = Learner(red).train(target=None, episodes=3, max_turns=2)
    assert len(trajs) == 3
    assert red.experience.count("lesson") == 3


def test_learner_resets_between_episodes(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    monkeypatch.setattr(red, "decide", lambda: "noop")
    monkeypatch.setattr(red, "reflect", lambda outcome=None: None)
    Learner(red).train(target=None, episodes=3, max_turns=2)
    # Each episode starts fresh, so history holds only the last episode's turns.
    assert len(red.history) <= 2
