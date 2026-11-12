"""run_simulation captures each agent's per-episode reflect() lesson onto state."""
from unittest.mock import MagicMock

from src.orchestrator import Orchestrator


def _orch() -> Orchestrator:
    # Unspecced mocks so run_simulation can touch any agent attribute; the
    # explicit return_values below drive the turn/reflect branches.
    return Orchestrator(MagicMock(), MagicMock())


def test_run_simulation_captures_each_agents_lesson_onto_state():
    orch = _orch()
    orch.red_agent.reflect.return_value = "red lesson"
    orch.blue_agent.reflect.return_value = "blue lesson"
    orch.red_agent.act.return_value = "stop"     # text -> turns end cleanly
    orch.blue_agent.act.return_value = "stop"
    orch.red_agent.build_observation.return_value = "obs"
    orch.blue_agent.build_observation.return_value = "obs"
    orch.run_simulation(max_turns=1)
    assert orch.state.red_lesson == "red lesson"
    assert orch.state.blue_lesson == "blue lesson"
