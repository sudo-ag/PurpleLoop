"""The case lives on SimulationState and is handed to blue each blue turn."""
from unittest.mock import MagicMock

from src.agents import Agent
from src.orchestrator import Orchestrator, SimulationState


def _orch() -> Orchestrator:
    return Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))


def test_state_starts_with_empty_case():
    assert SimulationState().blue_case == {"leads": [], "hypotheses": []}


def test_blue_agent_case_is_wired_to_the_state_object_on_a_blue_turn():
    orch = _orch()
    orch.state.current_agent_role = "blue"
    orch.blue_agent.build_observation.return_value = "obs"
    orch.blue_agent.act.return_value = "standing by"  # text -> turn ends cleanly
    orch.step()
    assert orch.blue_agent.case is orch.state.blue_case
