"""Horizon verdict for a persistence pursuit: decided from the in-memory plant
registry (executors are already disconnected by the end-of-loop verdict)."""
from src.referee import Referee
from src.orchestrator import SimulationState


def _ref(state):
    return Referee(state, detect_within_turns=3, objective="persistence")


def test_horizon_verdict_standing_plant_is_red():
    s = SimulationState()
    s.record_plant(["task|\\A"], turn=4)
    s.persistence_baseline_ever_read = True
    assert _ref(s).persistence_horizon_winner() == "red"


def test_horizon_verdict_all_evicted_is_blue():
    s = SimulationState()
    s.record_plant(["task|\\A"], turn=4)
    s.mark_evicted(["task|\\A"], turn=6)
    s.persistence_baseline_ever_read = True
    assert _ref(s).persistence_horizon_winner() == "blue"


def test_horizon_unproven_board_is_not_blue():
    # Blue never landed a readable sweep and nothing was recorded: an unproven
    # board is a draw, not a blue false-clean.
    s = SimulationState()
    assert _ref(s).persistence_horizon_winner() is None


def test_horizon_partial_eviction_leaves_red():
    s = SimulationState()
    s.record_plant(["task|\\A", "startup|C:\\x\\y.lnk"], turn=4)
    s.mark_evicted(["task|\\A"], turn=6)
    s.persistence_baseline_ever_read = True
    assert _ref(s).persistence_horizon_winner() == "red"
