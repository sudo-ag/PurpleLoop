"""The Referee scores an episode from the recorded milestones — same results
the Orchestrator produced before scoring was extracted."""
from src.referee import Referee
from src.orchestrator import SimulationState, TIER_FOOTHOLD, TIER_ROOT


def test_referee_verdict_matches_legacy_for_foothold_defended():
    state = SimulationState()
    state.red_tiers[TIER_FOOTHOLD] = 2
    state.blue_tier_detect[TIER_FOOTHOLD] = 3
    ref = Referee(state, detect_within_turns=3)
    assert ref.verdict() == "red reached T1 (foothold); blue defended T1"


def test_referee_verdict_root_reached_undetected():
    state = SimulationState()
    state.red_tiers[TIER_FOOTHOLD] = 2
    state.red_tiers[TIER_ROOT] = 4
    ref = Referee(state, detect_within_turns=3)
    v = ref.verdict()
    assert "red reached T3 (root)" in v
    assert "blue defended nothing" in v


def test_referee_resolve_outcome_blue_prevents():
    state = SimulationState()
    state.red_tiers[TIER_FOOTHOLD] = 2
    state.blue_remediate_turn = 3       # locked before any root access
    ref = Referee(state, detect_within_turns=3)
    assert ref.resolve_outcome() == "blue"
    assert state.blue_victory is True


def test_persistence_does_not_end_on_root_access():
    # Under persistence, red reaching root and blue detecting it must NOT end the
    # episode — the plant->hunt->evict sub-game needs to play out first.
    state = SimulationState()
    state.red_access_turn = 3
    state.blue_detect_turn = 3
    ref = Referee(state, detect_within_turns=3, objective="persistence")
    assert ref.resolve_outcome() is None
    assert state.blue_victory is False


def test_persistence_blue_eviction_ends_it_as_blue_win():
    state = SimulationState()
    state.red_access_turn = 3
    state.blue_persistence_removed_turn = 6
    ref = Referee(state, detect_within_turns=3, objective="persistence")
    assert ref.resolve_outcome() == "blue"
    assert state.blue_victory is True
