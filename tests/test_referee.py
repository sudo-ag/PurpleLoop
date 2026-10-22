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
