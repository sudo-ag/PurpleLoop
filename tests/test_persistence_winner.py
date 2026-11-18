"""Persistence win-eval: the engagement is decided by whether red's planted key
survived blue's eviction. See docs/superpowers/specs/2026-11-18-persistence-scenario-design.md.
"""
from src.arena import persistence_winner, build_scorecard


def test_planted_and_removed_is_blue():
    assert persistence_winner(planted_turn=2, removed_turn=5) == "blue"


def test_planted_not_removed_is_red():
    # A blue that only locked the password (no remove_persistence) sets no
    # removed_turn, so the key survives and red wins — the pedagogical crux.
    assert persistence_winner(planted_turn=2, removed_turn=None) == "red"


def test_never_planted_is_none():
    assert persistence_winner(planted_turn=None, removed_turn=None) is None


def test_removal_before_plant_is_red():
    # A stale/earlier removal does not count as evicting a later plant.
    assert persistence_winner(planted_turn=5, removed_turn=3) == "red"


class _S:
    red_persistence_planted_turn = 2
    blue_persistence_removed_turn = None


def test_scorecard_uses_persistence_winner_when_objective_is_persistence():
    card = build_scorecard(_S(), winner=None, episode=1, objective="persistence")
    assert card["graded_result"] == "red"


def test_scorecard_default_objective_unaffected():
    # No tier board + default objective -> graded_result stays None (legacy path).
    card = build_scorecard(_S(), winner=None, episode=1)
    assert card["graded_result"] is None
