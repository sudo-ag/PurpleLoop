"""Debriefs append to ep_NNN.md; lessons ride into ep_NNN.json."""
from types import SimpleNamespace

from src.arena import build_replay, compose_episode_report


def _state(**kw):
    base = dict(red_lesson=None, blue_lesson=None, history=[], turn=0,
                blue_case={"leads": [], "hypotheses": []})
    base.update(kw)
    return SimpleNamespace(**base)


def test_replay_carries_both_lessons():
    rep = build_replay(_state(red_lesson="rl", blue_lesson="bl", turn=3),
                       {"winner": None}, 1, {})
    assert rep["red_lesson"] == "rl" and rep["blue_lesson"] == "bl"


def test_episode_report_text_includes_both_debriefs():
    out = compose_episode_report("BASE BOARD",
                                 _state(red_lesson="rl", blue_lesson="bl"),
                                 {"verdict": "v", "tiers": []})
    assert "BASE BOARD" in out
    assert "🔴 Red Debrief" in out and "🔵 Blue Debrief" in out
