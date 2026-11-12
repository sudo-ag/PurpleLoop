"""Fix-pass hardening from the final review: blast-radius isolation (I1),
plain-language actions (I2), whitespace polish (M4), reproducibility (M7)."""
from types import SimpleNamespace

from src.debrief import build_debrief
from src.arena import compose_episode_report


def _state(**kw):
    base = dict(red_lesson=None, blue_lesson=None, history=[],
                blue_case={"leads": [], "hypotheses": []})
    base.update(kw)
    return SimpleNamespace(**base)


def test_actions_are_plain_language_not_raw_tool_names():  # I2
    st = _state(history=[{"role": "red", "tool": {"function": {"name": "execute_command"}}}])
    out = build_debrief("red", st, {"verdict": "v", "tiers": []})
    assert "ran a command on the target" in out
    assert "- execute_command" not in out


def test_compose_preserves_board_when_a_debrief_raises():  # I1
    bad = _state(history=["not-a-dict"])  # .get on a str would raise inside the builder
    out = compose_episode_report("THE BOARD", bad, {"verdict": "v", "tiers": []})
    assert "THE BOARD" in out


def test_polish_whitespace_only_falls_back_to_skeleton():  # M4
    skeleton = build_debrief("red", _state(), {"verdict": "v", "tiers": []})
    polished = build_debrief("red", _state(), {"verdict": "v", "tiers": []},
                             polish=lambda s, r: "   \n  ")
    assert polished == skeleton


def test_deterministic_build_is_reproducible():  # M7
    st = _state(red_lesson="x led to y, so next time z",
                history=[{"role": "red", "tool": {"function": {"name": "execute_command"}}}])
    card = {"verdict": "red reached T1", "tiers": []}
    assert build_debrief("red", st, card) == build_debrief("red", st, card)
