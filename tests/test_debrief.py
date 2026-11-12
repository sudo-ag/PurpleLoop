"""Deterministic per-agent debrief builder (src/debrief.py)."""
from types import SimpleNamespace

from src.debrief import build_debrief, _next_step


def _state(**kw):
    base = dict(red_lesson=None, blue_lesson=None, history=[],
                blue_case={"leads": [], "hypotheses": []})
    base.update(kw)
    return SimpleNamespace(**base)


def test_debrief_has_the_four_section_headers():
    out = build_debrief("red", _state(), {"verdict": "red reached T1", "tiers": []})
    for h in ("Executive Summary", "Actions", "Learned", "Next"):
        assert h in out


def test_exec_summary_uses_the_graded_verdict():
    out = build_debrief("blue", _state(),
                        {"verdict": "red reached T1; blue defended nothing", "tiers": []})
    assert "blue defended nothing" in out


def test_learned_section_shows_the_captured_lesson():
    out = build_debrief("red", _state(red_lesson="establish a stable shell first"),
                        {"verdict": "x", "tiers": []})
    assert "establish a stable shell first" in out


def test_next_step_extracts_the_forward_clause():
    s = _state(red_lesson="re-exploiting wasted turns, so next time reuse the session")
    assert "reuse the session" in _next_step("red", s, {"tiers": []})


def test_next_step_falls_back_when_no_forward_clause():
    s = _state(red_lesson="the exploit worked")  # no 'next time'
    assert _next_step("red", s, {"tiers": []})  # non-empty, no crash


def test_thin_episode_does_not_crash_and_is_nonempty():
    out = build_debrief("blue", _state(), {"verdict": "draw", "tiers": []})
    assert out.strip()


def test_blue_actions_narrate_the_case_file():
    case = {"leads": [{"id": 0, "sensor": "investigate_connections",
                       "observation": "port scan from .11", "confidence": "high", "turn": 2}],
            "hypotheses": [{"claim": "recon from .11", "confidence": "medium",
                            "lead_ids": [0], "turn": 3}]}
    out = build_debrief("blue", _state(blue_case=case), {"verdict": "x", "tiers": []})
    assert "port scan from .11" in out and "recon from .11" in out


def test_polish_failure_falls_back_to_skeleton():
    def boom(skeleton, role):
        raise RuntimeError("model down")
    skeleton = build_debrief("red", _state(red_lesson="x"), {"verdict": "v", "tiers": []})
    polished = build_debrief("red", _state(red_lesson="x"), {"verdict": "v", "tiers": []}, polish=boom)
    assert polished == skeleton


def test_polish_empty_return_falls_back_to_skeleton():
    skeleton = build_debrief("red", _state(), {"verdict": "v", "tiers": []})
    polished = build_debrief("red", _state(), {"verdict": "v", "tiers": []}, polish=lambda s, r: "")
    assert polished == skeleton
