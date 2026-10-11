from types import SimpleNamespace

from src.arena import build_scorecard, summarize


def _state(**kw):
    base = dict(
        turn=0, red_access_turn=None, blue_detect_turn=None,
        blue_contain_turn=None, contained_ip=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_scorecard_containment_before_access_is_contained():
    card = build_scorecard(_state(turn=3, blue_contain_turn=3, contained_ip="192.168.64.11"), "blue", 1)
    assert card["blue_outcome"] == "contained"
    assert card["red_outcome"] == "blocked"
    assert card["dwell"] is None


def test_scorecard_in_time_detection_is_detected_with_dwell():
    card = build_scorecard(_state(turn=6, red_access_turn=4, blue_detect_turn=6), "blue", 2)
    assert card["blue_outcome"] == "detected"
    assert card["red_outcome"] == "reached"
    assert card["dwell"] == 2


def test_scorecard_access_without_detection_is_missed():
    card = build_scorecard(_state(turn=9, red_access_turn=4), "red", 3)
    assert card["blue_outcome"] == "missed"
    assert card["red_outcome"] == "reached"


def test_scorecard_detection_without_access_is_false_positive():
    card = build_scorecard(_state(turn=2, blue_detect_turn=2), None, 4)
    assert card["blue_outcome"] == "false_positive"
    assert card["red_outcome"] == "blocked"


def test_summarize_counts_and_rates():
    cards = [
        {"winner": "blue", "blue_outcome": "contained", "dwell": None},
        {"winner": "blue", "blue_outcome": "detected", "dwell": 2},
        {"winner": "red", "blue_outcome": "missed", "dwell": None},
        {"winner": None, "blue_outcome": "false_positive", "dwell": None},
    ]
    s = summarize(cards)
    assert s["episodes"] == 4
    assert s["red_wins"] == 1
    assert s["blue_wins"] == 2
    assert s["draws"] == 1
    assert s["blue_detect_rate"] == 0.5     # contained + detected
    assert s["blue_contain_rate"] == 0.25
    assert s["blue_false_positive_rate"] == 0.25
    assert s["avg_dwell"] == 2.0


def test_summarize_empty():
    assert summarize([]) == {"episodes": 0}
