from types import SimpleNamespace
from unittest.mock import MagicMock

from src.arena import build_scorecard, summarize, scripted_reset


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


def test_scripted_reset_flushes_attacker_and_clears_log():
    blue = MagicMock()
    red = SimpleNamespace(jump_host="192.168.64.11")
    out = scripted_reset(blue, red, episode=2)
    cmds = " ".join(c.args[0] for c in blue.execute.call_args_list)
    assert "iptables -D INPUT -s 192.168.64.11 -j DROP" in cmds
    assert "truncate -s 0 /var/log/auth.log" in cmds
    assert any("192.168.64.11" in a for a in out["actions"])


def test_scripted_reset_skips_firewall_without_valid_attacker_ip():
    blue = MagicMock()
    red = SimpleNamespace(jump_host=None)        # single-box / mock: no jump
    scripted_reset(blue, red, episode=1)
    cmds = " ".join(c.args[0] for c in blue.execute.call_args_list)
    assert "iptables" not in cmds                 # nothing to flush
    assert "truncate -s 0 /var/log/auth.log" in cmds


def test_scripted_reset_rejects_non_ip_jump_host():
    # A bogus jump_host must never be interpolated into an iptables command.
    blue = MagicMock()
    red = SimpleNamespace(jump_host="evil; rm -rf /")
    scripted_reset(blue, red, episode=1)
    cmds = " ".join(c.args[0] for c in blue.execute.call_args_list)
    assert "iptables" not in cmds
    assert "rm -rf" not in cmds
