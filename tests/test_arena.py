from types import SimpleNamespace
from unittest.mock import MagicMock

from src.arena import build_scorecard, summarize, scripted_reset, graded_result, build_agents


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


# --- graded (tier-aware) scoring -------------------------------------------

def _tier(tier, reached=None, detect=None, defended=None):
    dwell = (detect - reached) if (reached is not None and detect is not None) else None
    return {"tier": tier, "name": {1: "foothold", 2: "exfil", 3: "root"}[tier],
            "reached_turn": reached, "detect_turn": detect, "dwell": dwell, "defended": defended}


def test_graded_result_blue_defends_top_reached():
    tiers = [_tier(1, reached=4, detect=5, defended=True), _tier(2), _tier(3)]
    assert graded_result(tiers) == "blue"


def test_graded_result_red_when_top_tier_undefended():
    tiers = [_tier(1, reached=4, detect=5, defended=True), _tier(2),
             _tier(3, reached=19, defended=False)]
    assert graded_result(tiers) == "red"


def test_graded_result_draw_or_prevention_when_nothing_reached():
    tiers = [_tier(1), _tier(2), _tier(3)]
    assert graded_result(tiers) == "draw"
    assert graded_result(tiers, contained_turn=2) == "blue"


def test_graded_result_none_without_board():
    assert graded_result(None) is None


def test_scorecard_carries_graded_result():
    tiers = [_tier(1, reached=4, detect=5, defended=True), _tier(2), _tier(3)]
    card = build_scorecard(_state(turn=6), None, 1, tiers=tiers)
    assert card["graded_result"] == "blue"


def test_summarize_prefers_tier_board_over_flag_winner():
    # Red reached only T1 but blue detected it in-window: the root-flag winner is
    # 'none' (no root read), yet the graded board must credit blue — the bug where
    # blue_detect_rate read 0.0 while the verdict said 'blue defended T1'.
    tiers = [_tier(1, reached=4, detect=5, defended=True), _tier(2), _tier(3)]
    cards = [{"winner": None, "blue_outcome": "missed", "dwell": None,
              "tiers": tiers, "graded_result": "blue"}]
    s = summarize(cards)
    assert s["blue_wins"] == 1 and s["red_wins"] == 0 and s["draws"] == 0
    assert s["blue_detect_rate"] == 1.0
    assert s["avg_dwell"] == 1.0


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


def test_build_replay_normalizes_timeline_and_milestones():
    from src.arena import build_replay
    history = [
        {"role": "red", "turn": 0, "tool": {"function": {"name": "run_on_attacker",
            "arguments": {"command": "nmap -sT 192.168.64.12"}}}, "output": "22/tcp open"},
        {"role": "blue", "turn": 1, "action": "text", "content": "Investigating."},
    ]
    state = _state(turn=9, red_access_turn=8, blue_detect_turn=9, history=history)
    card = build_scorecard(state, "blue", 3)
    rep = build_replay(state, card, 3, {"earned": True, "observe": True, "evade": False})

    assert rep["episode"] == 3 and rep["winner"] == "blue" and rep["turns"] == 9
    assert rep["mode"]["observe"] is True
    assert rep["milestones"]["red_access_turn"] == 8
    assert rep["milestones"]["blue_detect_turn"] == 9
    assert len(rep["timeline"]) == 2
    tool_evt, text_evt = rep["timeline"]
    assert tool_evt == {"turn": 0, "role": "red", "kind": "tool",
                        "name": "run_on_attacker",
                        "args": {"command": "nmap -sT 192.168.64.12"}, "output": "22/tcp open"}
    assert text_evt["kind"] == "text" and text_evt["output"] == "Investigating." and text_evt["role"] == "blue"


# --- build_agents earned/handed parity (shared by arena and main.py) -------

_ARGS = ("192.168.64.12", "llama3.2:latest", "vagrant", "vagrant",
         "192.168.64.11", "kali", "kali")


def test_build_agents_earned_red_has_no_cred_and_requires_foothold():
    red, blue = build_agents(*_ARGS, evade=False, earned=True, observe=False)
    assert red.executor.require_foothold is True
    assert red.executor.user == "" and red.executor.pwd == ""   # must earn a cred
    assert getattr(red, "attacker_executor", None) is not None   # Kali recon channel
    assert blue.executor.user == "vagrant"                       # blue keeps its cred


def test_build_agents_handed_red_keeps_configured_cred():
    red, blue = build_agents(*_ARGS, evade=False, earned=False, observe=False)
    assert red.executor.require_foothold is False
    assert red.executor.user == "vagrant"
    assert getattr(red, "attacker_executor", None) is None
