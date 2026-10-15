"""Scoring-integrity hardening (audit items F3/F4/F5).

F4: _is_error_output no longer mislabels useful output that merely contains an
    error word.
F5: a red stall/fail streak is not a blue win in observe mode.
F3: flag detection is case-insensitive.
"""
from unittest.mock import MagicMock

from src.agents import Agent
from src.orchestrator import Orchestrator


def _orch(**kw) -> Orchestrator:
    return Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), **kw)


# --- F4: error-output classification ---------------------------------------

def test_mixed_output_with_some_error_lines_is_still_useful():
    o = _orch()
    out = "/usr/bin/sudo\n/usr/bin/passwd\nfind: '/root': Permission denied"
    assert o._is_error_output(out) is False


def test_pure_error_output_is_an_error():
    o = _orch()
    assert o._is_error_output("Remote command failed with exit code 1.") is True


def test_every_line_error_is_an_error():
    o = _orch()
    assert o._is_error_output("bash: nope: command not found\ncat: x: no such file") is True


def test_empty_output_is_an_error():
    o = _orch()
    assert o._is_error_output("   \n  ") is True


def test_foothold_credit_survives_error_lines_in_output():
    # A successful command whose output includes a stray 'denied' line must still
    # count as a target foothold (the F4 regression this guards).
    o = _orch()
    tool = {"function": {"name": "execute_command", "arguments": {}}}
    out = "uid=1120(lando_calrissian) gid=100(users)\nfind: '/root': Permission denied"
    assert o._check_red_foothold(tool, out) is True


# --- F5: observe mode does not credit blue for a red stall -----------------

def test_observe_mode_red_stall_is_not_a_blue_win():
    o = _orch(observe=True)
    o.state.red_stalled_turns = 99
    o.state.red_failed_turns = 99
    assert o._stall_blue_win() is False


def test_active_mode_red_stall_is_a_blue_win():
    o = _orch(observe=False)
    o.state.red_failed_turns = o.stall_limit
    assert o._stall_blue_win() is True


def test_below_the_limit_is_not_a_stall_win():
    o = _orch(observe=False)
    o.state.red_stalled_turns = 0
    o.state.red_failed_turns = 0
    assert o._stall_blue_win() is False


# --- F3: case-insensitive flag detection -----------------------------------

def test_flag_detection_is_case_insensitive():
    o = _orch()
    assert o._check_red_victory("here is flag{abc}") is True
    assert o._check_red_victory("FLAG{ABC}") is True
    assert o._check_red_victory("no token here") is False


# --- generate_report surfaces the graded verdict + tier board (#6) ---------

def test_generate_report_surfaces_graded_verdict_and_tier_board():
    # The single-episode report (used by main.py) must carry the graded verdict
    # and per-tier board, not just the flag-binary winner.
    o = _orch()
    o.state.red_tiers = {1: 4, 3: 9}
    o.state.blue_tier_detect = {1: 5}
    o.state.red_access_turn = 9
    o.state.turn = 12
    r = o.generate_report()
    assert "**Verdict:**" in r
    assert "T1 foothold" in r and "T3 root" in r
