"""Graded objective tiers (Slice 1): T1 foothold + T3 root wired to real signals.

T2 (exfil) is declared but inert until the web/DB sensor lands, so these tests
only exercise T1/T3 recording plus the pure scoreboard/verdict logic.
"""
import json
from unittest.mock import MagicMock

from src.agents import Agent
from src.orchestrator import (
    Orchestrator,
    TIER_FOOTHOLD,
    TIER_EXFIL,
    TIER_ROOT,
)


def _orch(detect_within_turns: int = 3) -> Orchestrator:
    return Orchestrator(
        MagicMock(spec=Agent), MagicMock(spec=Agent),
        detect_within_turns=detect_within_turns,
    )


def _tool(name: str) -> dict:
    return {"function": {"name": name, "arguments": {}}}


# --- red foothold (T1) detection -------------------------------------------

def test_use_credential_success_is_foothold():
    orch = _orch()
    out = json.dumps({"tool": "use_credential", "status": "success", "user": "lando_calrissian"})
    assert orch._check_red_foothold(_tool("use_credential"), out) is True


def test_use_credential_failure_is_not_foothold():
    orch = _orch()
    out = json.dumps({"tool": "use_credential", "status": "failed", "user": "lando_calrissian"})
    assert orch._check_red_foothold(_tool("use_credential"), out) is False


def test_successful_target_command_is_foothold():
    orch = _orch()
    assert orch._check_red_foothold(_tool("execute_command"), "uid=1001(lando_calrissian)") is True


def test_errored_target_command_is_not_foothold():
    orch = _orch()
    assert orch._check_red_foothold(_tool("execute_command"), "bash: permission denied") is False


def test_attacker_box_recon_is_not_target_foothold():
    orch = _orch()
    # nmap output on Kali is real output but not a foothold on the target.
    assert orch._check_red_foothold(_tool("run_on_attacker"), "22/tcp open ssh") is False


# --- blue foothold (T1) detection ------------------------------------------

def test_blue_sees_non_control_login():
    orch = _orch()
    out = json.dumps({
        "tool": "investigate_logs",
        "events": [{"event": "Successful authentication", "severity": "high"}],
    })
    assert orch._check_blue_foothold_detect(out) is True


def test_blue_ignores_own_control_session():
    orch = _orch()
    out = json.dumps({
        "tool": "investigate_logs",
        "events": [{"event": "Blue control session login (self)", "severity": "informational"}],
    })
    assert orch._check_blue_foothold_detect(out) is False


# --- scoreboard + verdict ---------------------------------------------------

def test_tier_not_reached_is_na():
    board = {b["tier"]: b for b in _orch().tier_scoreboard()}
    assert board[TIER_FOOTHOLD]["defended"] is None
    assert board[TIER_FOOTHOLD]["reached_turn"] is None


def test_detected_in_window_is_defended():
    orch = _orch(detect_within_turns=3)
    orch.state.red_tiers[TIER_FOOTHOLD] = 2
    orch.state.blue_tier_detect[TIER_FOOTHOLD] = 4
    board = {b["tier"]: b for b in orch.tier_scoreboard()}
    assert board[TIER_FOOTHOLD]["defended"] is True
    assert board[TIER_FOOTHOLD]["dwell"] == 2


def test_detected_past_window_is_not_defended():
    orch = _orch(detect_within_turns=3)
    orch.state.red_tiers[TIER_FOOTHOLD] = 2
    orch.state.blue_tier_detect[TIER_FOOTHOLD] = 9
    board = {b["tier"]: b for b in orch.tier_scoreboard()}
    assert board[TIER_FOOTHOLD]["defended"] is False


def test_containment_defends_reached_tier():
    orch = _orch()
    orch.state.red_tiers[TIER_FOOTHOLD] = 3
    orch.state.blue_contain_turn = 3
    board = {b["tier"]: b for b in orch.tier_scoreboard()}
    assert board[TIER_FOOTHOLD]["defended"] is True


def test_verdict_reports_top_tier_and_defenses():
    orch = _orch()
    orch.state.red_tiers[TIER_FOOTHOLD] = 2
    orch.state.red_tiers[TIER_EXFIL] = 5
    orch.state.blue_tier_detect[TIER_FOOTHOLD] = 3  # caught T1, missed T2
    verdict = orch.verdict()
    assert "red reached T2 (exfil)" in verdict
    assert "blue defended T1" in verdict


def test_verdict_no_tier_reached():
    assert _orch().verdict() == "red reached no tier; blue had nothing to defend"
