"""Remediation grace window: blue detects a foothold on time but its account lock
is HELD for `remediate_grace` turns, so red gets a window to escalate before being
cut off. This keeps the T1 contest from being an instant-lock auto-win.
"""
import json
from unittest.mock import MagicMock

from src.orchestrator import TIER_FOOTHOLD, Orchestrator


def _orch(grace: int) -> Orchestrator:
    # Plain mocks: these tests drive the grace helpers directly, and the apply
    # path needs a settable `blue_agent.executor` (an instance attr a spec blocks).
    return Orchestrator(MagicMock(), MagicMock(), remediate_grace=grace)


def _remediate_call(user: str = "chewbacca") -> dict:
    return {"function": {"name": "remediate_account", "arguments": {"user": user}}}


# --- the grace predicate ----------------------------------------------------

def test_held_inside_window():
    orch = _orch(grace=2)
    orch.state.red_tiers[TIER_FOOTHOLD] = 2
    orch.state.turn = 3  # foothold+1, inside [2, 4)
    assert orch._remediation_held() is True


def test_not_held_after_window():
    orch = _orch(grace=2)
    orch.state.red_tiers[TIER_FOOTHOLD] = 2
    orch.state.turn = 4  # foothold+grace: window closed
    assert orch._remediation_held() is False


def test_not_held_before_any_foothold():
    orch = _orch(grace=2)
    orch.state.turn = 5
    assert orch._remediation_held() is False  # no foothold -> nothing to hold


def test_grace_zero_never_holds():
    orch = _orch(grace=0)
    orch.state.red_tiers[TIER_FOOTHOLD] = 2
    orch.state.turn = 2
    assert orch._remediation_held() is False  # disabled -> instant lock


# --- staging (held) ---------------------------------------------------------

def test_staging_records_user_but_grants_no_credit():
    """A staged lock must NOT look like a successful remediation, or the episode
    ends on it (prevention beats detection) and red never gets its window."""
    orch = _orch(grace=2)
    out = orch._stage_remediation(_remediate_call("chewbacca"))
    assert orch.state.staged_remediation_user == "chewbacca"
    assert json.loads(out)["remediated"] is False
    assert orch._check_blue_remediation(out) is None


# --- applying (window closed) -----------------------------------------------

def test_apply_executes_lock_and_credits_once_window_closes():
    orch = _orch(grace=2)
    orch.state.red_tiers[TIER_FOOTHOLD] = 2
    orch.state.staged_remediation_user = "chewbacca"
    orch.blue_agent.executor.remediate_account.return_value = {
        "tool": "remediate_account", "target_user": "chewbacca", "remediated": True,
    }

    orch.state.turn = 3  # still inside the window -> no-op
    orch._apply_staged_remediation()
    assert orch.state.blue_remediate_turn is None
    assert orch.state.staged_remediation_user == "chewbacca"

    orch.state.turn = 4  # window closed -> lock executes, credited
    orch._apply_staged_remediation()
    orch.blue_agent.executor.remediate_account.assert_called_once_with("chewbacca")
    assert orch.state.blue_remediate_turn == 4
    assert orch.state.remediated_user == "chewbacca"
    assert orch.state.staged_remediation_user is None
