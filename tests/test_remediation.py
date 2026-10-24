"""Blue remediation action: lock + kill a compromised account, scored as a stop."""
import json
from unittest.mock import MagicMock

from src.agents import Agent
from src.orchestrator import Orchestrator
from src.executor import ToolExecutor


def _orch(**kw) -> Orchestrator:
    return Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent), **kw)


def _ex() -> ToolExecutor:
    # Defender runs as vagrant; construction does no SSH, and the guard branches
    # below return before any command is executed.
    return ToolExecutor(host="192.168.64.12", user="vagrant", pwd="vagrant")


# --- executor self-harm guards (short-circuit before SSH) ------------------

def test_remediate_refuses_defender_account():
    r = _ex().remediate_account("vagrant")
    assert r["assessment"] == "REFUSED" and r["remediated"] is False


def test_remediate_refuses_root():
    assert _ex().remediate_account("root")["assessment"] == "REFUSED"


def test_remediate_rejects_invalid_name():
    r = _ex().remediate_account("evil; rm -rf /")
    assert r["remediated"] is False and "not a valid" in r["summary"]


def test_remediate_rejects_empty():
    assert _ex().remediate_account("")["remediated"] is False


# --- revoke_escalation: strip the root path from a foothold account --------

def test_revoke_refuses_defender_and_root():
    assert _ex().revoke_escalation("vagrant")["assessment"] == "REFUSED"
    assert _ex().revoke_escalation("root")["assessment"] == "REFUSED"


def test_revoke_rejects_invalid_name():
    assert _ex().revoke_escalation("x; rm -rf /")["revoked_groups"] == []


def test_revoke_noop_when_account_in_no_privileged_group():
    ex = _ex()
    ex.execute = MagicMock(return_value="boba_fett users")  # id -nG: no docker/sudo
    r = ex.revoke_escalation("boba_fett")
    assert r["assessment"] == "CLEAN" and r["revoked_groups"] == []


def test_revoke_strips_docker_group_and_records_for_restore():
    ex = _ex()
    ex.execute = MagicMock(side_effect=[
        "boba_fett docker users",             # id -nG
        "...\nPL_REVOKED",                    # gpasswd -d + pkill
    ])
    r = ex.revoke_escalation("boba_fett")
    assert r["assessment"] == "REVOKED"
    assert r["revoked_groups"] == ["docker"]
    assert ("boba_fett", ["docker"]) in ex._revoked_privs
    # the strip command targets the docker group
    assert "deluser boba_fett docker" in ex.execute.call_args_list[1].args[0]


# --- orchestrator detection + scoring --------------------------------------

def test_check_blue_remediation_parses_success():
    out = json.dumps({"tool": "remediate_account", "remediated": True, "target_user": "chewbacca"})
    assert _orch()._check_blue_remediation(out) == "chewbacca"


def test_check_blue_remediation_ignores_failure():
    out = json.dumps({"tool": "remediate_account", "remediated": False, "target_user": "chewbacca"})
    assert _orch()._check_blue_remediation(out) is None


def test_remediation_before_access_is_a_blue_win():
    o = _orch()
    o.state.blue_remediate_turn = 3
    o.state.turn = 3
    assert o._resolve_outcome() == "blue"
    assert o.state.blue_victory is True


def test_tier_is_defended_when_remediated_at_or_before_reach():
    o = _orch()
    o.state.red_tiers = {1: 5}
    o.state.blue_remediate_turn = 4
    board = {b["tier"]: b for b in o.tier_scoreboard()}
    assert board[1]["defended"] is True


# --- observe mode: network block held, on-host remediation LIVE ------------

def test_remediation_is_live_even_in_observe():
    ex = MagicMock()
    ex.remediate_account.return_value = {"tool": "remediate_account",
                                         "remediated": True, "target_user": "chewbacca"}
    blue = Agent(role="blue", executor=ex, observe=True)
    out = blue.process_tool_call(
        {"function": {"name": "remediate_account", "arguments": {"user": "chewbacca"}}})
    ex.remediate_account.assert_called_once_with("chewbacca")
    assert '"remediated": true' in out


def test_containment_is_still_held_in_observe():
    ex = MagicMock()
    blue = Agent(role="blue", executor=ex, observe=True)
    out = blue.process_tool_call(
        {"function": {"name": "contain_attacker", "arguments": {"ip": "192.168.64.11"}}})
    assert "containment held" in out
    ex.contain_attacker.assert_not_called()
