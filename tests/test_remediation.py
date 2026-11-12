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


# --- auto-revoke reflex: strip escalation the instant the foothold is seen -

def test_foothold_detection_auto_revokes_escalation():
    o = _orch()
    o.blue_agent.executor = MagicMock()
    o.blue_agent.executor.revoke_escalation.return_value = {
        "tool": "revoke_escalation", "assessment": "REVOKED", "revoked_groups": ["docker"]}
    out = json.dumps({"tool": "investigate_logs", "suspicious_users": ["boba_fett"],
                      "events": [{"event": "Successful authentication"}]})
    o._auto_revoke_escalation(out)
    o.blue_agent.executor.revoke_escalation.assert_called_once_with("boba_fett")
    assert o.state.escalation_auto_revoked is True


def test_auto_revoke_fires_only_once():
    o = _orch()
    o.blue_agent.executor = MagicMock()
    o.blue_agent.executor.revoke_escalation.return_value = {}
    out = json.dumps({"suspicious_users": ["boba_fett"]})
    o._auto_revoke_escalation(out)
    o._auto_revoke_escalation(out)
    assert o.blue_agent.executor.revoke_escalation.call_count == 1


def test_auto_revoke_noop_without_a_user():
    o = _orch()
    o.blue_agent.executor = MagicMock()
    o._auto_revoke_escalation(json.dumps({"suspicious_users": []}))
    o.blue_agent.executor.revoke_escalation.assert_not_called()
    assert o.state.escalation_auto_revoked is False


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


# --- remove_persistence: strips a planted SSH key, unlike its siblings does
#     NOT refuse root (stripping root's planted key is the primary use case) --

import base64  # noqa: E402


def _ex_with_keys(baseline_lines: set, live_lines_by_path: dict) -> ToolExecutor:
    """A ToolExecutor whose execute() serves a fixed authorized_keys read per
    path and records every command it's called with, so a write command's
    content can be decoded and checked."""
    ex = ToolExecutor(host="192.168.64.12", user="vagrant", pwd="vagrant")
    ex._authorized_keys_baseline = baseline_lines
    ex._calls = []

    def fake_execute(cmd, *a, **k):
        ex._calls.append(cmd)
        for path, content in live_lines_by_path.items():
            if f"cat {path}" in cmd:
                return content
        return ""

    ex.execute = fake_execute  # type: ignore[method-assign]
    return ex


def test_remove_persistence_refuses_defender_account():
    ex = _ex_with_keys(set(), {})
    r = ex.remove_persistence("vagrant")
    assert r["assessment"] == "REFUSED" and r["removed"] is False


def test_remove_persistence_refuses_option_like_name():
    ex = _ex_with_keys(set(), {})
    r = ex.remove_persistence("-foo")
    assert r["assessment"] == "REFUSED" and r["removed"] is False


def test_remove_persistence_does_not_refuse_root():
    # root is in _PROTECTED_ACCOUNTS for remediate_account/revoke_escalation,
    # but remove_persistence must NOT refuse it -- stripping root's own
    # planted key is the primary use case.
    ex = _ex_with_keys(
        baseline_lines={"root:ssh-ed25519 AAAA legit"},
        live_lines_by_path={"/root/.ssh/authorized_keys": "ssh-ed25519 AAAA legit"},
    )
    r = ex.remove_persistence("root")
    assert r["assessment"] != "REFUSED"


def test_remove_persistence_keeps_legit_drops_planted():
    ex = _ex_with_keys(
        baseline_lines={"lando_calrissian:ssh-ed25519 AAAA legit"},
        live_lines_by_path={
            "/home/lando_calrissian/.ssh/authorized_keys":
                "ssh-ed25519 AAAA legit\nssh-ed25519 BBBB planted",
        },
    )
    r = ex.remove_persistence("lando_calrissian")
    assert r["removed"] is True and r["assessment"] == "REMOVED"
    write_cmd = next(c for c in ex._calls if "base64 -d" in c)
    b64 = write_cmd.split("echo ", 1)[1].split(" |", 1)[0]
    written = base64.b64decode(b64).decode()
    assert "ssh-ed25519 AAAA legit" in written
    assert "ssh-ed25519 BBBB planted" not in written


def test_remove_persistence_no_baseline_refuses():
    ex = ToolExecutor(host="192.168.64.12", user="vagrant", pwd="vagrant")
    ex._authorized_keys_baseline = None
    ex._calls = []
    ex.execute = lambda cmd, *a, **k: (ex._calls.append(cmd), "")[1]  # type: ignore[method-assign]
    r = ex.remove_persistence("lando_calrissian")
    assert r["removed"] is False
    assert not any("tee" in c for c in ex._calls)


# --- investigate_persistence / remove_persistence tool-use wiring ----------

def test_investigate_persistence_wiring():
    ex = MagicMock()
    ex.investigate_persistence.return_value = {"tool": "investigate_persistence",
                                                "assessment": "CLEAN"}
    blue = Agent(role="blue", executor=ex)
    out = blue.process_tool_call({"function": {"name": "investigate_persistence", "arguments": {}}})
    ex.investigate_persistence.assert_called_once_with()
    assert '"assessment": "CLEAN"' in out


def test_remove_persistence_wiring():
    ex = MagicMock()
    ex.remove_persistence.return_value = {"tool": "remove_persistence",
                                           "removed": True, "target_user": "chewbacca"}
    blue = Agent(role="blue", executor=ex, observe=True)
    out = blue.process_tool_call(
        {"function": {"name": "remove_persistence", "arguments": {"user": "chewbacca"}}})
    ex.remove_persistence.assert_called_once_with("chewbacca")
    assert '"removed": true' in out
