"""Blue follows a 4-phase triage playbook (MONITOR -> TRIAGE -> ATTRIBUTE ->
RESPOND), the way an analyst works a signal, instead of blind tool rotation.

The phase is a pure function of blue's own history + the game facts the caller
passes (observe mode, confirmed attackers, already-contained).
"""
from src.agents import BlueAgent
from src.trajectory import Turn
from src.mock_executor import MockExecutor


def _blue() -> BlueAgent:
    b = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    b.executor.control_source_ip = "192.168.64.1"
    return b


def _turn(name: str, output: str = "ok") -> Turn:
    return Turn(0, "", {"function": {"name": name, "arguments": {}}}, output)


def _conn(**fields: object) -> str:
    import json
    return json.dumps({"tool": "investigate_connections", **fields})


def _logs(**fields: object) -> str:
    import json
    return json.dumps({"tool": "investigate_logs", **fields})


def _foothold_blue() -> BlueAgent:
    """Blue that has already seen a port scan (confirmed attacker) AND a foothold
    login for user boba_fett — i.e. an attributed, landed intrusion."""
    import json
    blue = _blue()
    blue.history = [
        Turn(0, "", {"function": {"name": "investigate_connections", "arguments": {}}},
             _conn(port_scanners=["192.168.64.11"], suspicious_ips=["192.168.64.11"])),
        Turn(1, "", {"function": {"name": "investigate_logs", "arguments": {}}},
             _logs(failed_attempts=0, suspicious_ips=["192.168.64.11"],
                   suspicious_users=["boba_fett"])),
    ]
    return blue


def _docker_turn(escape: bool) -> Turn:
    import json
    out = {"tool": "investigate_docker",
           "escape_capable_count": 1 if escape else 0,
           "flag_access_detected": escape}
    return Turn(2, "", {"function": {"name": "investigate_docker", "arguments": {}}}, json.dumps(out))


def _revoke_turn() -> Turn:
    import json
    out = {"tool": "revoke_escalation", "target_user": "boba_fett",
           "revoked_groups": ["docker"], "assessment": "REVOKED"}
    return Turn(2, "", {"function": {"name": "revoke_escalation", "arguments": {}}}, json.dumps(out))


# --- phase selection -------------------------------------------------------

def test_quiet_history_is_monitor():
    blue = _blue()
    blue.history = [_turn("investigate_logs", "{}")]
    assert blue.triage_phase(observe=True, confirmed_attackers=[], contained=False) == "MONITOR"


def test_bare_foreign_connection_is_a_lead_triage():
    blue = _blue()
    blue.history = [Turn(0, "", {"function": {"name": "investigate_connections", "arguments": {}}},
                         _conn(foreign_ips=["192.168.64.11"], port_scanners=[], suspicious_ips=[]))]
    assert blue.triage_phase(observe=True, confirmed_attackers=[], contained=False) == "TRIAGE"


def test_subthreshold_failed_auths_is_triage():
    blue = _blue()
    blue.history = [Turn(0, "", {"function": {"name": "investigate_logs", "arguments": {}}},
                         _logs(failed_attempts=2, suspicious_ips=["192.168.64.11"]))]
    assert blue.triage_phase(observe=True, confirmed_attackers=[], contained=False) == "TRIAGE"


def test_confirmed_attacker_actionable_is_respond():
    blue = _blue()
    assert blue.triage_phase(observe=False, confirmed_attackers=["192.168.64.11"], contained=False) == "RESPOND"


def test_confirmed_attacker_in_observe_is_attribute():
    blue = _blue()
    assert blue.triage_phase(observe=True, confirmed_attackers=["192.168.64.11"], contained=False) == "ATTRIBUTE"


def test_confirmed_attacker_already_contained_is_attribute():
    blue = _blue()
    assert blue.triage_phase(observe=False, confirmed_attackers=["192.168.64.11"], contained=True) == "ATTRIBUTE"


# --- per-phase steering ----------------------------------------------------

def test_respond_phase_orders_containment():
    blue = _blue()
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "contain_attacker" in g and "192.168.64.11" in g


def test_attribute_phase_documents_and_holds_in_observe():
    blue = _blue()
    g = blue.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "192.168.64.11" in g
    assert "contain_attacker" not in g          # held in observe
    assert "ATTRIBUTE" in g


def test_triage_phase_steers_to_corroboration_not_blind_rotation():
    # A lead exists; the only UNused tools are users/cron/network, but triage
    # must still reach for a corroboration sensor, not the next idle breadth tool.
    blue = _blue()
    blue.history = [
        Turn(0, "", {"function": {"name": "investigate_connections", "arguments": {}}},
             _conn(foreign_ips=["192.168.64.11"], port_scanners=[], suspicious_ips=[])),
        _turn("investigate_logs", "{}"),
        _turn("investigate_file_access", "{}"),
        _turn("investigate_processes", "{}"),
    ]
    g = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "TRIAGE" in g
    assert any(t in g for t in ("investigate_connections", "investigate_logs",
                                "investigate_file_access", "investigate_processes"))
    assert "investigate_users" not in g and "investigate_cron" not in g


def test_triage_doctrine_notes_docker_posture_slot():
    blue = _blue()
    blue.history = [Turn(0, "", {"function": {"name": "investigate_connections", "arguments": {}}},
                         _conn(foreign_ips=["192.168.64.11"], port_scanners=[], suspicious_ips=[]))]
    g = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "investigate_docker" in g


# --- IDENTIFY: a landed foothold triggers the escalation-surface check -----

def test_foothold_without_docker_check_is_identify():
    blue = _foothold_blue()
    assert blue.triage_phase(observe=False, confirmed_attackers=["192.168.64.11"], contained=False) == "IDENTIFY"


def test_identify_preempts_with_revoke_escalation_and_defers_investigation():
    # IDENTIFY's ONLY move is the immediate revoke — speed over investigation,
    # since red's breakout is one command away.
    blue = _foothold_blue()
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "revoke_escalation" in g and "boba_fett" in g
    assert "investigate_docker" not in g  # deferred to RESPOND


def test_identify_holds_until_revoke_runs_not_just_the_docker_check():
    # Running investigate_docker must NOT release IDENTIFY — only the revoke does.
    blue = _foothold_blue()
    blue.history.append(_docker_turn(escape=True))
    assert blue.triage_phase(observe=False, confirmed_attackers=["192.168.64.11"], contained=False) == "IDENTIFY"


def test_identify_fires_even_in_observe():
    # Observe holds the network block, not the on-host neutralize — blue still acts.
    blue = _foothold_blue()
    assert blue.triage_phase(observe=True, confirmed_attackers=["192.168.64.11"], contained=False) == "IDENTIFY"


def test_phase_advances_to_respond_once_revoke_has_run():
    blue = _foothold_blue()
    blue.history.append(_revoke_turn())
    assert blue.triage_phase(observe=False, confirmed_attackers=["192.168.64.11"], contained=False) == "RESPOND"


def test_recon_only_scan_skips_identify_and_contains_fast():
    # A port scan with NO foothold account must still contain immediately.
    blue = _blue()
    blue.history = [Turn(0, "", {"function": {"name": "investigate_connections", "arguments": {}}},
                         _conn(port_scanners=["192.168.64.11"], suspicious_ips=["192.168.64.11"]))]
    assert blue.triage_phase(observe=False, confirmed_attackers=["192.168.64.11"], contained=False) == "RESPOND"
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "contain_attacker" in g


# --- RESPOND (post-revoke): confirm the outcome, then finish containment ---

def test_respond_after_revoke_confirms_with_investigate_docker():
    blue = _foothold_blue()
    blue.history.append(_revoke_turn())
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "investigate_docker" in g and "contain_attacker" in g


def test_respond_reports_breakout_that_beat_the_revoke():
    blue = _foothold_blue()
    blue.history.append(_revoke_turn())
    blue.history.append(_docker_turn(escape=True))  # a breakout got through first
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "breakout DID occur" in g
    assert "contain_attacker" in g and "remediate_account" in g


def test_respond_reports_no_breakout_when_prevention_held():
    blue = _foothold_blue()
    blue.history.append(_revoke_turn())
    blue.history.append(_docker_turn(escape=False))  # revoke held; nothing got through
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "No breakout got through" in g
