"""investigate_resident_foothold: an ESTABLISHED session to an off-box peer is a
landed foothold, detectable before red runs any flagged command. The defender's
own control channel and local addresses are never counted.
"""
import json

from src.executor import ToolExecutor
from src.agents import BlueAgent, BLUE_FOOTHOLD_HUNT
from src.mock_executor import MockExecutor
from src.trajectory import Turn

CONTROL_IP = "192.168.64.1"
ATTACKER_IP = "192.168.64.11"


def _ex():
    ex = ToolExecutor(host="mock", user="u", pwd="p")  # __init__ does not connect
    ex.control_source_ip = CONTROL_IP
    return ex


def _ss(peer_ip, port="44444", local=".12:50022", proc='users:(("bash",pid=9,fd=3))'):
    return f"ESTAB 0 0 192.168.64{local} {peer_ip}:{port} {proc}"


def test_foreign_established_session_is_a_breach():
    ex = _ex()
    r = ex._parse_resident_foothold(_ss(ATTACKER_IP))
    assert r["assessment"] == "BREACH"
    assert r["flag_access_detected"] is True
    assert any(ATTACKER_IP in s["peer"] for s in r["foreign_sessions"])


def test_control_channel_session_is_clean():
    ex = _ex()
    r = ex._parse_resident_foothold(_ss(CONTROL_IP, port="22", proc='users:(("sshd",pid=1,fd=4))'))
    assert r["assessment"] == "CLEAN"
    assert r["foreign_sessions"] == []


def test_loopback_peer_is_clean():
    ex = _ex()
    r = ex._parse_resident_foothold(_ss("127.0.0.1", port="3306"))
    assert r["foreign_sessions"] == []


def test_header_and_blank_lines_ignored():
    ex = _ex()
    raw = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\n" + _ss(ATTACKER_IP)
    r = ex._parse_resident_foothold(raw)
    assert len(r["foreign_sessions"]) == 1


def test_public_internet_egress_is_clean():
    # The target's own legit outbound HTTPS (a service reaching a CDN/updates)
    # is a public-internet peer, NOT a foothold. Flagging it false-alarms on
    # every box with normal egress. Only private/LAN peers (where the attacker
    # pivots from, and where reverse shells call back) count.
    ex = _ex()
    r = ex._parse_resident_foothold(
        _ss("151.101.193.227", port="443", local=".12:59731",
            proc='users:(("ruby",pid=1462,fd=9))'))
    assert r["foreign_sessions"] == []
    assert r["assessment"] == "CLEAN"


def _blue():
    b = BlueAgent(executor=MockExecutor(), model="x")
    b.executor.control_source_ip = CONTROL_IP
    b.executor.user = "vagrant"
    return b


def _resident_breach():
    out = json.dumps({"tool": "investigate_resident_foothold",
                      "foreign_sessions": [{"peer": f"{ATTACKER_IP}:44444", "local": "x", "process": "bash"}],
                      "flag_access_detected": True, "assessment": "BREACH"})
    return Turn(0, "", {"function": {"name": "investigate_resident_foothold", "arguments": {}}}, out)


def test_resident_breach_registers_a_foothold():
    b = _blue()
    b.history = [_resident_breach()]
    assert b._has_foothold() is True


def test_resident_foothold_hunted_first():
    # Confirmed scanner, no foothold yet: the hunt steers the resident sensor
    # first, since it catches the foothold earliest.
    b = _blue()
    g = b.tool_guidance(observe=True, confirmed_attackers=[ATTACKER_IP], contained=False)
    assert "investigate_resident_foothold" in g
    assert BLUE_FOOTHOLD_HUNT[0] == "investigate_resident_foothold"


def test_resident_breach_fires_the_surface_close():
    # Once the foothold is registered, HARDEN closes the surface (observe mode).
    b = _blue()
    b.history = [_resident_breach()]
    g = b.tool_guidance(observe=True, confirmed_attackers=[ATTACKER_IP], contained=False)
    assert "remediate_escalation_surface" in g
