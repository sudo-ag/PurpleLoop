"""Earned-foothold confirmation (option B).

A quietly cracked-cred login trips none of the malice signals
(`confirmed_attackers` wanted a port scan, a brute-force spike, or flag access),
so against a stealthy red blue never entered its response phase and never closed
a vector. Here a successful non-control login is surfaced as its own
`foothold_ips` field and counted as a confirmed attacker — scoped to source IP
!= the control session, which is blue's only legitimate login in this two-box
model.
"""
import json

from src.agents import BlueAgent
from src.executor import ToolExecutor
from src.mock_executor import MockExecutor
from src.trajectory import Turn


def _executor():
    ex = ToolExecutor(host="192.168.64.10", user="vagrant", pwd="vagrant", timeout=30)
    ex.control_source_ip = "192.168.64.1"
    return ex


def test_quiet_cracked_cred_login_is_a_foothold_ip():
    # 0 failures, no flag access — the stealthy earned login. Its source IP must
    # surface as a foothold, not just a generic suspicious IP.
    ex = _executor()
    line = (
        "Oct 16 10:00:00 ubuntu sshd[1000]: Accepted password for lando_calrissian "
        "from 192.168.64.11 port 51000 ssh2"
    )
    result = ex._parse_auth_log(line)
    assert result["foothold_ips"] == ["192.168.64.11"]
    assert result["failed_attempts"] == 0
    assert result["flag_access_detected"] is False


def test_control_session_login_is_not_a_foothold():
    ex = _executor()
    line = (
        "Oct 16 10:00:00 ubuntu sshd[1000]: Accepted password for vagrant "
        "from 192.168.64.1 port 51000 ssh2"
    )
    result = ex._parse_auth_log(line)
    assert result["foothold_ips"] == []


def test_confirmed_attackers_counts_the_foothold():
    # The whole point: no scan, no brute spike, no flag — yet blue must confirm.
    b = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    b.executor.control_source_ip = "192.168.64.1"
    b.history = [
        Turn(0, "", {"function": {"name": "investigate_logs", "arguments": {}}},
             json.dumps({"tool": "investigate_logs", "failed_attempts": 0,
                         "flag_access_detected": False,
                         "foothold_ips": ["192.168.64.11"],
                         "suspicious_ips": ["192.168.64.11"]})),
    ]
    assert b.confirmed_attackers() == ["192.168.64.11"]
