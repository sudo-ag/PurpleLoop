"""investigate_ftp_sessions: FTP session visibility, parsed from syslog.

Attribution/dwell-time only — this sensor must NEVER set flag_access_detected.
investigate_webshells() is the sole breach signal for this family (Family 2 /
ProFTPD mod_copy); this sensor only tells blue who connected and when.
"""
from src.executor import ToolExecutor


# Real captured log line shape (verified live against the target box).
OPENED_SELF = (
    "Nov  6 00:48:25 ubuntu proftpd[3470]: localhost "
    "(192.168.64.1[192.168.64.1]) - FTP session opened."
)
OPENED_ATTACKER = (
    "Nov  6 00:49:10 ubuntu proftpd[3471]: localhost "
    "(192.168.64.11[192.168.64.11]) - FTP session opened."
)
CLOSED_ATTACKER = (
    "Nov  6 00:50:02 ubuntu proftpd[3471]: localhost "
    "(192.168.64.11[192.168.64.11]) - FTP session closed."
)


def _executor() -> ToolExecutor:
    return ToolExecutor(host="192.168.64.10", user="vagrant", pwd="vagrant", timeout=30)


def test_self_ftp_session_is_filtered_out():
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    executor.execute = lambda cmd, *a, **k: OPENED_SELF
    result = executor.investigate_ftp_sessions()
    assert result["foreign_ips"] == []
    assert result["sessions"] == []


def test_different_source_ip_is_reported():
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    executor.execute = lambda cmd, *a, **k: OPENED_ATTACKER
    result = executor.investigate_ftp_sessions()
    assert result["foreign_ips"] == ["192.168.64.11"]
    assert len(result["sessions"]) == 1
    assert result["sessions"][0]["source_ip"] == "192.168.64.11"
    assert result["sessions"][0]["event"] == "opened"


def test_mixed_self_and_attacker_sessions_only_reports_attacker():
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    raw = "\n".join([OPENED_SELF, OPENED_ATTACKER, CLOSED_ATTACKER])
    executor.execute = lambda cmd, *a, **k: raw
    result = executor.investigate_ftp_sessions()
    assert result["foreign_ips"] == ["192.168.64.11"]
    assert len(result["sessions"]) == 2
    assert [s["event"] for s in result["sessions"]] == ["opened", "closed"]


def test_never_sets_flag_access_detected():
    # Attribution-only sensor: must not claim a breach signal, no matter what
    # it sees. Task 1's investigate_webshells() is the sole breach signal for
    # this family.
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    executor.execute = lambda cmd, *a, **k: OPENED_ATTACKER
    result = executor.investigate_ftp_sessions()
    assert "flag_access_detected" not in result


def test_no_ftp_activity_is_clean():
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    executor.execute = lambda cmd, *a, **k: ""
    result = executor.investigate_ftp_sessions()
    assert result["sessions"] == []
    assert result["assessment"] == "CLEAN"
