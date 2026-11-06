"""investigate_box_anomalies: window-bound baseline-diff of listening ports +
full user-account list -- a catch-all sensor for signals no other sensor
owns (investigate_privileged_accounts only tracks uid-0 accounts)."""
from src.executor import ToolExecutor


_SS_HEADER = "State      Recv-Q Send-Q Local Address:Port    Peer Address:Port Process"


def _ss_output(ports):
    lines = [_SS_HEADER]
    for port in ports:
        lines.append(f"LISTEN     0      128    0.0.0.0:{port}         0.0.0.0:*")
    return "\n".join(lines)


def _ex_returning(ports, users) -> ToolExecutor:
    ex = ToolExecutor(host="mock", user="u", pwd="p")  # __init__ does not connect
    ex._stub_ports = list(ports)
    ex._stub_users = list(users)

    def fake_execute(cmd, *a, **k):
        if "date " in cmd:
            return "2026 Oct  8 22:22:16|1760000000\n"
        if "SSH_CONNECTION" in cmd:
            return "192.168.64.1 51000 192.168.64.12 22\n"
        if "ss -tln" in cmd:
            return _ss_output(ex._stub_ports)
        if "getent passwd" in cmd:
            return "\n".join(ex._stub_users)
        return ""

    ex.execute = fake_execute  # type: ignore[method-assign]
    ex._stub_set_ports = lambda ports: setattr(ex, "_stub_ports", list(ports))
    ex._stub_set_users = lambda users: setattr(ex, "_stub_users", list(users))
    return ex


def test_new_listening_port_is_a_breach():
    ex = _ex_returning(ports=["22", "80"], users=["root", "alice"])
    ex.mark_analysis_window()
    ex._stub_set_ports(["22", "80", "4444"])  # attacker backdoor listener
    r = ex.investigate_box_anomalies()
    assert r["new_ports"] == ["tcp:4444"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_new_user_account_is_a_breach():
    ex = _ex_returning(ports=["22", "80"], users=["root", "alice"])
    ex.mark_analysis_window()
    ex._stub_set_users(["root", "alice", "backdoor"])
    r = ex.investigate_box_anomalies()
    assert r["new_users"] == ["backdoor"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_no_change_is_clean():
    ex = _ex_returning(ports=["22", "80"], users=["root", "alice"])
    ex.mark_analysis_window()
    r = ex.investigate_box_anomalies()
    assert r["new_ports"] == [] and r["new_users"] == []
    assert r["flag_access_detected"] is False and r["assessment"] == "CLEAN"


def test_no_baseline_is_clean_not_breach():
    ex = _ex_returning(ports=["22", "80"], users=["root", "alice"])
    # mark_analysis_window() never called -> no baseline
    r = ex.investigate_box_anomalies()
    assert r["flag_access_detected"] is False and r.get("baseline_unavailable") is True


def test_ports_baseline_failure_still_allows_users_diff():
    # ss returns nothing at baseline time -> ports baseline is None, but the
    # users baseline captured fine. The two signals are independent; one
    # failing must not blind the other.
    ex = _ex_returning(ports=[], users=["root", "alice"])
    ex.mark_analysis_window()
    assert ex._ports_baseline is None
    assert ex._users_baseline is not None
    ex._stub_set_users(["root", "alice", "backdoor"])
    r = ex.investigate_box_anomalies()
    assert r.get("baseline_unavailable") is not True
    assert r["ports_unavailable"] is True
    assert r["new_users"] == ["backdoor"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_users_baseline_failure_still_allows_ports_diff():
    # getent passwd returns nothing at baseline time -> users baseline is
    # None, but the ports baseline captured fine.
    ex = _ex_returning(ports=["22", "80"], users=[])
    ex.mark_analysis_window()
    assert ex._users_baseline is None
    assert ex._ports_baseline is not None
    ex._stub_set_ports(["22", "80", "4444"])
    r = ex.investigate_box_anomalies()
    assert r.get("baseline_unavailable") is not True
    assert r["users_unavailable"] is True
    assert r["new_ports"] == ["tcp:4444"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_blue_own_ssh_login_is_not_a_new_port():
    # Blue's own SSH-in connection is a client-side connection, not a new
    # LISTEN-state socket -- sshd was already listening on 22 at baseline
    # time, so no self-filter is needed, and the set stays unchanged.
    ex = _ex_returning(ports=["22"], users=["root"])
    ex.mark_analysis_window()
    r = ex.investigate_box_anomalies()
    assert r["new_ports"] == []
    assert r["flag_access_detected"] is False and r["assessment"] == "CLEAN"


def test_ports_baseline_missing_one_expected_port_is_still_valid():
    # Structural validity, not "port 22 must be present": a baseline read
    # that happens not to include port 22 (e.g. sshd not up yet at window
    # open) must still be a trustworthy, well-formed baseline.
    ex = _ex_returning(ports=["80"], users=["root", "alice"])
    ex.mark_analysis_window()
    assert ex._ports_baseline is not None
    assert ex._ports_baseline == {"tcp:80"}
    ex._stub_set_ports(["80", "22"])  # port 22 shows up later -> still "new"
    r = ex.investigate_box_anomalies()
    assert r["new_ports"] == ["tcp:22"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_users_baseline_missing_one_expected_user_is_still_valid():
    # Structural validity, not "alice must be present": a baseline read
    # that happens not to include some particular username must still be
    # a trustworthy, well-formed baseline.
    ex = _ex_returning(ports=["22"], users=["root"])
    ex.mark_analysis_window()
    assert ex._users_baseline is not None
    assert ex._users_baseline == {"root"}
    ex._stub_set_users(["root", "alice"])  # alice shows up later -> still "new"
    r = ex.investigate_box_anomalies()
    assert r["new_users"] == ["alice"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"
