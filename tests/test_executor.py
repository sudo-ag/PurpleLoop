import datetime
import subprocess
import pytest
from unittest.mock import MagicMock, patch
from src.executor import MAX_LOG_EVENTS, SSH_MASTER_EXPECT, ToolExecutor


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
    executor.execute = MagicMock(return_value="2026 Oct  8 22:22:16\n")
    executor.mark_analysis_window()
    assert executor._analysis_year == 2026
    assert executor.analysis_since == _syslog_line_epoch("Oct  8 22:22:16", 2026, None)
    assert executor.execute.call_args.args[0] == 'date "+%Y %b %e %H:%M:%S"'


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
