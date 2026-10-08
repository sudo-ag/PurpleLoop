import logging
import subprocess
import json
import re
import os
import tempfile
import atexit
import datetime
from typing import List, Optional, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


MAX_LOG_EVENTS = 25


# How long the master connection lingers after the last session closes. It must
# comfortably outlast the longest gap between commands (model inference can take
# minutes); if it ever does drop, execute_remote() self-heals by reconnecting.
DEFAULT_CONTROL_PERSIST = int(os.getenv("PL_SSH_CONTROL_PERSIST", "900"))

# Brings up a backgrounded OpenSSH ControlMaster. We authenticate with the
# password exactly once here; every later command rides the control socket with
# no auth at all (see _ssh_session_cmd). We shell out to the system `ssh` binary
# on purpose: on macOS it holds Local Network entitlement that a venv Python does
# not, so a raw paramiko socket to a LAN target is blocked ("No route to host").
SSH_MASTER_EXPECT = r"""
set timeout $env(PL_SSH_TIMEOUT)

spawn -noecho ssh -M -N -f \
    -o ControlPath=$env(PL_SSH_CONTROL) \
    -o ControlPersist=$env(PL_SSH_PERSIST) \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=$env(PL_SSH_TIMEOUT) \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 \
    -- "$env(PL_SSH_USER)@$env(PL_SSH_HOST)"

expect {
    -re "(?i)are you sure you want to continue connecting" {
        send "yes\r"
        exp_continue
    }
    -re "(?i)password:" {
        send -- "$env(PL_SSH_PASSWORD)\r"
        exp_continue
    }
    -re "(?i)permission denied" {
        exit 5
    }
    timeout {
        exit 124
    }
    eof
}

catch wait result
exit [lindex $result 3]
"""


def _compact_log_events(
    events: List[Dict[str, Any]],
    limit: int = MAX_LOG_EVENTS,
) -> List[Dict[str, Any]]:
    if len(events) <= limit:
        return events

    selected: List[int] = []
    selected_set: set[int] = set()

    def select(index: int) -> None:
        if index not in selected_set and len(selected) < limit:
            selected.append(index)
            selected_set.add(index)

    critical_indexes = [
        index
        for index, event in enumerate(events)
        if event.get("severity") == "critical"
    ]
    for index in critical_indexes[-limit:]:
        select(index)

    for index in range(len(events) - 1, -1, -1):
        if len(selected) >= limit:
            break
        if events[index].get("severity") in ("medium", "high", "critical"):
            select(index)

    for index in range(len(events) - 1, -1, -1):
        if len(selected) >= limit:
            break
        select(index)

    return [events[index] for index in sorted(selected)]


def _clean_openssh_output(output: str) -> str:
    cleaned_lines = []
    for line in output.splitlines():
        if "Permanently added" in line and "known hosts" in line:
            continue
        if re.search(r"(?i)password:\s*$", line):
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines).strip("\n")
    return f"{cleaned}\n" if cleaned else ""


_SYSLOG_MONTHS = {
    m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)
}


def _syslog_line_epoch(line: str, year: int, ref_epoch: Optional[float]) -> Optional[float]:
    """Epoch of a line's leading syslog timestamp ("Sep 16 22:59:12"), or None.

    Syslog omits the year, so we anchor to the target's year. If that lands the
    event more than a day in the future of ref_epoch, it's a December-read-in-
    January wrap, so roll back a year.
    """
    parts = line.split(maxsplit=3)
    if len(parts) < 3:
        return None
    month = _SYSLOG_MONTHS.get(parts[0])
    if month is None:
        return None
    try:
        day = int(parts[1])
        hh, mm, ss = (int(x) for x in parts[2].split(":"))
        ts = datetime.datetime(year, month, day, hh, mm, ss).timestamp()
    except (ValueError, TypeError):
        return None
    if ref_epoch is not None and ts > ref_epoch + 86400:
        try:
            ts = datetime.datetime(year - 1, month, day, hh, mm, ss).timestamp()
        except ValueError:
            pass
    return ts


class ToolExecutor:
    """
    The SSH Bridge for executing commands on a target host.
    Supports persistent connections to reduce overhead.

    Also provides blue-team investigation tools (Option B — structured signals)
    that return JSON findings the blue agent can use to build an incident report.
    """
    FORBIDDEN_KEYWORDS: List[str] = [
        "rm -rf /",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        "passwd",
        "/etc/shadow",
        "/etc/passwd"
    ]

    def __init__(self, host: str, user: str, pwd: str, timeout: int = 60):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.timeout = timeout
        # One control socket per executor instance, so parallel targets never
        # collide. Short dir keeps us well under the ~104-char AF_UNIX path cap.
        self._control_dir = tempfile.mkdtemp(prefix="pl-ssh-")
        self._control_path = os.path.join(self._control_dir, "cm.sock")
        # Blue log analysis is scoped to events at/after this target-clock epoch.
        # None = no scoping (full history), which is the default for unit tests.
        self.analysis_since: Optional[float] = None
        self._analysis_year: int = datetime.datetime.now().year
        # Safety net: tear down the master if the orchestrator never calls
        # disconnect() (crash, Ctrl-C), so we don't leak backgrounded ssh procs.
        atexit.register(self.disconnect)

    @property
    def _target(self) -> str:
        return f"{self.user}@{self.host}"

    def _master_alive(self) -> bool:
        return os.path.exists(self._control_path)

    def connect(self):
        """Brings up the shared SSH ControlMaster (one password auth per host)."""
        if self._master_alive():
            return

        logger.info(f"Opening SSH master to {self.host}...")
        os.makedirs(self._control_dir, exist_ok=True)
        env = dict(os.environ)
        env.update({
            "PL_SSH_USER": self.user,
            "PL_SSH_HOST": self.host,
            "PL_SSH_PASSWORD": self.pwd,
            "PL_SSH_TIMEOUT": str(self.timeout),
            "PL_SSH_CONTROL": self._control_path,
            "PL_SSH_PERSIST": str(DEFAULT_CONTROL_PERSIST),
        })
        try:
            proc = subprocess.run(
                ["expect", "-c", SSH_MASTER_EXPECT],
                capture_output=True,
                text=True,
                timeout=self.timeout + 15,
                env=env,
            )
        except FileNotFoundError as e:
            raise RuntimeError(
                "SSH master requires /usr/bin/expect, but expect was not found."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"Timed out establishing SSH master to {self.host}."
            ) from e

        if not self._master_alive():
            detail = (proc.stdout or proc.stderr or "").strip().splitlines()
            raise RuntimeError(
                f"Failed to establish SSH master to {self.host}: "
                f"{detail[-1] if detail else 'unknown error'}"
            )
        logger.info("SSH master established to %s.", self.host)

    def disconnect(self):
        """Tears down the ControlMaster and cleans up the socket."""
        if self._master_alive():
            subprocess.run(
                ["ssh", "-O", "exit", "-o", f"ControlPath={self._control_path}",
                 "--", self._target],
                capture_output=True, text=True, timeout=10,
            )
        try:
            if os.path.exists(self._control_path):
                os.remove(self._control_path)
            if os.path.isdir(self._control_dir):
                os.rmdir(self._control_dir)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Generic command execution
    # ------------------------------------------------------------------

    def _check_forbidden(self, command: str, scope: str) -> None:
        for keyword in self.FORBIDDEN_KEYWORDS:
            if keyword in command:
                logger.warning(f"Blocked forbidden {scope} command: {command}")
                raise ValueError(f"Forbidden command: {keyword} detected.")

    def _ssh_session_cmd(self, command: str) -> List[str]:
        # Rides the existing master over ControlPath. BatchMode=yes means that if
        # the master is somehow gone it fails fast (rc 255) instead of hanging on
        # a password prompt, which is exactly the signal execute_remote() retries.
        return [
            "ssh",
            "-o", f"ControlPath={self._control_path}",
            "-o", "ControlMaster=no",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "--",
            self._target,
            command,
        ]

    def _run_session(self, command: str) -> "tuple[bool, str]":
        """Run one command over the master. Returns (connection_ok, text)."""
        try:
            result = subprocess.run(
                self._ssh_session_cmd(command),
                capture_output=True,
                text=True,
                timeout=self.timeout + 10,
            )
        except FileNotFoundError:
            return True, "Error: 'ssh' client not found on PATH."
        except subprocess.TimeoutExpired:
            return True, f"Error: Remote command timed out after {self.timeout} seconds."

        # ssh uses exit code 255 exclusively for its own connection errors. With
        # no stdout, that means the master dropped — signal a reconnect+retry.
        if result.returncode == 255 and not result.stdout:
            return False, result.stderr.strip()

        output = _clean_openssh_output(result.stdout)
        if output:
            return True, output
        if result.stderr.strip():
            return True, result.stderr
        if result.returncode != 0:
            return True, f"Remote command failed with exit code {result.returncode}."
        return True, "Remote command executed successfully (no output)."

    def execute_remote(self, command: str) -> str:
        """
        Executes a command on the target host over the shared SSH ControlMaster.
        Self-heals: if the master has aged out (long idle gaps during model
        inference), it is re-established once and the command retried.
        """
        self._check_forbidden(command, "remote")

        if not self._master_alive():
            self.connect()

        ok, text = self._run_session(command)
        if ok:
            return text

        # Master dropped mid-run — rebuild it once and retry. disconnect() first
        # clears any stale socket so _master_alive() in connect() isn't fooled.
        logger.warning("SSH master to %s dropped; reconnecting.", self.host)
        try:
            self.disconnect()
            self.connect()
        except Exception as e:
            return f"Error: SSH connection to {self.host} failed: {e}"
        ok, text = self._run_session(command)
        if not ok:
            return f"Error: SSH connection to {self.host} failed: {text}"
        return text

    def execute_local(self, command: str) -> str:
        """
        Executes a command on the local machine (e.g., Kali host) and returns the output.
        """
        self._check_forbidden(command, "local")

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.stdout:
                return result.stdout
            if result.stderr:
                return f"Local Error: {result.stderr}"
            return "Local command executed successfully (no output)."

        except subprocess.TimeoutExpired:
            return f"Error: Local command timed out after {self.timeout} seconds."
        except Exception as e:
            return f"Local execution failed: {str(e)}"

    def execute(self, command: str) -> str:
        """
        Legacy wrapper for backward compatibility. Always routes to remote.
        """
        return self.execute_remote(command)

    def mark_analysis_window(self) -> None:
        """
        Start blue's log-analysis window at the target's current time.

        Events older than this are pre-existing box history (flag provisioning,
        prior runs) — not this engagement — so blue ignores them and can no
        longer win on stale logs. Anchored to the target's own clock, read over
        SSH, so controller/target time skew can't shift the window.
        """
        out = self.execute("date +%s").strip()
        try:
            self.analysis_since = float(out.split()[0])
        except (ValueError, IndexError):
            self.analysis_since = None
            logger.warning("Could not read target clock; blue will see full log history.")
            return
        self._analysis_year = datetime.datetime.fromtimestamp(self.analysis_since).year
        logger.info("Blue analysis window starts at target epoch %d.", int(self.analysis_since))

    def _within_window(self, line: str) -> bool:
        """True if a log line is in blue's analysis window (or no window is set)."""
        if self.analysis_since is None:
            return True
        ts = _syslog_line_epoch(line, self._analysis_year, self.analysis_since)
        # Fail open: lines we can't timestamp are kept rather than silently lost.
        return ts is None or ts >= self.analysis_since

    # ------------------------------------------------------------------
    # Blue team investigation tools (Option B — structured signals)
    # These return JSON-formatted strings that the blue agent can parse
    # and use to build an incident report.
    # ------------------------------------------------------------------

    def investigate_logs(self, log_type: str = "auth") -> Dict[str, Any]:
        """
        Investigate system logs for suspicious activity.
        Returns a dict with structured findings.

        log_type: "auth" (auth.log) or "syslog" (syslog/messages)
        """
        if log_type == "auth":
            raw = self.execute(
                "sudo cat /var/log/auth.log 2>/dev/null || "
                "cat /var/log/auth.log 2>/dev/null || true"
            )
            return self._parse_auth_log(raw)
        elif log_type == "syslog":
            raw = self.execute(
                "sudo tail -100 /var/log/syslog 2>/dev/null || "
                "sudo tail -100 /var/log/messages 2>/dev/null || "
                "cat /var/log/syslog 2>/dev/null || true"
            )
            return self._parse_syslog(raw)
        else:
            return {
                "tool": "investigate_logs",
                "log_type": log_type,
                "error": f"Log type '{log_type}' not supported",
                "events": [],
            }

    def investigate_processes(self) -> Dict[str, Any]:
        """
        Examine running processes for suspicious activity.
        Returns a dict with process findings.
        """
        raw = self.execute(
            "ps aux 2>/dev/null || ps -ef 2>/dev/null || true"
        )
        return self._parse_ps(raw)

    def investigate_network(self) -> Dict[str, Any]:
        """
        Examine network state for suspicious listeners and connections.
        Returns a dict with network findings.
        """
        raw = self.execute(
            "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || true"
        )
        return self._parse_network(raw)

    def investigate_file_access(self, file_path: str = "/root/flag.txt") -> Dict[str, Any]:
        """
        Check access history for a sensitive file.
        Returns a dict with structured access findings.
        """
        audit_raw = self.execute(
            f"sudo ausearch -f '{file_path}' -ts recent 2>/dev/null || true"
        )
        stat_raw = self.execute(
            f"stat '{file_path}' 2>/dev/null || true"
        )
        ls_raw = self.execute(
            f"sudo ls -la '{file_path}' 2>/dev/null || "
            f"ls -la '{file_path}' 2>/dev/null || true"
        )
        return self._parse_file_access(audit_raw, stat_raw, ls_raw, file_path)

    # ------------------------------------------------------------------
    # Parsers — turn raw command output into structured signals
    # ------------------------------------------------------------------

    def _parse_auth_log(self, raw: str) -> Dict[str, Any]:
        if not raw or raw.strip() in ("", "true"):
            return {
                "tool": "investigate_logs",
                "log_type": "auth",
                "error": "No auth.log available",
                "events": [],
                "failed_auth_count": 0,
                "successful_logins": 0,
                "sudo_commands": 0,
                "flag_access_detected": False,
                "suspicious_events": 0,
                "critical_events": 0,
                "suspicious_ips": [],
                "suspicious_users": [],
                "summary": "No auth.log available.",
                "assessment": "CLEAN",
                "recommendation": "Monitor for suspicious activity.",
            }

        events = []
        failed_count = 0
        success_count = 0
        sudo_count = 0
        flag_access = False
        ioc_ips: set = set()
        ioc_users: set = set()

        for line in raw.splitlines():
            if not line.strip():
                continue
            if not self._within_window(line):
                continue
            evt: Dict[str, Any] = {"raw": line}
            if "Failed password" in line or "authentication failure" in line.lower():
                failed_count += 1
                evt["severity"] = "medium"
                evt["event"] = "Failed password"
                for ip in _find_all_ip(line):
                    ioc_ips.add(ip)
                user = _find_user(line)
                if user:
                    ioc_users.add(user)
                evt["note"] = "Failed login attempt"
                events.append(evt)
            elif "Accepted password" in line or " Accepted " in line:
                success_count += 1
                evt["severity"] = "high"
                evt["event"] = "Successful authentication"
                for ip in _find_all_ip(line):
                    ioc_ips.add(ip)
                user = _find_user(line)
                if user:
                    ioc_users.add(user)
                evt["note"] = "Successful login"
                events.append(evt)
            elif "sudo:" in line and "COMMAND=" in line:
                sudo_count += 1
                evt["severity"] = "high"
                evt["event"] = "Sudo command executed"
                user = _find_user(line)
                if user:
                    ioc_users.add(user)
                cmd = _find_command(line)
                if cmd and ("flag" in cmd.lower() or "sensitive" in cmd.lower() or "passwd" in cmd.lower()):
                    evt["severity"] = "critical"
                    evt["note"] = f"Sensitive command executed via sudo: {cmd}"
                    flag_access = True
                else:
                    evt["note"] = f"Sudo: {cmd}"
                evt["indicator"] = "sudo_escalation"
                events.append(evt)
            elif "session opened" in line.lower():
                evt["severity"] = "informational"
                evt["event"] = "Session opened"
                events.append(evt)
            elif "session closed" in line.lower():
                evt["severity"] = "informational"
                evt["event"] = "Session closed"
                events.append(evt)

        critical_count = sum(1 for e in events if e.get("severity") == "critical")
        suspicious_count = sum(
            1 for e in events
            if e.get("severity") in ("medium", "high", "critical")
        )

        summary = (
            f"Auth log: {len(raw.splitlines())} lines. "
            f"Failures: {failed_count}, Successes: {success_count}, "
            f"Sudo: {sudo_count}, Critical: {critical_count}."
        )
        if ioc_ips:
            summary += f" Suspicious IPs: {', '.join(sorted(ioc_ips))}."
        if ioc_users:
            summary += f" Suspicious users: {', '.join(sorted(ioc_users))}."
        if flag_access:
            summary += " FLAG FILE ACCESS DETECTED."

        assessment = (
            "BREACH" if flag_access
            else "SUSPICIOUS" if (suspicious_count >= 2 or sudo_count > 0)
            else "MONITOR" if failed_count > 2
            else "CLEAN"
        )
        recommendation = (
            "IMMEDIATE ACTION: Flag file was accessed. Treat as confirmed compromise. "
            "Investigate the user and IP. Check for persistence. Rotate credentials."
            if flag_access
            else "Investigate the suspicious activity. Review sudo usage. "
            "Check for lateral movement."
            if suspicious_count >= 2
            else "Monitor the failed login attempts. Consider blocking the source IP."
        )

        visible_events = _compact_log_events(events)

        findings = {
            "tool": "investigate_logs",
            "log_type": "auth",
            "total_events": len(raw.splitlines()),
            "parsed_events": len(events),
            "events": visible_events,
            "events_returned": len(visible_events),
            "events_omitted": max(0, len(events) - len(visible_events)),
            "failed_attempts": failed_count,
            "successful_logins": success_count,
            "sudo_commands": sudo_count,
            "flag_access_detected": flag_access,
            "suspicious_events": suspicious_count,
            "critical_events": critical_count,
            "suspicious_ips": sorted(ioc_ips),
            "suspicious_users": sorted(ioc_users),
            "summary": summary,
            "assessment": assessment,
            "recommendation": recommendation,
        }
        return findings

    def _parse_syslog(self, raw: str) -> Dict[str, Any]:
        if not raw or raw.strip() in ("", "true"):
            return {
                "tool": "investigate_logs",
                "log_type": "syslog",
                "error": "No syslog available",
                "events": [],
            }

        events = []
        sudo_events = 0
        flag_access = False
        ioc_users: set = set()

        for line in raw.splitlines():
            if not line.strip():
                continue
            if not self._within_window(line):
                continue
            evt: Dict[str, Any] = {"raw": line}
            if "sudo:" in line and "COMMAND=" in line:
                sudo_events += 1
                evt["severity"] = "high"
                evt["event"] = "Sudo command"
                user = _find_user(line)
                if user:
                    ioc_users.add(user)
                cmd = _find_command(line)
                evt["command"] = cmd
                if cmd and ("flag" in cmd.lower() or "sensitive" in cmd.lower()):
                    evt["severity"] = "critical"
                    evt["flag_access"] = True
                    flag_access = True
                events.append(evt)
            elif "sshd" in line.lower() and "session" in line.lower():
                evt["severity"] = "informational"
                evt["event"] = "SSH session"
                events.append(evt)

        critical_count = sum(1 for e in events if e.get("severity") == "critical")
        suspicious_count = sum(
            1 for e in events
            if e.get("severity") in ("medium", "high", "critical")
        )

        summary = (
            f"Syslog: {len(raw.splitlines())} lines. "
            f"Sudo events: {sudo_events}, Critical: {critical_count}."
        )
        if ioc_users:
            summary += f" Users: {', '.join(sorted(ioc_users))}."
        if flag_access:
            summary += " FLAG FILE ACCESS DETECTED."

        assessment = (
            "BREACH" if flag_access
            else "SUSPICIOUS" if sudo_events > 0
            else "CLEAN"
        )
        recommendation = (
            "Investigate sudo usage and flag access." if flag_access
            else "Review sudo activity."
        )

        visible_events = _compact_log_events(events)

        return {
            "tool": "investigate_logs",
            "log_type": "syslog",
            "total_events": len(raw.splitlines()),
            "parsed_events": len(events),
            "events": visible_events,
            "events_returned": len(visible_events),
            "events_omitted": max(0, len(events) - len(visible_events)),
            "sudo_events": sudo_events,
            "flag_access_detected": flag_access,
            "suspicious_events": suspicious_count,
            "critical_events": critical_count,
            "suspicious_users": sorted(ioc_users),
            "summary": summary,
            "assessment": assessment,
            "recommendation": recommendation,
        }

    def _parse_ps(self, raw: str) -> Dict[str, Any]:
        if not raw or raw.strip() in ("", "true"):
            return {
                "tool": "investigate_processes",
                "error": "No process list available",
                "processes": [],
                "suspicious_processes": [],
                "critical_processes": [],
                "suspicious_count": 0,
                "critical_count": 0,
                "summary": "No process list available.",
                "assessment": "CLEAN",
                "recommendation": "Investigate any suspicious processes.",
            }

        processes = []
        suspicious = []

        for line in raw.splitlines():
            if not line.strip():
                continue
            proc = _parse_ps_line(line)
            if proc:
                processes.append(proc)
                if proc.get("suspicious"):
                    suspicious.append(proc)

        critical = [p for p in suspicious if p.get("critical")]
        suspicious_count = len(suspicious)
        critical_count = len(critical)

        # Trim to a manageable size: all suspicious + top 10 by CPU
        shown_processes = suspicious + [
            p for p in processes if not p.get("suspicious")
        ]
        shown_processes.sort(key=lambda p: float(p.get("cpu", "0") or "0"), reverse=True)
        if len(shown_processes) > 10 + suspicious_count:
            shown_processes = shown_processes[: 10 + suspicious_count]

        # Trim each process to the fields the model needs
        trimmed = []
        for p in shown_processes:
            trimmed.append({
                "pid": p.get("pid"),
                "user": p.get("user"),
                "cpu": p.get("cpu"),
                "mem": p.get("mem"),
                "command": p.get("command"),
                "suspicious": p.get("suspicious", False),
                "critical": p.get("critical", False),
                "reasons": p.get("reasons", []),
            })

        summary = (
            f"Processes: {len(processes)} total (showing top 10 + suspicious). "
            f"Suspicious: {suspicious_count}, Critical: {critical_count}."
        )
        if critical:
            summary += " CRITICAL: Suspicious processes that may indicate attacker activity."
        elif suspicious:
            summary += " Some suspicious processes detected — review."
        else:
            summary += " No obvious suspicious processes."

        return {
            "tool": "investigate_processes",
            "total_processes": len(processes),
            "shown_count": len(trimmed),
            "processes": trimmed,
            "suspicious_processes": [
                {
                    "pid": p.get("pid"),
                    "user": p.get("user"),
                    "cpu": p.get("cpu"),
                    "mem": p.get("mem"),
                    "command": p.get("command"),
                    "suspicious": p.get("suspicious", False),
                    "critical": p.get("critical", False),
                    "reasons": p.get("reasons", []),
                }
                for p in suspicious
            ],
            "critical_processes": [
                {
                    "pid": p.get("pid"),
                    "user": p.get("user"),
                    "cpu": p.get("cpu"),
                    "mem": p.get("mem"),
                    "command": p.get("command"),
                    "suspicious": p.get("suspicious", False),
                    "critical": p.get("critical", False),
                    "reasons": p.get("reasons", []),
                }
                for p in critical
            ],
            "suspicious_count": suspicious_count,
            "critical_count": critical_count,
            "summary": summary,
            "assessment": (
                "BREACH" if critical_count > 0
                else "SUSPICIOUS" if suspicious_count > 0
                else "CLEAN"
            ),
            "recommendation": (
                "Investigate the suspicious processes. If flag file access was seen, "
                "terminate attacker shells."
                if critical_count > 0
                else "Investigate any suspicious processes."
            ),
        }

    def _parse_network(self, raw: str) -> Dict[str, Any]:
        if not raw or raw.strip() in ("", "true"):
            return {
                "tool": "investigate_network",
                "error": "No network data available",
                "listeners": [],
                "connections": [],
                "suspicious_listeners": [],
                "suspicious_count": 0,
                "critical_count": 0,
                "summary": "No network data available.",
                "assessment": "CLEAN",
                "recommendation": "No obvious network anomalies.",
            }

        listeners = []
        connections = []
        suspicious_listeners = []

        for line in raw.splitlines():
            if not line.strip():
                continue
            if "Proto" in line or "Active" in line or "Recv-Q" in line:
                # Header line — skip
                continue
            parsed = _parse_netstat_line(line)
            if parsed:
                if parsed.get("state") == "LISTEN":
                    listeners.append(parsed)
                    if parsed.get("suspicious"):
                        suspicious_listeners.append(parsed)
                else:
                    connections.append(parsed)

        suspicious_count = len(suspicious_listeners)
        critical_count = sum(1 for l in suspicious_listeners if l.get("critical"))

        summary = (
            f"Listeners: {len(listeners)}, Connections: {len(connections)}."
        )
        if suspicious_listeners:
            summary += f" {suspicious_count} suspicious listener(s)."
        if not listeners and not connections:
            summary += " No network data."

        return {
            "tool": "investigate_network",
            "listeners": listeners[:50],
            "connections": connections[:50],
            "suspicious_listeners": suspicious_listeners,
            "suspicious_count": suspicious_count,
            "critical_count": critical_count,
            "summary": summary,
            "assessment": (
                "SUSPICIOUS" if suspicious_count > 0
                else "CLEAN"
            ),
            "recommendation": (
                "Investigate any unexpected listeners or connections."
                if suspicious_count > 0
                else "No obvious network anomalies."
            ),
        }

    def _parse_file_access(
        self,
        audit_raw: str,
        stat_raw: str,
        ls_raw: str,
        filepath: str,
    ) -> Dict[str, Any]:
        findings: Dict[str, Any] = {
            "tool": "investigate_file_access",
            "filepath": filepath,
            "file_exists": False,
            "file_permissions": None,
            "file_owner": None,
            "file_size": None,
            "audit_available": False,
            "access_events": [],
            "suspicious_access_count": 0,
            "critical_access_count": 0,
            "summary": "",
            "assessment": "UNKNOWN",
            "recommendation": "",
        }

        # File exists and what are its permissions?
        if ls_raw and not ls_raw.strip().startswith("Error:") and ls_raw.strip() != "true":
            if filepath in ls_raw or "/root/" in ls_raw:
                findings["file_exists"] = True
                findings["ls_output"] = ls_raw.strip()
                for line in ls_raw.splitlines():
                    if filepath in line or (line.strip().startswith("-") or line.strip().startswith("d")):
                        parts = line.split()
                        if len(parts) >= 3:
                            findings["file_permissions"] = parts[0]
                            findings["file_owner"] = parts[2]

        # Stat info
        if stat_raw and not stat_raw.strip().startswith("Error:") and stat_raw.strip() != "true":
            findings["stat_available"] = True
            findings["stat_output"] = stat_raw.strip()

        # Auditd info
        if audit_raw and not audit_raw.strip().startswith("Error:") and audit_raw.strip() != "true":
            findings["audit_available"] = True
            findings["audit_output"] = audit_raw.strip()
            for line in audit_raw.splitlines():
                if not line.strip():
                    continue
                evt: Dict[str, Any] = {"raw": line, "severity": "informational"}
                if "cat" in line.lower() or "read" in line.lower():
                    evt["action"] = "read"
                    evt["severity"] = "critical"
                    evt["note"] = "File read operation"
                    findings["critical_access_count"] += 1
                elif "write" in line.lower() or "modify" in line.lower():
                    evt["action"] = "write"
                    evt["severity"] = "high"
                    evt["note"] = "File write operation"
                if "user=" in line.lower() or "uid=" in line.lower():
                    evt["user_info"] = line.strip()
                findings["access_events"].append(evt)

        # If file exists and we have no audit data, flag it
        if findings["file_exists"] and not findings["audit_available"]:
            findings["access_events"].append({
                "timestamp": "unknown",
                "action": "exists",
                "severity": "medium",
                "note": (
                    f"Sensitive file {filepath} exists but audit log "
                    "unavailable — access cannot be verified from logs"
                ),
            })
            findings["suspicious_access_count"] = 1

        # Count suspicious/critical
        for evt in findings["access_events"]:
            sev = evt.get("severity", "informational")
            if sev in ("high", "critical"):
                findings["suspicious_access_count"] += 1
            if sev == "critical":
                findings["critical_access_count"] += 1

        # Build summary and assessment
        if findings["file_exists"]:
            if findings["audit_available"] and findings["critical_access_count"] > 0:
                findings["summary"] = (
                    f"CRITICAL: Sensitive file {filepath} was accessed/read. "
                    "Audit logs confirm access. Possible data exfiltration."
                )
                findings["assessment"] = "BREACH"
                findings["recommendation"] = (
                    "IMMEDIATE: Treat as confirmed compromise. Preserve evidence. "
                    "Investigate attacker. Rotate credentials. Check for exfiltration."
                )
            elif findings["audit_available"] and findings["suspicious_access_count"] > 0:
                findings["summary"] = (
                    f"Suspicious access to {filepath} detected. "
                    "Audit logs show access events that warrant investigation."
                )
                findings["assessment"] = "BREACH"
                findings["recommendation"] = (
                    "Investigate the access events. Determine if data was exfiltrated."
                )
            elif findings["audit_available"]:
                findings["summary"] = (
                    f"Audit logs available for {filepath}. "
                    "No suspicious access events detected in audit log."
                )
                findings["assessment"] = "CLEAN"
                findings["recommendation"] = (
                    "Continue monitoring. No suspicious access detected in audit logs."
                )
            else:
                findings["summary"] = (
                    f"Sensitive file {filepath} exists. "
                    "Audit logs not available — access cannot be verified from logs."
                )
                findings["assessment"] = "SUSPICIOUS"
                findings["recommendation"] = (
                    "Enable audit logging for sensitive files. "
                    "Investigate whether file was accessed."
                )
        else:
            findings["summary"] = (
                f"Sensitive file {filepath} does not exist "
                "or is not accessible."
            )
            findings["assessment"] = "INFO"
            findings["recommendation"] = (
                "Flag file not found at expected path. "
                "Investigate other locations."
            )

        return findings

    def investigate_users(self) -> str:
        """
        Check for suspicious user accounts or modifications.
        Returns a JSON string with user findings.
        """
        passwd_raw = self.execute(
            "cat /etc/passwd 2>/dev/null || true"
        )
        sudoers_raw = self.execute(
            "sudo cat /etc/sudoers 2>/dev/null || "
            "sudo cat /etc/sudoers.d/* 2>/dev/null || true"
        )
        lastlog_raw = self.execute(
            "sudo lastlog 2>/dev/null || lastlog 2>/dev/null || true"
        )
        return self._parse_users(passwd_raw, sudoers_raw, lastlog_raw)

    def investigate_cron(self) -> str:
        """
        Check for suspicious cron jobs or scheduled tasks.
        Returns a JSON string with cron findings.
        """
        crontab_raw = self.execute(
            "sudo crontab -l 2>/dev/null || true"
        )
        cron_dirs_raw = self.execute(
            "sudo ls -la /etc/cron.d/ /etc/cron.daily/ "
            "/etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ "
            "2>/dev/null || true"
        )
        return self._parse_cron(crontab_raw, cron_dirs_raw)

    # ------------------------------------------------------------------
    # User and cron parsers
    # ------------------------------------------------------------------

    def _parse_users(
        self,
        passwd_raw: str,
        sudoers_raw: str,
        lastlog_raw: str,
    ) -> str:
        findings: Dict[str, Any] = {
            "tool": "investigate_users",
            "users": [],
            "suspicious_users": [],
            "sudo_privileged_users": [],
            "recent_logins": [],
            "suspicious_count": 0,
            "critical_count": 0,
            "summary": "",
            "assessment": "CLEAN",
            "recommendation": "",
            "sudoers_has_nopasswd": False,
            "compromised_login": False,
            "compromised_user_candidate": False,
        }

        # Parse /etc/passwd
        users = []
        suspicious_users_list = []
        for line in passwd_raw.splitlines():
            if not line.strip() or ":" not in line:
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                user = parts[0]
                uid = parts[2]
                shell = parts[6]
                users.append({
                    "username": user,
                    "uid": uid,
                    "shell": shell,
                })

        findings["users"] = users
        findings["sudo_privileged_users"] = [
            u["username"] for u in users if u.get("uid") == "0"
        ]

        # Identify suspicious users
        for u in users:
            reasons = []
            username = u.get("username", "")
            uid = u.get("uid", "")
            shell = u.get("shell", "")

            # Standard system accounts to ignore
            standard = {
                "root", "daemon", "bin", "sys", "sync", "games", "man",
                "lp", "mail", "news", "uucp", "proxy", "www-data", "backup",
                "list", "irc", "gnats", "nobody", "systemd-network",
                "systemd-resolve", "messagebus", "_apt", "tss", "rtkit",
                "pulse", "polkitd", "colord", "saned", "uuidd", "tcpdump",
                "landscape", "pollinate", "sshd", "vagrant", "msfadmin",
            }
            if username not in standard and uid not in ("0", "65534"):
                reasons.append("non_standard_user")
            if shell in ("/bin/bash", "/bin/sh", "/bin/zsh",
                         "/usr/bin/bash", "/usr/bin/sh", "/usr/bin/zsh"):
                if username not in ("root", "vagrant", "msfadmin"):
                    reasons.append("interactive_shell")
            if username == "msfadmin":
                reasons.append("compromised_user_candidate")
                findings["compromised_user_candidate"] = True

            if reasons:
                u_copy = dict(u)
                u_copy["suspicious"] = True
                u_copy["reasons"] = reasons
                suspicious_users_list.append(u_copy)

        findings["suspicious_users"] = suspicious_users_list
        findings["suspicious_count"] = len(suspicious_users_list)
        findings["critical_count"] = len([
            u for u in users if u.get("username") == "msfadmin"
        ])

        # Parse sudoers
        if sudoers_raw and not sudoers_raw.strip().startswith("Error:") and sudoers_raw.strip() != "true":
            findings["sudoers_has_nopasswd"] = "NOPASSWD" in sudoers_raw

        # Parse lastlog
        recent_logins = []
        for line in lastlog_raw.splitlines():
            if not line.strip():
                continue
            if "Name" in line or "Never logged in" in line:
                continue
            parts = line.split()
            if len(parts) >= 1:
                username = parts[0]
                tty = parts[1] if len(parts) > 1 else ""
                host = parts[2] if len(parts) > 2 else ""
                recent_logins.append({
                    "username": username,
                    "tty": tty,
                    "host": host,
                })
                if username == "msfadmin":
                    findings["compromised_login"] = True
        findings["recent_logins"] = recent_logins

        # Summary
        parts = []
        if suspicious_users_list:
            parts.append(
                f"{len(suspicious_users_list)} suspicious user(s)"
            )
        if findings.get("compromised_login"):
            parts.append("compromised user login detected")
        if findings.get("sudoers_has_nopasswd"):
            parts.append("passwordless sudo available")
        if findings.get("compromised_user_candidate"):
            parts.append("known compromised user (msfadmin) present")

        findings["summary"] = ". ".join(parts) if parts else (
            "No suspicious user activity detected."
        )

        assessment = "CLEAN"
        if findings.get("compromised_login") or findings.get("compromised_user_candidate"):
            assessment = "BREACH"
        elif findings["suspicious_count"] > 0:
            assessment = "SUSPICIOUS"

        findings["assessment"] = assessment
        findings["recommendation"] = (
            "Investigate the suspicious users and compromised accounts "
            "immediately."
            if assessment == "BREACH"
            else "Review user accounts and sudoers configuration."
            if findings["suspicious_count"] > 0
            else "No urgent user-related findings."
        )

        return json.dumps(findings, indent=2)

    def _parse_cron(self, crontab_raw: str, cron_dirs_raw: str) -> str:
        findings: Dict[str, Any] = {
            "tool": "investigate_cron",
            "crontab_entries": [],
            "cron_directories": [],
            "suspicious_entries": [],
            "suspicious_count": 0,
            "critical_count": 0,
            "summary": "",
            "assessment": "CLEAN",
            "recommendation": "",
        }

        # Parse crontab
        for line in crontab_raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            findings["crontab_entries"].append(line)
            if _cron_entry_is_suspicious(line):
                findings["suspicious_entries"].append(line)
                if _cron_entry_is_critical(line):
                    findings["critical_count"] += 1

        # Parse cron directories
        for line in cron_dirs_raw.splitlines():
            line = line.strip()
            if not line:
                continue
            findings["cron_directories"].append(line)
            if _cron_entry_is_suspicious(line):
                findings["suspicious_entries"].append(line)
                findings["suspicious_count"] += 1

        findings["suspicious_count"] = len(findings["suspicious_entries"])
        findings["critical_count"] = len([
            e for e in findings["suspicious_entries"]
            if _cron_entry_is_critical(e)
        ])

        # Summary
        parts = []
        if findings["suspicious_entries"]:
            parts.append(
                f"{findings['suspicious_count']} suspicious cron "
                "entry(ies)"
            )
        if findings["critical_count"] > 0:
            parts.append("critical cron entries detected")

        findings["summary"] = ". ".join(parts) if parts else (
            "No suspicious cron jobs detected."
        )

        assessment = "CLEAN"
        if findings["critical_count"] > 0:
            assessment = "BREACH"
        elif findings["suspicious_count"] > 0:
            assessment = "SUSPICIOUS"

        findings["assessment"] = assessment
        findings["recommendation"] = (
            "Review and remove suspicious cron jobs immediately. "
            "Check for persistence mechanisms."
            if assessment == "BREACH"
            else "Review cron configuration for anomalies."
            if findings["suspicious_count"] > 0
            else "No urgent cron findings."
        )

        return json.dumps(findings, indent=2)


# ------------------------------------------------------------------
# Helpers for parsing
# ------------------------------------------------------------------

def _find_all_ip(text: str) -> List[str]:
    """Extract IPv4 addresses from a string."""
    return re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)


def _find_user(text: str) -> Optional[str]:
    """Extract username from log lines like:
    'Failed password for msfadmin from ...'
    'msfadmin : TTY=pts/0 ; ... COMMAND=...'
    """
    m = re.search(r'for (\S+) from', text)
    if m:
        return m.group(1)
    m = re.search(r'(\S+) :.*COMMAND=', text)
    if m:
        return m.group(1)
    return None


def _find_command(text: str) -> Optional[str]:
    """Extract command from sudo log lines like:
    '... COMMAND=/usr/bin/cat /root/flag.txt'
    """
    m = re.search(r'COMMAND=(\S.*)', text)
    if m:
        return m.group(1)
    return None


def _parse_ps_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single 'ps aux' line into a structured dict."""
    if not line.strip():
        return None
    parts = line.split()
    if len(parts) < 11:
        return None
    try:
        pid = int(parts[1])
    except ValueError:
        return None

    user = parts[0]
    cpu = parts[2]
    mem = parts[3]
    vsz = parts[4]
    rss = parts[5]
    tty = parts[6]
    etime = parts[7]
    cmd = " ".join(parts[10:])

    suspicion: List[str] = []
    critical = False

    # Root shells
    if user == "root" and _is_shell_cmd(cmd):
        suspicion.append("root_shell")
        if "flag" in cmd.lower():
            critical = True
            suspicion.append("flag_access")

    # Network tools (often used by attackers)
    if _is_network_tool(cmd):
        suspicion.append("network_tool")
        if user == "root":
            critical = True

    # Reverse shell / shell indicators
    if "reverse" in cmd.lower() or "shell" in cmd.lower():
        suspicion.append("reverse_shell_indication")

    # Exploit frameworks
    if "msf" in cmd.lower() or "metasploit" in cmd.lower():
        suspicion.append("exploit_framework")
        critical = True

    # Sensitive file access
    if _cmd_accesses_file(cmd, ["flag", "sensitive", "shadow", "passwd"]):
        suspicion.append("sensitive_file_access")
        critical = True

    # SSH-related (could be attacker using ssh)
    if "ssh" in cmd and not cmd.split()[0].lower().endswith("d"):
        suspicion.append("ssh_related")

    return {
        "pid": pid,
        "user": user,
        "cpu": cpu,
        "mem": mem,
        "vsz": vsz,
        "rss": rss,
        "tty": tty,
        "elapsed": etime,
        "command": cmd,
        "suspicious": len(suspicion) > 0,
        "critical": critical,
        "reasons": suspicion,
    }


def _is_shell_cmd(cmd: str) -> bool:
    """Check if a command looks like a shell."""
    shells = ["bash", "sh", "zsh", "dash", "fish", "csh", "tcsh"]
    cmd_base = cmd.split()[0] if cmd.split() else ""
    return cmd_base in shells


def _is_network_tool(cmd: str) -> bool:
    """Check if a command is a network tool often used by attackers."""
    network_tools = ["nc", "netcat", "ncat", "socat", "netcat", "aircrack", "tcpdump"]
    cmd_base = cmd.split()[0] if cmd.split() else ""
    return cmd_base in network_tools


def _cmd_accesses_file(cmd: str, keywords: List[str]) -> bool:
    """Check if a command line accesses a file matching keywords."""
    cmd_lower = cmd.lower()
    return any(kw in cmd_lower for kw in keywords)


def _parse_netstat_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single 'ss -tulnp' or 'netstat -tulnp' line."""
    line = line.strip()
    if not line:
        return None
    if "Proto" in line or "Active" in line or "Recv-Q" in line:
        return None  # header

    parts = line.split()
    if len(parts) < 4:
        return None

    # Determine format: ss vs netstat
    # ss -tulnp: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    # netstat -tulnp: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name

    local_addr = ""
    remote_addr = ""
    state = "unknown"
    proc_info = ""

    # Try to detect ss format (has Netid column like "tcp", "udp", "tcp6", "udp6")
    if parts[0] in ("tcp", "tcp6", "udp", "udp6", "unix"):
        # ss format
        if len(parts) >= 4:
            local_addr = parts[3]
        if len(parts) >= 5:
            remote_addr = parts[4]
        if len(parts) >= 6:
            state = parts[5]
        # Process info is at the end after "users:"
        if "users:" in line:
            proc_info = line.split("users:")[1].strip().strip("()")
    else:
        # netstat format
        if len(parts) >= 4:
            local_addr = parts[3]
        if len(parts) >= 5:
            remote_addr = parts[4]
        if len(parts) >= 6:
            state = parts[5]
        if len(parts) >= 7:
            proc_info = " ".join(parts[6:])

    # Normalize state
    if "LISTEN" in state or state == "LISTEN":
        state = "LISTEN"
    elif state == "0.0.0.0:*" or state == "*:*":
        state = "LISTEN"

    # Check for suspicious listeners
    suspicious = False
    critical = False

    # Common C2/tool ports
    suspicious_ports = ["4444", "1337", "1234", "5555", "6666", "6667",
                        "8080", "8443", "reverse"]
    for port in suspicious_ports:
        if port in local_addr:
            suspicious = True
            critical = True

    # Process-based suspicion
    if proc_info:
        proc_lower = proc_info.lower()
        if "nc" in proc_lower or "netcat" in proc_lower or "ncat" in proc_lower:
            suspicious = True
            critical = True
        if "reverse" in proc_lower:
            suspicious = True
            critical = True
        if "flag" in proc_lower.lower():
            suspicious = True
            critical = True

    return {
        "local_address": local_addr,
        "remote_address": remote_addr,
        "state": state,
        "process": proc_info,
        "suspicious": suspicious,
        "critical": critical,
    }


def _cron_entry_is_suspicious(entry: str) -> bool:
    """Check if a cron entry looks suspicious."""
    entry_lower = entry.lower()
    suspicious_patterns = [
        "flag", "reverse", "shell", "bash -i",
        "nc ", "netcat", "ncat", "socat",
        "python", "curl ", "wget ", "/dev/tcp",
        "msf", "metasploit", "exploit",
        "chmod 777", "chmod 4777", "setuid",
        "nohup", "&>", "2>&1",
    ]
    return any(p in entry_lower for p in suspicious_patterns)


def _cron_entry_is_critical(entry: str) -> bool:
    """Check if a cron entry is critical (likely malicious)."""
    entry_lower = entry.lower()
    critical_patterns = [
        "flag", "reverse", "shell", "nc ", "netcat",
        "bash -i", "/dev/tcp", "msf", "metasploit",
        "chmod 777", "chmod 4777", "setuid",
    ]
    return any(p in entry_lower for p in critical_patterns)
