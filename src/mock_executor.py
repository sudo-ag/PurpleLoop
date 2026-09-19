import logging
from typing import Dict, List, Tuple, Any
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MockExecutor:
    """
    A mock executor that simulates a target box with structured investigation data.
    Reflects a scenario where red has already accessed the flag.
    """
    def __init__(self, host: str = "mock", user: str = "mock", pwd: str = "mock"):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.files = {
            "/root/flag.txt": "FLAG{MOCK_FLAG_12345}",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nmsfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash",
        }
        self.commands_run: List[str] = []

        # Structured investigation data — reflects red already accessing the flag
        self._processes = [
            {"pid": 1, "user": "root", "cpu": 0.0, "mem": 0.1, "command": "/sbin/init", "suspicious": False},
            {"pid": 1234, "user": "root", "cpu": 0.0, "mem": 0.0, "command": "/usr/sbin/sshd -D", "suspicious": False},
            {"pid": 5678, "user": "root", "cpu": 0.2, "mem": 0.1, "command": "cat /root/flag.txt", "suspicious": True, "reason": "Reading sensitive flag file as root"},
            {"pid": 9012, "user": "msfadmin", "cpu": 0.0, "mem": 0.0, "command": "/bin/bash", "suspicious": False},
        ]
        self._network = [
            {"proto": "tcp", "local": "0.0.0.0:22", "remote": "*:*", "state": "LISTEN", "pid": 1234, "process": "/usr/sbin/sshd -D", "suspicious": False},
            {"proto": "tcp", "local": "10.0.0.1:4444", "remote": "192.168.1.5:54321", "state": "ESTABLISHED", "pid": 5678, "process": "cat /root/flag.txt", "suspicious": False},
        ]
        self._auth_log_lines = [
            {"timestamp": "2026-09-17T10:15:00Z", "source": "sshd", "event": "accepted_password", "user": "msfadmin", "source_ip": "192.168.1.5", "details": "Accepted password for msfadmin from 192.168.1.5 port 52341 ssh2", "suspicious": False},
            {"timestamp": "2026-09-17T10:15:05Z", "source": "sudo", "event": "sudo_command", "user": "msfadmin", "target_user": "root", "command": "/bin/bash", "details": "msfadmin : TTY=pts/0 ; PWD=/home/msfadmin ; USER=root ; COMMAND=/bin/bash", "suspicious": False},
            {"timestamp": "2026-09-17T10:16:00Z", "source": "sudo", "event": "sudo_command", "user": "msfadmin", "target_user": "root", "command": "/usr/bin/cat /root/flag.txt", "details": "msfadmin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /root/flag.txt", "suspicious": True, "reason": "User msfadmin executed cat on sensitive flag file as root via sudo"},
        ]
        self._file_access_events = [
            {"timestamp": "2026-09-17T10:16:00Z", "user": "msfadmin", "uid": 1000, "file": "/root/flag.txt", "action": "read", "command": "/usr/bin/cat", "via": "sudo", "suspicious": True, "reason": "Sensitive flag file read via sudo by non-root user"},
        ]

    def connect(self):
        """No-op for the mock executor — no persistent connection."""
        logger.info("MockExecutor.connect: no-op")

    def disconnect(self):
        """No-op for the mock executor."""
        logger.info("MockExecutor.disconnect: no-op")

    def execute(self, command: str) -> str:
        logger.info(f"Mock executing: {command}")
        self.commands_run.append(command)

        if "flag.txt" in command and ("cat" in command or "grep" in command):
            return self.files.get("/root/flag.txt", "File not found")
        if "passwd" in command and "cat" in command:
            return self.files.get("/etc/passwd", "File not found")
        if "auth.log" in command and ("cat" in command or "grep" in command):
            return "Oct 16 10:00:00 mock sshd[123]: Failed password for msfadmin from 10.0.0.1 port 12345 ssh2\n" \
                   "Oct 16 10:00:05 mock sshd[124]: Failed password for msfadmin from 10.0.0.1 port 12345 ssh2\n" \
                   "Oct 16 10:00:10 mock sshd[125]: Accepted password for msfadmin from 10.0.0.1 port 12345 ssh2\n" \
                   "Oct 16 10:00:15 mock sudo: msfadmin : TTY=pts/0 ; PWD=/home/msfadmin ; USER=root ; COMMAND=/bin/bash\n" \
                   "Oct 16 10:00:20 mock sshd[126]: session opened for user msfadmin by (uid=0)\n" \
                   "Oct 16 10:01:00 mock sudo: msfadmin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /root/flag.txt\n" \
                   "Oct 16 10:01:05 mock sshd[126]: session closed for user msfadmin"
        if "ls /root" in command:
            return "flag.txt"
        if "whoami" in command:
            return "root"
        if "id" in command:
            return "uid=0(root) gid=0(root) groups=0(root)"
        if "uname -a" in command:
            return "Linux mock 5.4.0-generic #1 SMP Mon Jan 1 00:00:00 UTC 2024 x86_64"
        if "ps aux" in command:
            return "root 1 0.0 0.0 1234 567 /sbin/init\nroot 123 0.1 0.1 456 789 /usr/sbin/sshd\nroot 456 0.0 0.0 789 101 /usr/sbin/sshd-privsep"
        if "netstat" in command:
            return "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN"
        if "ss -tlnp" in command:
            return "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"/usr/sbin/sshd\",pid=1234,fd=3))"
        if "lastlog" in command:
            return "Username     Port     Host             Last Login\nroot         pts/0    192.168.1.5      Wed Sep 17 10:16:00 2026\nmsfadmin     pts/0    192.168.1.5      Wed Sep 17 10:15:05 2026\n"

        return f"Mock output for command: {command}"

    # ---- Blue investigation tools (structured signals) ----

    def investigate_logs(self, log_type: str = "auth") -> Dict[str, Any]:
        """Return structured auth log data from the mock auth.log."""
        logger.info(f"MockExecutor.investigate_logs: log_type={log_type}")
        if log_type not in ("auth", "syslog"):
            return {
                "tool": "investigate_logs",
                "status": "error",
                "log_type": log_type,
                "error": f"Log type '{log_type}' not supported in mock. Try 'auth'.",
            }

        suspicious = [e for e in self._auth_log_lines if e.get("suspicious")]
        failed_auths = [e for e in self._auth_log_lines if e.get("event") == "accepted_password" and e.get("source_ip")]
        sudo_events = [e for e in self._auth_log_lines if e.get("event") == "sudo_command"]
        return {
            "tool": "investigate_logs",
            "status": "success",
            "log_type": log_type,
            "timestamp": "2026-09-17T10:20:00Z",
            "total_events": len(self._auth_log_lines),
            "failed_auth_count": len(failed_auths),
            "sudo_events_count": len(sudo_events),
            "suspicious_count": len(suspicious),
            "findings": self._auth_log_lines,
            "suspicious_findings": suspicious,
            "failed_auth_events": failed_auths,
            "sudo_events": sudo_events,
            "summary": (
                f"Auth log ({len(self._auth_log_lines)} events): "
                f"{len(failed_auths)} auth events, {len(sudo_events)} sudo commands. "
                f"{len(suspicious)} suspicious: {suspicious[0]['details'] if suspicious else 'N/A'}"
            ),
        }

    def investigate_processes(self) -> Dict[str, Any]:
        logger.info("MockExecutor.investigate_processes: returning structured process data")
        suspicious = [p for p in self._processes if p.get("suspicious")]
        return {
            "tool": "investigate_processes",
            "status": "success",
            "timestamp": "2026-09-17T10:20:00Z",
            "total_processes": len(self._processes),
            "suspicious_count": len(suspicious),
            "findings": self._processes,
            "suspicious_findings": suspicious,
            "summary": (
                f"Found {len(suspicious)} suspicious process(es). "
                f"PID {suspicious[0]['pid'] if suspicious else 'N/A'}: "
                f"{suspicious[0]['command'] if suspicious else 'N/A'} — "
                f"{suspicious[0]['reason'] if suspicious else 'N/A'}"
            ),
        }

    def investigate_network(self) -> Dict[str, Any]:
        logger.info("MockExecutor.investigate_network: returning structured network data")
        suspicious = [n for n in self._network if n.get("suspicious")]
        return {
            "tool": "investigate_network",
            "status": "success",
            "timestamp": "2026-09-17T10:20:00Z",
            "total_connections": len(self._network),
            "suspicious_count": len(suspicious),
            "findings": self._network,
            "suspicious_findings": suspicious,
            "summary": (
                f"Found {len(suspicious)} suspicious connection(s)"
                if suspicious else "No suspicious network activity detected."
            ),
        }

    def investigate_file_access(self, file_path: str = "/root/flag.txt") -> Dict[str, Any]:
        logger.info(f"MockExecutor.investigate_file_access: checking {file_path}")
        matching_events = [e for e in self._file_access_events if e.get("file") == file_path]
        exists = file_path in self.files
        return {
            "tool": "investigate_file_access",
            "status": "success",
            "timestamp": "2026-09-17T10:20:00Z",
            "file_path": file_path,
            "exists": exists,
            "file_contents": self.files.get(file_path) if exists else None,
            "access_events_count": len(matching_events),
            "findings": matching_events,
            "suspicious_count": len([e for e in matching_events if e.get("suspicious")]),
            "summary": (
                f"File {file_path}: {'exists' if exists else 'not found'}. "
                f"{len(matching_events)} access event(s). "
                f"{'SENSITIVE FILE WAS ACCESSED — potential exfiltration.' if matching_events and any(e.get('suspicious') for e in matching_events) else 'No suspicious access detected.'}"
            ),
        }
