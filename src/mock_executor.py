import logging
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MockExecutor:
    """
    A mock executor that simulates a target box.
    """
    def __init__(self, host: str = "mock", user: str = "mock", pwd: str = "mock"):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.files = {
            "/root/flag.txt": "FLAG{MOCK_FLAG_12345}",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash",
            "/var/log/auth.log": "Oct 16 10:00:00 mock sshd[123]: Failed password for msfadmin from 10.0.0.1 port 12345 ssh2"
        }
        self.commands_run = []

    def execute(self, command: str) -> str:
        logger.info(f"Mock executing: {command}")
        self.commands_run.append(command)

        if "flag.txt" in command and ("cat" in command or "grep" in command):
            return self.files.get("/root/flag.txt", "File not found")
        if "passwd" in command and "cat" in command:
            return self.files.get("/etc/passwd", "File not found")
        if "auth.log" in command and ("cat" in command or "grep" in command):
            return self.files.get("/var/log/auth.log", "File not found")
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

        return f"Mock output for command: {command}"
