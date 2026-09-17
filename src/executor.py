import paramiko
import logging
import socket
import time
import subprocess
from typing import List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ToolExecutor:
    """
    The SSH Bridge for executing commands on a target host.
    Now supports persistent connections to reduce overhead.
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

    def __init__(self, host: str, user: str, pwd: str, timeout: int = 10):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None

    def connect(self):
        """Establishes a persistent SSH connection."""
        if self.client:
            return

        logger.info(f"Connecting to {self.host}...")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                hostname=self.host,
                username=self.user,
                password=self.pwd,
                timeout=self.timeout
            )
            logger.info("SSH connection established.")
        except Exception as e:
            self.client = None
            logger.exception(f"Failed to connect to {self.host}: {e}")
            raise e

    def disconnect(self):
        """Closes the persistent SSH connection."""
        if self.client:
            self.client.close()
            self.client = None
            logger.info("SSH connection closed.")

    def execute_remote(self, command: str) -> str:
        """
        Executes a command on the target host via persistent SSH and returns the output.
        """
        for keyword in self.FORBIDDEN_KEYWORDS:
            if keyword in command:
                logger.warning(f"Blocked forbidden remote command: {command}")
                raise ValueError(f"Forbidden command: {keyword} detected.")

        if not self.client:
            self.connect()

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)

            output = ""
            try:
                while True:
                    if stdout.channel.recv_ready():
                        chunk = stdout.read(1024).decode('utf-8')
                        if not chunk:
                            break
                        output += chunk

                    if stdout.channel.exit_status_ready():
                        output += stdout.read().decode('utf-8')
                        break

                    time.sleep(0.1)
            except socket.timeout:
                return f"Error: Remote command timed out after {self.timeout} seconds."
            except Exception as e:
                return f"Error reading remote output: {str(e)}"

            error = stderr.read().decode('utf-8')
            if error and not output:
                logger.error(f"Remote command execution error: {error}")
                return error

            return output if output else "Remote command executed successfully (no output)."
        except Exception as e:
            logger.exception(f"SSH execution failed: {e}")
            # If the connection dropped, try to reconnect once
            self.client = None
            raise e

    def execute_local(self, command: str) -> str:
        """
        Executes a command on the local machine (e.g., Kali host) and returns the output.
        """
        for keyword in self.FORBIDDEN_KEYWORDS:
            if keyword in command:
                logger.warning(f"Blocked forbidden local command: {command}")
                raise ValueError(f"Forbidden local command: {keyword} detected.")

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

