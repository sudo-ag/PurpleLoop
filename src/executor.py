import paramiko
import logging
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ToolExecutor:
    """
    The SSH Bridge for executing commands on a target host.
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

    def execute(self, command: str) -> str:
        """
        Executes a command on the target host and returns the output.

        Args:
            command: The shell command to execute.

        Returns:
            The stdout of the command.

        Raises:
            ValueError: If the command contains forbidden keywords.
            Exception: For SSH or execution errors.
        """
        # Guardrails
        for keyword in self.FORBIDDEN_KEYWORDS:
            if keyword in command:
                logger.warning(f"Blocked forbidden command: {command}")
                raise ValueError(f"Forbidden command: {keyword} detected.")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                username=self.user,
                password=self.pwd,
                timeout=self.timeout
            )

            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)

            # Read output
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')

            if error and not output:
                logger.error(f"Command execution error: {error}")
                return error

            return output
        except Exception as e:
            logger.exception(f"SSH execution failed: {e}")
            raise e
        finally:
            client.close()
