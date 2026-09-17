import pytest
from unittest.mock import MagicMock, patch
from src.executor import ToolExecutor

def test_execute_simple_command():
    # Mock paramiko.SSHClient
    with patch('paramiko.SSHClient') as mock_ssh:
        mock_client = MagicMock()
        mock_ssh.return_value = mock_client

        # Mock the execute process
        mock_stdout = MagicMock()
        # Use a lambda or a real function to avoid MagicMock's automatic return values
        mock_stdout.read.return_value = b"bash\n"

        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        executor = ToolExecutor(host="localhost", user="testuser", pwd="testpassword")
        result = executor.execute("echo bash")

        assert "bash" in result

def test_execute_forbidden_command():
    with patch('paramiko.SSHClient') as mock_ssh:
        executor = ToolExecutor(host="localhost", user="testuser", pwd="testpassword")

        # This should be blocked by guardrails
        with pytest.raises(ValueError, match="Forbidden command"):
            executor.execute("rm -rf /")
