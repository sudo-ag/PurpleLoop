import pytest
from src.executor import ToolExecutor

DOJO_ONLY = ["echo x >> /etc/passwd", "cat /etc/shadow"]
ALWAYS_BLOCKED = ["rm -rf /", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/x", "shutdown now", "reboot"]

def test_passwd_blocked_when_flag_off():
    ex = ToolExecutor(host="mock", dojo_exploit_ok=False)
    for cmd in DOJO_ONLY:
        with pytest.raises(ValueError):
            ex._check_forbidden(cmd, "remote")

def test_passwd_allowed_when_flag_on():
    ex = ToolExecutor(host="mock", dojo_exploit_ok=True)
    for cmd in DOJO_ONLY:
        ex._check_forbidden(cmd, "remote")  # no raise

def test_destructive_blocked_even_when_flag_on():
    ex = ToolExecutor(host="mock", dojo_exploit_ok=True)
    for cmd in ALWAYS_BLOCKED:
        with pytest.raises(ValueError):
            ex._check_forbidden(cmd, "remote")

def test_default_is_off():
    assert ToolExecutor(host="mock").dojo_exploit_ok is False
