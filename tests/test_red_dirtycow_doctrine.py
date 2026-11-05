from src.agents import RedAgent
from src.mock_executor import MockExecutor


def test_redagent_earned_prompt_includes_dirtycow_doctrine():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=True)
    prompt = red.system_prompt
    # Discovery, not a seeded fact: red must check the kernel itself.
    assert "uname -r" in prompt
    # Dirty COW tradecraft, unique to this doctrine block.
    assert "/tmp/dc.c" in prompt
    assert "gcc -pthread /tmp/dc.c -o /tmp/dc" in prompt
    # T3 is credited on VERIFIED uid=0 creation, not su + flag read (no tty
    # over SSH, so su can't work here).
    assert "grep '^firefart:' /etc/passwd" in prompt
    assert "id firefart" in prompt
    assert "su firefart" not in prompt
    assert "cat /root/flag.txt" not in prompt.split("KERNEL EXPLOIT")[-1]


def test_non_earned_redagent_has_no_dirtycow_doctrine():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=False)
    prompt = red.system_prompt
    assert "/tmp/dc.c" not in prompt
    assert "Dirty COW" not in prompt
