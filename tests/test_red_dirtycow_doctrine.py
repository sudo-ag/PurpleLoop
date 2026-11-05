from src.agents import RedAgent
from src.mock_executor import MockExecutor


def test_redagent_earned_prompt_includes_dirtycow_doctrine():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=True)
    prompt = red.system_prompt
    # Discovery, not a seeded fact: red must check the kernel itself.
    assert "uname -r" in prompt
    # Dirty COW tradecraft steps, each a separate per-call SSH command.
    assert "/tmp/dc.c" in prompt
    assert "gcc -pthread /tmp/dc.c -o /tmp/dc" in prompt
    assert "su firefart" in prompt
    assert "cat /root/flag.txt" in prompt
