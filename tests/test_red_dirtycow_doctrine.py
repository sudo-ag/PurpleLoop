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
    # Must back up the original line BEFORE overwriting it in place.
    assert "grep '^root:' /etc/passwd" in prompt
    # The corrected, length-matched overwrite content (the bug this round fixed:
    # the prior doctrine's replacement line was longer than the original and
    # overran into the next line).
    assert "firefart::0:0:p:/root:/bin/bash" in prompt
    assert "firefart::0:0:pwned:/root:/bin/bash" not in prompt


def test_dirtycow_replacement_line_is_byte_length_matched_to_original():
    # Regression test for the exact bug that triggered this fix round: Dirty
    # COW overwrites in place and cannot grow the file, so the replacement
    # passwd line must be EXACTLY as long as the line it overwrites, trailing
    # newline included, or it corrupts the next line's leading bytes.
    original = "root:x:0:0:root:/root:/bin/bash\n"
    replacement = "firefart::0:0:p:/root:/bin/bash\n"
    assert len(original) == len(replacement)


def test_non_earned_redagent_has_no_dirtycow_doctrine():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=False)
    prompt = red.system_prompt
    assert "/tmp/dc.c" not in prompt
    assert "Dirty COW" not in prompt
