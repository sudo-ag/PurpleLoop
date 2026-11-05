import re

from src.agents import RedAgent
from src.mock_executor import MockExecutor


def _earned_prompt() -> str:
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=True)
    return red.system_prompt


def test_redagent_earned_prompt_includes_dirtycow_doctrine():
    prompt = _earned_prompt()
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
    # Must back up the original line BEFORE overwriting it in place — a real,
    # on-disk copy, not just a transcript print (Important 3). No sudo: this
    # whole doctrine is the fallback for an account WITHOUT sudo, so a `sudo
    # cp` would fail or hang on a password prompt at the safety step itself;
    # /etc/passwd is world-readable so a plain cp needs no privilege.
    assert "grep '^root:' /etc/passwd" in prompt
    assert "cp /etc/passwd /tmp/passwd.bak" in prompt
    assert "sudo cp /etc/passwd /tmp/passwd.bak" not in prompt
    # The corrected, length-matched overwrite content (the bug this round fixed:
    # the prior doctrine's replacement line was longer than the original and
    # overran into the next line).
    assert "firefart::0:0:p:/root:/bin/bash" in prompt
    assert "firefart::0:0:pwned:/root:/bin/bash" not in prompt
    # Red must MEASURE its target line's length, not trust a hardcoded byte
    # count as a fact about the box (Important 4: no-seeding rule).
    assert "wc -c" in prompt
    assert "NOT a fact about your box" in prompt


def test_dirtycow_replacement_line_in_doctrine_is_byte_length_matched():
    # Regression test for the exact bug that triggered this fix round: Dirty
    # COW overwrites in place and cannot grow the file, so the replacement
    # passwd line must be EXACTLY as long as the line it overwrites, trailing
    # newline included, or it corrupts the next line's leading bytes.
    #
    # Pulls both strings OUT OF THE SHIPPED DOCTRINE TEXT (not copies living
    # only in this test file), so a future edit that reintroduces a length
    # mismatch in src/agents.py fails this test even if nobody touches these
    # literals.
    prompt = _earned_prompt()
    orig_m = re.search(r"\(`(root:x:0:0:root:/root:/bin/bash\\n)`\)", prompt)
    repl_m = re.search(r"\$'(firefart[^']*)'", prompt)
    assert orig_m and repl_m, "could not locate the worked example in the doctrine text"
    # The doctrine writes a literal two-char `\n` escape (for bash ANSI-C
    # quoting to turn into a real newline byte on the target); convert it to
    # an actual newline here to measure what Dirty COW will actually write.
    original = orig_m.group(1).replace("\\n", "\n")
    replacement = repl_m.group(1).replace("\\n", "\n")
    assert len(original) == len(replacement)


def test_non_earned_redagent_has_no_dirtycow_doctrine():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest", earned=False)
    prompt = red.system_prompt
    assert "/tmp/dc.c" not in prompt
    assert "Dirty COW" not in prompt
