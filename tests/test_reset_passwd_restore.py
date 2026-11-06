from types import SimpleNamespace
from unittest.mock import MagicMock

from src.arena import scripted_reset
from src.executor import _is_sensitive_file_access


def test_scripted_reset_backs_up_baseline_and_conditionally_restores():
    blue = MagicMock()
    red = SimpleNamespace(jump_host=None)
    out = scripted_reset(blue, red, episode=1)
    cmds = [c.args[0] for c in blue.execute.call_args_list]
    joined = " ".join(cmds)

    # Baseline is created once (only if it doesn't already exist), but ONLY
    # after clearing any pre-existing rogue uid0 account first — otherwise a
    # leftover rogue account from an interrupted prior run gets baked into
    # the "clean" baseline forever (Important 1).
    baseline_cmd = next(
        c for c in cmds
        if "test -f /etc/passwd.purpleloop-baseline" in c
        and "cp /etc/passwd /etc/passwd.purpleloop-baseline" in c
    )
    assert "deluser" in baseline_cmd
    # Strict ordering, not just co-occurrence: deluser attempt, THEN a
    # re-check that it actually worked, THEN (only then) the cp. If deluser
    # silently fails (e.g. a held-open account), the stale re-check must
    # still block the cp rather than bake a rogue file into the baseline.
    deluser_idx = baseline_cmd.index("deluser")
    recheck_idx = baseline_cmd.index("{f=1} END{exit !f}")
    cp_idx = baseline_cmd.index("cp /etc/passwd /etc/passwd.purpleloop-baseline")
    assert deluser_idx < recheck_idx < cp_idx
    # Restore is conditional on a rogue uid0 account OR a diff from baseline,
    # not unconditional.
    assert any(
        "awk -F:" in c
        and "diff -q /etc/passwd /etc/passwd.purpleloop-baseline" in c
        and "cp /etc/passwd.purpleloop-baseline /etc/passwd" in c
        for c in cmds
    )
    assert any("passwd" in a for a in out["actions"])
    assert "/etc/passwd" in joined


def test_scripted_reset_subcommands_are_all_exempt_from_breach_detection():
    # Ties the "reset's own /etc/passwd housekeeping never scores as a
    # breach" claim to the ACTUAL commands scripted_reset emits, not a
    # hand-copied mirror of them in a test file (which could silently drift
    # from arena.py if a future edit drops the marker from one call).
    blue = MagicMock()
    red = SimpleNamespace(jump_host=None)
    scripted_reset(blue, red, episode=1)
    cmds = [c.args[0] for c in blue.execute.call_args_list]

    checked = 0
    for script in cmds:
        # Split into the same granularity sudo itself logs: one COMMAND=
        # per `sudo ...` invocation (the text sudo logs excludes the literal
        # "sudo" word itself, matching what _is_sensitive_file_access reads
        # from a real auth.log COMMAND= field).
        for part in script.split("sudo ")[1:]:
            if "/etc/passwd" not in part:
                continue
            checked += 1
            assert _is_sensitive_file_access(part) is False, part
    # Real source has 6 /etc/passwd-referencing sub-invocations across the
    # two reset commands (3 awk checks, 1 diff, 2 cp) — fail loudly if that
    # drops to 0, since an empty loop would pass vacuously.
    assert checked >= 6


def test_scripted_reset_restore_is_a_safe_no_op_when_nothing_to_restore():
    # No real branching happens on the Python side (the condition is evaluated
    # remotely by the shell one-liner), so this call must never raise even
    # when there's nothing rogue to clean up.
    blue = MagicMock()
    red = SimpleNamespace(jump_host=None)
    out = scripted_reset(blue, red, episode=5)
    assert out["episode"] == 5
