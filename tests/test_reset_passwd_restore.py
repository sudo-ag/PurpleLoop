from types import SimpleNamespace
from unittest.mock import MagicMock

from src.arena import scripted_reset


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


def test_scripted_reset_restore_is_a_safe_no_op_when_nothing_to_restore():
    # No real branching happens on the Python side (the condition is evaluated
    # remotely by the shell one-liner), so this call must never raise even
    # when there's nothing rogue to clean up.
    blue = MagicMock()
    red = SimpleNamespace(jump_host=None)
    out = scripted_reset(blue, red, episode=5)
    assert out["episode"] == 5
