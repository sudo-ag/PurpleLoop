"""investigate_privileged_accounts: window-bound rogue uid-0 detector."""
from src.executor import ToolExecutor

PASSWD_CLEAN = "root:x:0:0:root:/root:/bin/bash\nboba_fett:x:1121:100::/home/boba:/bin/bash\n"
PASSWD_ROGUE = PASSWD_CLEAN + "firefart:x:0:0:pwned:/root:/bin/bash\n"
# Dirty COW overwrites the root line in place: root vanishes, firefart takes uid 0.
PASSWD_OVERWRITTEN = "firefart:x:0:0:pwned:/root:/bin/bash\nboba_fett:x:1121:100::/home/boba:/bin/bash\n"


def _ex_returning(passwd: str) -> ToolExecutor:
    ex = ToolExecutor(host="mock", user="u", pwd="p", dojo_exploit_ok=True)  # __init__ does not connect
    ex.execute = lambda cmd, *a, **k: passwd  # type: ignore[method-assign]
    return ex


def test_only_root_uid0_is_clean():
    ex = _ex_returning(PASSWD_CLEAN); ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == [] and r["flag_access_detected"] is False


def test_new_uid0_is_a_breach():
    ex = _ex_returning(PASSWD_ROGUE); ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == ["firefart"]
    assert r["suspicious_users"] == ["firefart"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_root_replaced_by_rogue_is_a_breach():
    # Dirty COW OVERWRITES the root line: root is absent from a valid read, yet
    # this must still be flagged (not silently reported clean/unavailable).
    ex = _ex_returning(PASSWD_OVERWRITTEN); ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == ["firefart"]
    assert r["suspicious_users"] == ["firefart"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_preexisting_uid0_not_credited():
    ex = _ex_returning(PASSWD_ROGUE); ex._uid0_baseline = {"root", "firefart"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == [] and r["flag_access_detected"] is False


def test_non_dojo_mark_window_does_not_read_passwd():
    from unittest.mock import MagicMock
    ex = ToolExecutor(host="mock", user="u", pwd="p", dojo_exploit_ok=False)

    def fake_execute(cmd, *a, **k):
        assert "passwd" not in cmd, "passwd read must be gated on dojo_exploit_ok"
        if "date" in cmd:
            return "2026 Oct  8 22:22:16|1760000000\n"
        return "192.168.64.1 51000 192.168.64.12 22\n"

    ex.execute = MagicMock(side_effect=fake_execute)
    ex.mark_analysis_window()  # must not raise
    assert ex._uid0_baseline is None


def test_non_dojo_real_guard_blocks_passwd():
    import pytest
    ex = ToolExecutor(host="mock", user="u", pwd="p", dojo_exploit_ok=False)
    with pytest.raises(ValueError):
        ex._check_forbidden("cat /etc/passwd", "remote")


def test_no_baseline_is_clean_and_flagged_unavailable():
    ex = _ex_returning(PASSWD_ROGUE)
    r = ex.investigate_privileged_accounts()
    assert r["assessment"] == "CLEAN" and r["baseline_unavailable"] is True
    assert r["flag_access_detected"] is False


def test_live_read_without_root_is_clean():
    ex = _ex_returning("garbage\n"); ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["assessment"] == "CLEAN" and r["rogue_accounts"] == []
