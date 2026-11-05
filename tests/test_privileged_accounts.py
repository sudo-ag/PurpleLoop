"""investigate_privileged_accounts: window-bound rogue uid-0 detector."""
from src.executor import ToolExecutor

PASSWD_CLEAN = "root:x:0:0:root:/root:/bin/bash\nboba_fett:x:1121:100::/home/boba:/bin/bash\n"
PASSWD_ROGUE = PASSWD_CLEAN + "firefart:x:0:0:pwned:/root:/bin/bash\n"


def _ex_returning(passwd: str) -> ToolExecutor:
    ex = ToolExecutor(host="mock", user="u", pwd="p")  # __init__ does not connect
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


def test_preexisting_uid0_not_credited():
    ex = _ex_returning(PASSWD_ROGUE); ex._uid0_baseline = {"root", "firefart"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == [] and r["flag_access_detected"] is False
