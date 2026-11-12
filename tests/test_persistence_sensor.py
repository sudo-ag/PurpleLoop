"""investigate_persistence: window-bound baseline-diff of every account's
~/.ssh/authorized_keys, for a planted SSH-key backdoor."""
from src.executor import ToolExecutor


def _ex_returning(keys_by_account: dict, sentinel: bool = True) -> ToolExecutor:
    ex = ToolExecutor(host="mock", user="u", pwd="p")  # __init__ does not connect
    ex._stub_keys = dict(keys_by_account)
    ex._stub_sentinel = sentinel

    def fake_execute(cmd, *a, **k):
        if "date " in cmd:
            return "2026 Oct  8 22:22:16|1760000000\n"
        if "SSH_CONNECTION" in cmd:
            return "192.168.64.1 51000 192.168.64.12 22\n"
        if "authorized_keys" in cmd:
            lines = [
                f"{acct}:{line}"
                for acct, acct_lines in ex._stub_keys.items()
                for line in acct_lines
            ]
            if ex._stub_sentinel:
                lines.append("PL_OK")
            return "\n".join(lines)
        return ""

    ex.execute = fake_execute  # type: ignore[method-assign]
    ex._stub_set_keys = lambda keys: setattr(ex, "_stub_keys", dict(keys))
    return ex


def test_empty_baseline_everywhere_is_clean_not_unavailable():
    # No account has any authorized_keys content -- a common, valid baseline
    # (the defender logs in by password, not key). Must read as CLEAN, never
    # as a failed/unavailable baseline.
    ex = _ex_returning(keys_by_account={})
    ex.mark_analysis_window()
    assert ex._authorized_keys_baseline == set()
    r = ex.investigate_persistence()
    assert r["new_keys"] == []
    assert r["flag_access_detected"] is False and r["assessment"] == "CLEAN"
    assert r.get("baseline_unavailable") is not True


def test_new_key_on_an_account_is_a_breach():
    ex = _ex_returning(keys_by_account={"lando_calrissian": ["ssh-ed25519 AAAA legit"]})
    ex.mark_analysis_window()
    ex._stub_set_keys({
        "lando_calrissian": ["ssh-ed25519 AAAA legit", "ssh-ed25519 BBBB planted"],
    })
    r = ex.investigate_persistence()
    assert r["new_keys"] == ["lando_calrissian:ssh-ed25519 BBBB planted"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_unchanged_preexisting_key_never_flags():
    ex = _ex_returning(keys_by_account={"root": ["ssh-ed25519 AAAA legit"]})
    ex.mark_analysis_window()
    r1 = ex.investigate_persistence()
    r2 = ex.investigate_persistence()
    assert r1["new_keys"] == [] and r1["assessment"] == "CLEAN"
    assert r2["new_keys"] == [] and r2["assessment"] == "CLEAN"


def test_new_key_attributed_to_right_account_only():
    ex = _ex_returning(keys_by_account={
        "root": ["ssh-ed25519 AAAA root-key"],
        "lando_calrissian": ["ssh-ed25519 BBBB user-key"],
    })
    ex.mark_analysis_window()
    ex._stub_set_keys({
        "root": ["ssh-ed25519 AAAA root-key", "ssh-ed25519 CCCC planted"],
        "lando_calrissian": ["ssh-ed25519 BBBB user-key"],  # untouched
    })
    r = ex.investigate_persistence()
    assert r["new_keys"] == ["root:ssh-ed25519 CCCC planted"]


def test_missing_sentinel_is_baseline_unavailable():
    # Simulates a failed read (e.g. sudo denied) -- the command ran but never
    # reached its own trailing marker.
    ex = _ex_returning(keys_by_account={}, sentinel=False)
    ex.mark_analysis_window()
    assert ex._list_authorized_keys() is None
    assert ex._authorized_keys_baseline is None
    r = ex.investigate_persistence()
    assert r["baseline_unavailable"] is True
    assert r["flag_access_detected"] is False
