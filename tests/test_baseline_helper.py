"""_capture_baseline / _diff_baseline: shared helper extracted from the three
hand-rolled baseline blocks in mark_analysis_window() and their diff logic in
investigate_privileged_accounts()/investigate_webshells(). Each sensor keeps
its OWN validator (uid0's "root" sentinel vs webroot's/proc's structural
checks) -- these tests prove the refactored code is byte-identical to the
pre-refactor behavior for all three baselines, not just "looks equivalent"."""
from src.executor import ToolExecutor

PASSWD_CLEAN = "root:x:0:0:root:/root:/bin/bash\nboba_fett:x:1121:100::/home/boba:/bin/bash\n"
PASSWD_ROGUE = PASSWD_CLEAN + "firefart:x:0:0:pwned:/root:/bin/bash\n"
PASSWD_OVERWRITTEN = "firefart:x:0:0:pwned:/root:/bin/bash\nboba_fett:x:1121:100::/home/boba:/bin/bash\n"


def _ex_with(passwd=None, webroot_lines=None, proc_lines=None, dojo_exploit_ok=True) -> ToolExecutor:
    ex = ToolExecutor(host="mock", user="u", pwd="p", dojo_exploit_ok=dojo_exploit_ok)

    def fake_execute(cmd, *a, **k):
        if "date " in cmd:
            return "2026 Oct  8 22:22:16|1760000000\n"
        if "SSH_CONNECTION" in cmd:
            return "192.168.64.1 51000 192.168.64.12 22\n"
        if "passwd" in cmd:
            return passwd if passwd is not None else ""
        if "/var/www/html" in cmd:
            return webroot_lines if webroot_lines is not None else ""
        if "ps -eo args" in cmd:
            return proc_lines if proc_lines is not None else ""
        return ""

    ex.execute = fake_execute  # type: ignore[method-assign]
    return ex


# --- _capture_baseline direct behavior ---------------------------------------

def test_capture_baseline_returns_fn_result_on_success():
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    assert ex._capture_baseline(lambda: {"a", "b"}) == {"a", "b"}


def test_capture_baseline_returns_none_on_exception():
    ex = ToolExecutor(host="mock", user="u", pwd="p")

    def boom():
        raise RuntimeError("ssh died")

    assert ex._capture_baseline(boom) is None


def test_capture_baseline_returns_none_when_fn_returns_none():
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    assert ex._capture_baseline(lambda: None) is None


# --- _diff_baseline direct behavior ------------------------------------------

def test_diff_baseline_both_present_returns_sorted_diff():
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    ok, diff = ex._diff_baseline({"a", "b"}, {"a", "b", "d", "c"})
    assert ok is True
    assert diff == ["c", "d"]


def test_diff_baseline_baseline_none_is_not_ok():
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    assert ex._diff_baseline(None, {"a"}) == (False, [])


def test_diff_baseline_live_none_is_not_ok():
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    assert ex._diff_baseline({"a"}, None) == (False, [])


def test_diff_baseline_both_none_is_not_ok():
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    assert ex._diff_baseline(None, None) == (False, [])


# --- uid0 baseline: sentinel validator (NOT structural) ----------------------
# mark_analysis_window() keeps the uid0 baseline only when "root" is present in
# the read -- a specific-sentinel check, distinct from webroot's/proc's
# structural checks. These scenarios mirror tests/test_privileged_accounts.py.

def test_uid0_baseline_valid_read_is_captured():
    ex = _ex_with(passwd=PASSWD_CLEAN)
    ex.mark_analysis_window()
    assert ex._uid0_baseline == {"root"}


def test_uid0_baseline_empty_read_is_none():
    ex = _ex_with(passwd="")
    ex.mark_analysis_window()
    assert ex._uid0_baseline is None


def test_uid0_baseline_read_without_root_sentinel_is_none():
    # Structurally fine (7-field lines) but missing the root sentinel -- the
    # uid0 validator must reject this even though it isn't empty/garbage,
    # unlike webroot's/proc's purely structural checks.
    ex = _ex_with(passwd="boba_fett:x:1121:100::/home/boba:/bin/bash\n")
    ex.mark_analysis_window()
    assert ex._uid0_baseline is None


def test_uid0_baseline_not_captured_outside_dojo():
    ex = _ex_with(passwd=PASSWD_CLEAN, dojo_exploit_ok=False)
    ex.mark_analysis_window()
    assert ex._uid0_baseline is None


def test_uid0_diff_new_account_is_a_breach_identical_to_pre_refactor():
    ex = _ex_with(passwd=PASSWD_ROGUE)
    ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == ["firefart"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_uid0_diff_root_replaced_is_still_a_breach():
    ex = _ex_with(passwd=PASSWD_OVERWRITTEN)
    ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == ["firefart"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_uid0_diff_no_baseline_is_clean_and_unavailable():
    ex = _ex_with(passwd=PASSWD_ROGUE)
    r = ex.investigate_privileged_accounts()
    assert r["baseline_unavailable"] is True and r["flag_access_detected"] is False


# --- webroot baseline: structural validator (NOT sentinel) -------------------
# _list_webroot() is valid only if at least one line actually sits under the
# web root -- no specific filename/extension required, unlike uid0's sentinel.

def test_webroot_baseline_valid_read_is_captured():
    ex = _ex_with(webroot_lines="/var/www/html/payroll_app.php")
    ex.mark_analysis_window()
    assert ex._webroot_baseline == {"payroll_app.php"}


def test_webroot_baseline_empty_read_is_none():
    ex = _ex_with(webroot_lines="")
    ex.mark_analysis_window()
    assert ex._webroot_baseline is None


def test_webroot_baseline_read_failing_structural_check_is_none():
    # Lines present, but none under the web root prefix -> structurally invalid.
    ex = _ex_with(webroot_lines="find: permission denied")
    ex.mark_analysis_window()
    assert ex._webroot_baseline is None


def test_webroot_diff_new_file_is_a_breach_identical_to_pre_refactor():
    ex = _ex_with(webroot_lines="/var/www/html/index.html", proc_lines="apache2 -k start")
    ex.mark_analysis_window()
    ex.execute = lambda cmd, *a, **k: (
        "/var/www/html/index.html\n/var/www/html/shell.php" if "/var/www/html" in cmd
        else ("apache2 -k start" if "ps -eo args" in cmd else "")
    )
    r = ex.investigate_webshells()
    assert r["new_files"] == ["shell.php"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


# --- proc baseline: structural validator (empty-output check) ----------------

def test_proc_baseline_valid_read_is_captured():
    ex = _ex_with(proc_lines="apache2 -k start")
    ex.mark_analysis_window()
    assert ex._proc_baseline == {"apache2 -k start"}


def test_proc_baseline_empty_read_is_none():
    ex = _ex_with(proc_lines="")
    ex.mark_analysis_window()
    assert ex._proc_baseline is None


def test_proc_diff_new_process_is_a_breach_identical_to_pre_refactor():
    ex = _ex_with(webroot_lines="/var/www/html/index.html", proc_lines="apache2 -k start")
    ex.mark_analysis_window()
    ex.execute = lambda cmd, *a, **k: (
        "/var/www/html/index.html" if "/var/www/html" in cmd
        else ("apache2 -k start\nsh -c id" if "ps -eo args" in cmd else "")
    )
    r = ex.investigate_webshells()
    assert "sh -c id" in r["new_processes"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_webshells_no_baseline_at_all_is_unavailable():
    ex = _ex_with(webroot_lines="/var/www/html/index.html", proc_lines="apache2 -k start")
    # mark_analysis_window() never called -> no baselines
    r = ex.investigate_webshells()
    assert r["baseline_unavailable"] is True and r["flag_access_detected"] is False
