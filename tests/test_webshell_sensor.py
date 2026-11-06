"""investigate_webshells: window-bound baseline-diff of the web root + process
tree, for a planted webshell (ProFTPD mod_copy arbitrary-file-write RCE)."""
from src.executor import ToolExecutor


def _ex_returning(webroot_files, procs) -> ToolExecutor:
    ex = ToolExecutor(host="mock", user="u", pwd="p")  # __init__ does not connect
    ex._stub_files = list(webroot_files)
    ex._stub_proc_list = list(procs)

    def fake_execute(cmd, *a, **k):
        if "date " in cmd:
            return "2026 Oct  8 22:22:16|1760000000\n"
        if "SSH_CONNECTION" in cmd:
            return "192.168.64.1 51000 192.168.64.12 22\n"
        if "/var/www/html" in cmd:
            return "\n".join(f"/var/www/html/{f}" for f in ex._stub_files)
        if "ps -eo args" in cmd:
            return "\n".join(ex._stub_proc_list)
        return ""

    ex.execute = fake_execute  # type: ignore[method-assign]
    ex._stub_webroot_files = lambda files: setattr(ex, "_stub_files", list(files))
    ex._stub_procs = lambda procs: setattr(ex, "_stub_proc_list", list(procs))
    return ex


def test_new_webroot_file_is_a_breach():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    ex.mark_analysis_window()  # captures baseline: {"index.html"}, {"apache2 -k start"}
    ex._stub_webroot_files(["index.html", "shell.php"])
    r = ex.investigate_webshells()
    assert r["new_files"] == ["shell.php"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_no_change_is_clean():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    ex.mark_analysis_window()
    r = ex.investigate_webshells()
    assert r["flag_access_detected"] is False and r["assessment"] == "CLEAN"


def test_unexpected_apache_child_is_a_breach():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    ex.mark_analysis_window()
    ex._stub_procs(["apache2 -k start", "sh -c id"])  # webshell-spawned child
    r = ex.investigate_webshells()
    assert "sh -c id" in r["new_processes"] and r["flag_access_detected"] is True


def test_no_baseline_is_clean_not_breach():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    # mark_analysis_window() never called -> no baseline
    r = ex.investigate_webshells()
    assert r["flag_access_detected"] is False and r.get("baseline_unavailable") is True


def test_php_only_webroot_baseline_is_captured_and_diffed():
    # Real target's /var/www/html holds exactly one file: payroll_app.php --
    # no .html, no allowlisted subdir. Baseline capture must not depend on
    # either, or this sensor is permanently blind on the actual box.
    ex = _ex_returning(webroot_files=["payroll_app.php"], procs=["apache2 -k start"])
    ex.mark_analysis_window()
    assert ex._webroot_baseline is not None
    ex._stub_webroot_files(["payroll_app.php", "shell.php"])
    r = ex.investigate_webshells()
    assert r["new_files"] == ["shell.php"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_webroot_baseline_failure_still_allows_process_diff():
    # find returns nothing at baseline time -> webroot baseline is None, but
    # the process baseline captured fine. The two signals are independent;
    # one failing must not blind the other.
    ex = _ex_returning(webroot_files=[], procs=["apache2 -k start"])
    ex.mark_analysis_window()
    assert ex._webroot_baseline is None
    assert ex._proc_baseline is not None
    ex._stub_procs(["apache2 -k start", "sh -c id"])
    r = ex.investigate_webshells()
    assert r.get("baseline_unavailable") is not True
    assert r["webroot_unavailable"] is True
    assert "sh -c id" in r["new_processes"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_proc_baseline_failure_still_allows_webroot_diff():
    # ps returns nothing at baseline time -> process baseline is None, but
    # the webroot baseline captured fine.
    ex = _ex_returning(webroot_files=["index.html"], procs=[])
    ex.mark_analysis_window()
    assert ex._proc_baseline is None
    assert ex._webroot_baseline is not None
    ex._stub_webroot_files(["index.html", "shell.php"])
    r = ex.investigate_webshells()
    assert r.get("baseline_unavailable") is not True
    assert r["proc_unavailable"] is True
    assert r["new_files"] == ["shell.php"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"


def test_ssh_reconnect_with_different_pts_is_not_a_breach():
    # Blue's own control session shows up in `ps` as a transient sshd process.
    # A reconnect gets a NEW pts/pid ("sshd: user@pts/1" vs "...pts/0" at
    # baseline time) -- the noise filter must drop both, on either side of the
    # diff, by command-string pattern, not by exact match, or every reconnect
    # would false-positive a breach.
    ex = _ex_returning(
        webroot_files=["index.html"],
        procs=["apache2 -k start", "sshd: user@pts/0"],
    )
    ex.mark_analysis_window()
    ex._stub_procs(["apache2 -k start", "sshd: user@pts/1"])  # reconnected
    r = ex.investigate_webshells()
    assert "sshd: user@pts/1" not in r["new_processes"]
    assert r["new_processes"] == []
    assert r["flag_access_detected"] is False and r["assessment"] == "CLEAN"
