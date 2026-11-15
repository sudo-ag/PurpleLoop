"""investigate_escalation_paths: per-category status, caching, fail-safe, cap."""
from src.executor import ToolExecutor

END = "__PL_END__"  # the sensor appends this to a command to prove it ran


def _ex(outputs):
    """Executor whose execute() returns the first output whose key is a substring
    of the command; otherwise '__PL_END__' (ran, nothing found => clean)."""
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    ex.execute_calls = []

    def fake(cmd, *a, **k):
        ex.execute_calls.append(cmd)
        for key, val in outputs.items():
            if key in cmd:
                return val
        return END
    ex.execute = fake  # type: ignore[method-assign]
    return ex


def test_unreadable_category_is_unavailable_not_clean():
    ex = _ex({"dpkg -V": ""})  # no end-sentinel => the command did not complete
    res = ex.investigate_escalation_paths()
    assert res["categories"]["package_integrity"]["status"] == "unavailable"


def test_flagged_suid_appears_in_findings():
    ex = _ex({"4000": "/opt/weird/backdoor\n" + END, "dpkg -S": END})  # unowned suid
    res = ex.investigate_escalation_paths()
    assert any(f["category"] == "suid" for f in res["findings"])
    assert res["assessment"] == "FINDINGS"


def test_clean_host_assesses_clean():
    ex = _ex({})  # every category returns the bare sentinel => clean
    res = ex.investigate_escalation_paths()
    assert res["assessment"] == "CLEAN"


def test_result_is_cached_within_episode():
    ex = _ex({})
    ex.investigate_escalation_paths()
    n = len(ex.execute_calls)
    ex.investigate_escalation_paths()
    assert len(ex.execute_calls) == n  # second call ran no new commands


def test_mark_analysis_window_clears_the_cache():
    ex = _ex({})
    ex.investigate_escalation_paths()
    assert ex._escalation_cache is not None
    ex.mark_analysis_window()  # per-episode reset hook
    assert ex._escalation_cache is None


def test_findings_are_capped():
    many = "\n".join(f"/opt/w/f{i}" for i in range(300)) + "\n" + END
    ex = _ex({"0002": many})
    res = ex.investigate_escalation_paths()
    assert len(res["findings"]) <= 100
