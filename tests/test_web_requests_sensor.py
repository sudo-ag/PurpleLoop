"""investigate_web_requests: Apache access-log burst attribution.

Attribution only — this sensor must NEVER set flag_access_detected. It flags
the burst-of-requests fingerprint of an automated SQLi tool (sqlmap) hitting
the payroll app, but a burst alone is not proof of compromise.
"""
from src.executor import ToolExecutor


# Real captured access.log lines (combined format), verified live against the
# target box: one GET followed by three rapid POSTs, all within ~1 second.
BURST_LINES = "\n".join([
    '192.168.64.11 - - [06/Nov/2026:05:08:01 +0000] "GET /payroll_app.php HTTP/1.1" 200 460 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"',
    '192.168.64.11 - - [06/Nov/2026:05:08:02 +0000] "POST /payroll_app.php HTTP/1.1" 200 390 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"',
    '192.168.64.11 - - [06/Nov/2026:05:08:02 +0000] "POST /payroll_app.php HTTP/1.1" 200 177 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"',
    '192.168.64.11 - - [06/Nov/2026:05:08:02 +0000] "POST /payroll_app.php HTTP/1.1" 200 177 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"',
])

ISOLATED_LINE = (
    '192.168.64.11 - - [06/Nov/2026:05:08:01 +0000] "GET /payroll_app.php HTTP/1.1" '
    '200 460 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 '
    '(KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"'
)

# Window start used by tests: anything at/after this epoch is "in window".
WINDOW_START_EPOCH = 1793941680  # 2026-11-06T05:08:00+00:00

OUTSIDE_WINDOW_LINE = (
    '192.168.64.11 - - [06/Nov/2026:05:07:00 +0000] "GET /payroll_app.php HTTP/1.1" '
    '200 460 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ja-JP) AppleWebKit/533.20.25 '
    '(KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"'
)


def _executor() -> ToolExecutor:
    executor = ToolExecutor(host="192.168.64.10", user="vagrant", pwd="vagrant", timeout=30)
    executor.control_source_ip = "192.168.64.1"
    executor.analysis_since_epoch = WINDOW_START_EPOCH
    return executor


def test_burst_from_foreign_ip_is_detected():
    executor = _executor()
    executor.execute = lambda cmd, *a, **k: BURST_LINES
    result = executor.investigate_web_requests()
    assert len(result["bursts"]) == 1
    burst = result["bursts"][0]
    assert burst["source_ip"] == "192.168.64.11"
    assert burst["request_count"] >= 3
    assert result["foreign_ips"] == ["192.168.64.11"]


def test_isolated_single_request_is_not_a_burst():
    executor = _executor()
    executor.execute = lambda cmd, *a, **k: ISOLATED_LINE
    result = executor.investigate_web_requests()
    assert result["bursts"] == []
    assert result["foreign_ips"] == []


def test_burst_from_control_source_ip_is_self_filtered():
    # Documents the invariant: even if blue's own management IP somehow
    # produced this exact burst shape, it must never be attributed as a
    # finding against itself. Mirrors investigate_ftp_sessions's self-filter.
    executor = _executor()
    executor.control_source_ip = "192.168.64.11"
    executor.execute = lambda cmd, *a, **k: BURST_LINES
    result = executor.investigate_web_requests()
    assert result["bursts"] == []
    assert result["foreign_ips"] == []


def test_request_outside_window_is_excluded():
    executor = _executor()
    executor.execute = lambda cmd, *a, **k: OUTSIDE_WINDOW_LINE
    result = executor.investigate_web_requests()
    assert result["bursts"] == []
    assert result["foreign_ips"] == []


def test_never_sets_flag_access_detected():
    executor = _executor()
    executor.execute = lambda cmd, *a, **k: BURST_LINES
    result = executor.investigate_web_requests()
    assert "flag_access_detected" not in result
