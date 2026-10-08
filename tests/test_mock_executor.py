from src.mock_executor import MockExecutor


def test_find_flag_returns_usable_path():
    executor = MockExecutor()

    result = executor.execute("find / -maxdepth 4 -name flag.txt 2>/dev/null")

    assert "/root/flag.txt" in result


def test_investigate_logs_reports_confirmed_flag_breach():
    executor = MockExecutor()

    result = executor.investigate_logs()

    assert result["flag_access_detected"] is True
    assert result["critical_events"] == 1
    assert result["assessment"] == "BREACH"
    assert "/root/flag.txt" in result["summary"]
