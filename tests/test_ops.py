from src.ops import _winner_from_state
from src.ops import start_simulation


def test_winner_from_state_handles_report_text():
    assert _winner_from_state("# PurpleLoop Battle Report") is None


def test_start_simulation_disables_dashboard_by_default(monkeypatch, tmp_path):
    popen_calls = []

    class FakeProcess:
        pid = 1234

    def fake_popen(cmd, cwd, env, stdout, stderr, start_new_session):
        popen_calls.append({
            "cmd": cmd,
            "cwd": cwd,
            "env": env,
            "stdout": stdout,
            "stderr": stderr,
            "start_new_session": start_new_session,
        })
        return FakeProcess()

    def fail_session():
        raise AssertionError("dashboard state should not be polled by default")

    monkeypatch.setattr("src.ops.REPO", tmp_path)
    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("src.ops._session", fail_session)

    info = start_simulation(host="mock")

    assert info["dashboard_enabled"] is False
    assert popen_calls[0]["env"]["DISABLE_DASHBOARD"] == "1"
