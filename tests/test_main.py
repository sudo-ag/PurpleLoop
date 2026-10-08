import main


def test_dashboard_disabled_by_default(monkeypatch):
    monkeypatch.delenv("DISABLE_DASHBOARD", raising=False)
    monkeypatch.delenv("ENABLE_DASHBOARD", raising=False)

    assert main.dashboard_enabled() is False


def test_dashboard_can_be_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_DASHBOARD", "1")

    assert main.dashboard_enabled() is True
