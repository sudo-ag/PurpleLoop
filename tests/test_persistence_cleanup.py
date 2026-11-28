"""Unconditional between-episode persistence cleanup: at episode end the
orchestrator strips every post-baseline autostart entry on blue's executor, so a
plant that outlived the episode (red win) never dirties the box for the next run."""
from unittest.mock import MagicMock, patch

from src.agents import Agent
from src.executor import ToolExecutor
from src.orchestrator import Orchestrator


def _winrm():
    return ToolExecutor(host="192.168.64.17", user="vagrant", pwd="vagrant",
                        transport="winrm", jump_host="192.168.64.11",
                        jump_user="kali", jump_pwd="kali", timeout=30)


def test_clean_all_persistence_removes_every_new_entry():
    ex = _winrm()
    ex._win_persist_baseline = {"task|\\Old"}
    live = {"task|\\Old", "task|\\Red", "startup|C:\\x\\y.lnk"}
    with patch.object(ex, "_list_win_persistence", return_value=live), \
         patch.object(ex, "_remove_win_persist_entry", return_value=(True, "PL_OK")) as rm:
        res = ex.clean_all_persistence()
    removed_args = {c.args[0] for c in rm.call_args_list}
    assert removed_args == {"task|\\Red", "startup|C:\\x\\y.lnk"}
    assert set(res["removed"]) == {"task|\\Red", "startup|C:\\x\\y.lnk"}


def test_clean_all_persistence_no_baseline_is_noop():
    ex = _winrm()
    ex._win_persist_baseline = None
    with patch.object(ex, "_remove_win_persist_entry") as rm:
        res = ex.clean_all_persistence()
    rm.assert_not_called()
    assert res["removed"] == []


def test_orchestrator_cleanup_calls_clean_all_persistence_on_winrm():
    o = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    fake = MagicMock()
    fake.transport = "winrm"
    o.blue_agent.executor = fake
    o._cleanup_persistence()
    fake.clean_all_persistence.assert_called_once()


def test_orchestrator_cleanup_noop_on_non_winrm():
    o = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    fake = MagicMock()
    fake.transport = "ssh"
    o.blue_agent.executor = fake
    o._cleanup_persistence()
    fake.clean_all_persistence.assert_not_called()
