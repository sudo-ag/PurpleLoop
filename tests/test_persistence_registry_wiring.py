"""Orchestrator records every verified Windows plant (by canonical identity) and
every eviction into the plant registry, independent of the legacy scalar turns."""
import json
from unittest.mock import MagicMock

from src.agents import Agent
from src.executor import ToolExecutor
from src.orchestrator import Orchestrator

_PLANT_OUT = "SUCCESS: The scheduled task has successfully been created."
_PLANT_CALL = {"function": {"name": "execute_command", "arguments": {}}}


def _boom():
    raise AssertionError("unexpected live persistence sweep")


class _FakeExec:
    transport = "winrm"
    _diff_baseline = staticmethod(ToolExecutor._diff_baseline)

    def __init__(self, baseline, live):
        self._win_persist_baseline = baseline
        self._live = live

    def _list_win_persistence(self):
        return self._live


def _orch(baseline, live):
    o = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    o.blue_agent.executor = _FakeExec(baseline, live)
    o.state.turn = 3
    return o


def test_windows_plant_records_new_canonical_identity():
    o = _orch(baseline={"task|\\Old"}, live={"task|\\Old", "startup|C:\\x\\y.lnk"})
    o._record_persistence_events("red", _PLANT_CALL, _PLANT_OUT)
    standing = o.state.standing_plants()
    assert [p["identity"] for p in standing] == ["startup|C:\\x\\y.lnk"]


def test_plant_signal_without_new_entry_records_nothing():
    # Red's output matches the plant signal but nothing new appeared (denied /
    # duplicate create): no phantom record.
    o = _orch(baseline={"task|\\Old"}, live={"task|\\Old"})
    o._record_persistence_events("red", _PLANT_CALL, _PLANT_OUT)
    assert o.state.standing_plants() == []


def test_blue_removal_marks_evicted():
    o = _orch(baseline=set(), live=set())
    o.state.record_plant(["startup|C:\\x\\y.lnk"], turn=2)
    out = json.dumps({"tool": "remove_persistence_windows",
                      "removed_entries": ["startup|C:\\x\\y.lnk"]})
    o._record_persistence_events("blue", {"function": {"name": "remove_persistence_windows"}}, out)
    assert o.state.standing_plants() == []


def test_windows_startup_drop_is_recorded_via_diff():
    # A Startup-folder drop produces NO task/service creation signal in its output
    # ("1 file(s) copied."), yet a new startup| entry appears in the diff. It must
    # still be recorded, or red's evasion is invisible to the registry/verdict.
    live = {"task|\\Old", "startup|C:\\u\\Startup\\x.lnk"}
    o = _orch(baseline={"task|\\Old"}, live=live)
    call = {"function": {"name": "execute_command", "arguments": {
        "command": "copy evil.lnk \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk\""}}}
    o._record_persistence_events("red", call, "        1 file(s) copied.")
    assert [p["identity"] for p in o.state.standing_plants()] == ["startup|C:\\u\\Startup\\x.lnk"]


def test_non_persistence_command_does_not_sweep_or_record():
    # A benign red command (not persistence-shaped, no plant signal) records nothing
    # — and must not fire a live sweep. live is set so a stray sweep would record.
    o = _orch(baseline=set(), live={"startup|C:\\u\\Startup\\x.lnk"})
    o.blue_agent.executor._list_win_persistence = _boom  # fail if swept
    call = {"function": {"name": "execute_command", "arguments": {"command": "whoami /groups"}}}
    o._record_persistence_events("red", call, "contractor")
    assert o.state.standing_plants() == []


def test_blue_readable_sweep_sets_baseline_ever_read():
    o = _orch(baseline=set(), live=set())
    out = json.dumps({"tool": "investigate_persistence_windows", "assessment": "CLEAN"})
    o._record_persistence_events("blue", {"function": {"name": "investigate_persistence_windows"}}, out)
    assert o.state.persistence_baseline_ever_read is True


# --- Fix #2: reconcile the in-loop winner with the horizon verdict -------------

def test_prevention_blue_win_honored_without_sweep():
    # Blue cut the foothold before any plant and never swept persistence: the
    # in-loop prevention win must stand, not collapse to None at the horizon.
    o = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    assert o._persistence_episode_winner("blue") == "blue"


def test_stall_blue_win_discarded_when_a_plant_stands():
    # Red planted then idled; the stall "blue" must NOT override a standing plant.
    o = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    o.state.record_plant(["task|\\A"], turn=2)
    assert o._persistence_episode_winner("blue") == "red"


def test_horizon_used_when_no_early_winner():
    o = Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))
    o.state.record_plant(["task|\\A"], turn=2)
    assert o._persistence_episode_winner(None) == "red"
