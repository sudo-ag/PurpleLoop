"""Task 4: a closed vector is recorded as a prevention-class stop and surfaced
in the verdict; refused/error/unsupported closes score nothing."""
import json
from unittest.mock import MagicMock
from src.orchestrator import Orchestrator, SimulationState
from src.referee import Referee


def _orch():
    return Orchestrator(red_agent=MagicMock(), blue_agent=MagicMock())


def _closed(cat="writable", item="/opt/sinatra"):
    return json.dumps({"tool": "remediate_finding", "status": "closed",
                       "category": cat, "target": item})


def test_close_records_vector_stop():
    o = _orch()
    o.state.turn = 5
    o._record_vector_stop(_closed())
    assert o.state.vector_stops == [
        {"category": "writable", "item": "/opt/sinatra", "turn": 5}]


def test_close_is_recorded_once_per_item():
    o = _orch()
    o.state.turn = 2
    o._record_vector_stop(_closed())
    o.state.turn = 4
    o._record_vector_stop(_closed())  # same item again
    assert len(o.state.vector_stops) == 1


def test_refused_or_error_records_no_stop():
    o = _orch()
    for st in ("refused", "error", "unsupported"):
        o._record_vector_stop(json.dumps(
            {"tool": "remediate_finding", "status": st, "category": "writable", "target": "/x"}))
    assert o.state.vector_stops == []


def test_verdict_names_stopped_vectors():
    s = SimulationState()
    s.vector_stops = [{"category": "writable", "item": "/opt/sinatra", "turn": 3}]
    v = Referee(s).verdict()
    assert "writable" in v or "/opt/sinatra" in v


def test_surface_records_each_closed_vector():
    o = _orch()
    o.state.turn = 7
    out = json.dumps({"tool": "remediate_escalation_surface", "closed": [
        {"category": "writable", "item": "/opt/sinatra"},
        {"category": "suid", "item": "/usr/bin/odd"}]})
    o._record_vector_stop(out)
    items = {v["item"] for v in o.state.vector_stops}
    assert items == {"/opt/sinatra", "/usr/bin/odd"}
    assert all(v["turn"] == 7 for v in o.state.vector_stops)
