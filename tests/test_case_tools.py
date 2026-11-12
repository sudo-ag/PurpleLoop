"""Blue's note-taking tools mutate the shared case at dispatch time."""
import json
from unittest.mock import MagicMock

from src.agents import Agent, BLUE_TOOL_PRIORITY
from src.case import new_case, current_hypothesis
from src.executor import ToolExecutor


def _blue() -> Agent:
    return Agent("blue", MagicMock(spec=ToolExecutor))


def test_record_lead_appends_to_the_shared_case():
    b = _blue(); b.case = new_case()
    out = b._dispatch_record_lead({"sensor": "investigate_processes",
                                   "observation": "new root proc", "confidence": "high"})
    assert json.loads(out)["status"] == "ok"
    assert b.case["leads"][0]["sensor"] == "investigate_processes"


def test_update_hypothesis_is_visible_same_turn():
    b = _blue(); b.case = new_case()
    b._dispatch_record_lead({"sensor": "investigate_connections", "observation": "x", "confidence": "low"})
    b._dispatch_update_hypothesis({"claim": "probing", "confidence": "medium", "lead_ids": [0]})
    assert current_hypothesis(b.case)["claim"] == "probing"


def test_record_lead_with_missing_confidence_does_not_crash_and_defaults_low():
    b = _blue(); b.case = new_case()
    out = b._dispatch_record_lead({"sensor": "investigate_logs", "observation": "y"})
    assert json.loads(out)["status"] == "ok"
    assert b.case["leads"][0]["confidence"] == "low"


def test_update_hypothesis_with_non_list_lead_ids_is_an_error_not_a_crash():
    b = _blue(); b.case = new_case()
    out = b._dispatch_update_hypothesis({"claim": "z", "confidence": "low", "lead_ids": "nope"})
    assert json.loads(out)["status"] == "error"


def test_note_tools_are_not_in_breadth_rotation():
    assert "record_lead" not in BLUE_TOOL_PRIORITY
    assert "update_hypothesis" not in BLUE_TOOL_PRIORITY
