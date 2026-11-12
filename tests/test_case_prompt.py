"""Blue's per-turn observation includes a compacted case view; store untouched."""
from unittest.mock import MagicMock

from src.agents import Agent
from src.case import new_case, add_lead
from src.executor import ToolExecutor


def _blue() -> Agent:
    return Agent("blue", MagicMock(spec=ToolExecutor))


def test_blue_observation_includes_the_case_view():
    b = _blue(); b.case = new_case()
    add_lead(b.case, "investigate_connections", "foreign IP .11", "medium", 2)
    obs = b.build_observation()
    assert "foreign IP .11" in obs


def test_rendering_the_view_does_not_trim_the_full_store():
    b = _blue(); b.case = new_case()
    for n in range(30):
        add_lead(b.case, "investigate_logs", f"e{n}", "low", n)
    _ = b.build_observation()
    assert len(b.case["leads"]) == 30


def test_no_case_view_when_case_is_none():
    b = _blue(); b.case = None
    _ = b.build_observation()  # must not raise
