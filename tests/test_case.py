"""Blue's case/story model: leads + working hypothesis (src/case.py)."""
from src.case import (
    new_case,
    add_lead,
    add_hypothesis,
    current_hypothesis,
    cited_sensors,
    compact_view,
    norm_confidence,
)


def test_new_case_is_empty():
    assert new_case() == {"leads": [], "hypotheses": []}


def test_add_lead_returns_monotonic_ids_and_stores_fields():
    c = new_case()
    i0 = add_lead(c, "investigate_connections", "foreign IP .11", "medium", 2)
    i1 = add_lead(c, "investigate_processes", "new root proc", "high", 4)
    assert (i0, i1) == (0, 1)
    assert c["leads"][0] == {
        "id": 0,
        "sensor": "investigate_connections",
        "observation": "foreign IP .11",
        "confidence": "medium",
        "turn": 2,
    }


def test_current_hypothesis_is_the_last_one_or_none():
    c = new_case()
    assert current_hypothesis(c) is None
    add_hypothesis(c, "probing from .11", "low", [0], 2)
    add_hypothesis(c, "active privesc from .11", "high", [0, 1], 4)
    assert current_hypothesis(c)["claim"] == "active privesc from .11"


def test_cited_sensors_is_distinct_and_skips_unknown_ids():
    c = new_case()
    add_lead(c, "investigate_connections", "x", "low", 1)   # id 0
    add_lead(c, "investigate_connections", "y", "low", 2)   # id 1 (same sensor)
    add_lead(c, "investigate_processes", "z", "low", 3)     # id 2
    assert cited_sensors(c, [0, 1]) == {"investigate_connections"}
    assert cited_sensors(c, [0, 2, 99]) == {"investigate_connections", "investigate_processes"}


def test_norm_confidence_falls_back_to_low():
    assert norm_confidence("high") == "high"
    assert norm_confidence("bogus") == "low"
    assert norm_confidence(None) == "low"


def test_compact_view_trims_to_last_max_leads_but_mentions_hypothesis():
    c = new_case()
    for n in range(20):
        add_lead(c, "investigate_logs", f"evt{n}", "low", n)
    add_hypothesis(c, "noise", "low", [19], 20)
    view = compact_view(c, max_leads=5)
    assert "evt19" in view and "evt0" not in view
    assert "noise" in view
