"""Task 5: doctrine — blue closes the vector (remediate_finding), red pivots
off a path the defender hardened."""
from src.agents import BLUE_SYSTEM_PROMPT, RED_EARNED_ADDENDUM


def test_blue_prompt_has_reactive_close_directive():
    assert "remediate_finding" in BLUE_SYSTEM_PROMPT


def test_red_prompt_has_pivot_directive():
    p = RED_EARNED_ADDENDUM.lower()
    assert "hardened" in p
    assert "another" in p or "different" in p
