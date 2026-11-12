"""Blue's in-episode case/story model.

A case is a plain dict the orchestrator owns on `SimulationState.blue_case`;
blue mutates it only through these validated functions (called from the
`record_lead` / `update_hypothesis` tools), so blue cannot write arbitrary
fields. Leads are append-only facts; hypotheses are an append-only log whose
tail is the current belief — keeping the history is what lets the replay and
the executive summary show how the story changed over time.
"""
from typing import Any, Dict, List, Optional, Set

_LEVELS = ("low", "medium", "high")


def new_case() -> Dict[str, Any]:
    return {"leads": [], "hypotheses": []}


def norm_confidence(value: Any) -> str:
    """Confidence is one of low/medium/high; anything else fails safe to low."""
    return value if value in _LEVELS else "low"


def add_lead(case: Dict[str, Any], sensor: str, observation: str,
             confidence: str, turn: int) -> int:
    """Append a lead, return its id (monotonic, index-based)."""
    lead_id = len(case["leads"])
    case["leads"].append({
        "id": lead_id,
        "sensor": sensor,
        "observation": observation,
        "confidence": norm_confidence(confidence),
        "turn": turn,
    })
    return lead_id


def add_hypothesis(case: Dict[str, Any], claim: str, confidence: str,
                   lead_ids: List[int], turn: int) -> None:
    case["hypotheses"].append({
        "claim": claim,
        "confidence": norm_confidence(confidence),
        "lead_ids": list(lead_ids),
        "turn": turn,
    })


def current_hypothesis(case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return case["hypotheses"][-1] if case["hypotheses"] else None


def cited_sensors(case: Dict[str, Any], lead_ids: List[int]) -> Set[str]:
    """Distinct sensors of the cited leads; ids with no matching lead are skipped."""
    by_id = {lead["id"]: lead["sensor"] for lead in case["leads"]}
    return {by_id[i] for i in lead_ids if i in by_id}


def compact_view(case: Dict[str, Any], max_leads: int = 12) -> str:
    """Prompt-facing text: the last `max_leads` leads + the current hypothesis.

    Reads only — never trims the stored case."""
    lines = ["CASE FILE:"]
    for lead in case["leads"][-max_leads:]:
        lines.append(
            f"  [#{lead['id']} t{lead['turn']} {lead['confidence']}] "
            f"{lead['sensor']}: {lead['observation']}"
        )
    hyp = current_hypothesis(case)
    if hyp is not None:
        lines.append(
            f"HYPOTHESIS ({hyp['confidence']}, leads {hyp['lead_ids']}): {hyp['claim']}"
        )
    return "\n".join(lines)
