"""Shared vocabulary for an agent's run: the turns it took and the campaign result.

Kept dependency-free so both the standalone agent and the arena/referee can
import it without pulling in the executor or the orchestrator.
"""
from dataclasses import dataclass, field
from typing import Any, List


@dataclass
class Turn:
    n: int
    observation: str     # what the agent saw this turn — its OWN stream only
    action: Any          # the tool-call list or text the agent emitted
    output: str          # the result of acting


@dataclass
class Trajectory:
    role: str
    turns: List[Turn] = field(default_factory=list)
    objective_met: bool = False
