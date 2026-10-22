"""Portable per-system learning: run ONE agent for N episodes against a target
and let it accumulate tradecraft lessons. No adversary, no scoring — that is the
arena's job. This is the loop that travels with a deployed agent: "drop me in a
new system and let me learn it."
"""
from typing import Any, Callable, List, Optional

from src.trajectory import Trajectory


class Learner:
    def __init__(self, agent: Any):
        self.agent = agent

    def train(
        self,
        target: Optional[Any],
        episodes: int,
        max_turns: int,
        reset_fn: Optional[Callable[[Any, int], Any]] = None,
    ) -> List[Trajectory]:
        """Run `episodes` self-driven passes; the agent reflects after each, so its
        knowledge compounds across them. Returns the per-episode trajectories."""
        if target is not None:
            self.agent.target = target
        trajs: List[Trajectory] = []
        for i in range(1, episodes + 1):
            if reset_fn is not None:
                reset_fn(self.agent.executor, i)
            self.agent.reset_episode()
            traj = self.agent.run(max_turns)
            self.agent.reflect("objective met" if traj.objective_met else "neutral")
            trajs.append(traj)
        return trajs
