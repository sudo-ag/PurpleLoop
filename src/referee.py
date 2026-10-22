"""The game's referee: scores an episode from the milestones recorded on the
SimulationState. Pure read/score — it never drives agents, and the agents never
know it exists. The orchestrator records milestones during the loop; the Referee
turns them into a per-tier scoreboard, a one-line verdict, and a winner.
"""
from typing import Any, Dict, List, Optional

# Graded objective tiers (realistic rubric). Red climbs these; blue defends each
# with a matching sensor. T2 (data/credential exfil) is declared but INERT until
# the web/DB exfil sensor lands — nothing records its slots yet.
TIER_FOOTHOLD = 1   # red authenticated an interactive, non-admin foothold
TIER_EXFIL = 2      # red exfiltrated data/credentials (e.g. payroll DB via SQLi)
TIER_ROOT = 3       # red read the root flag (the legacy top objective)
TIERS = (TIER_FOOTHOLD, TIER_EXFIL, TIER_ROOT)
TIER_NAMES = {TIER_FOOTHOLD: "foothold", TIER_EXFIL: "exfil", TIER_ROOT: "root"}


class Referee:
    def __init__(self, state: Any, detect_within_turns: int = 3):
        self.state = state
        self.detect_within_turns = detect_within_turns

    def detection_dwell(self) -> Optional[int]:
        """Turns between red reaching the objective and blue detecting it. None if
        either milestone is missing; negative means blue flagged it early."""
        if self.state.red_access_turn is None or self.state.blue_detect_turn is None:
            return None
        return self.state.blue_detect_turn - self.state.red_access_turn

    def tier_scoreboard(self) -> List[Dict[str, Any]]:
        """Per-tier graded result: for each objective tier, whether red reached it
        and whether blue defended it (detected within the dwell window, or
        contained the attacker at/before that tier). `defended` is None for a tier
        red never reached (no attack to defend)."""
        contain = self.state.blue_contain_turn
        remediate = self.state.blue_remediate_turn
        board: List[Dict[str, Any]] = []
        for tier in TIERS:
            reached = self.state.red_tiers.get(tier)
            detect = self.state.blue_tier_detect.get(tier)
            dwell = (detect - reached) if (reached is not None and detect is not None) else None
            if reached is None:
                defended: Optional[bool] = None
            else:
                stopped_first = min(
                    [t for t in (contain, remediate) if t is not None], default=None
                )
                stopped = stopped_first is not None and stopped_first <= reached
                in_time = detect is not None and reached <= detect <= reached + self.detect_within_turns
                defended = bool(stopped or in_time)
            board.append({
                "tier": tier,
                "name": TIER_NAMES[tier],
                "reached_turn": reached,
                "detect_turn": detect,
                "dwell": dwell,
                "defended": defended,
            })
        return board

    def verdict(self) -> str:
        """One-line graded summary derived from the tier scoreboard, e.g.
        'red reached T2 (exfil); blue defended T1'."""
        board = self.tier_scoreboard()
        reached = [b for b in board if b["reached_turn"] is not None]
        if not reached:
            return "red reached no tier; blue had nothing to defend"
        top = max(b["tier"] for b in reached)
        red_part = f"red reached T{top} ({TIER_NAMES[top]})"
        defended = [b for b in reached if b["defended"]]
        if not defended:
            blue_part = "blue defended nothing"
        else:
            blue_part = "blue defended " + ", ".join(f"T{b['tier']}" for b in defended)
        return f"{red_part}; {blue_part}"

    def resolve_outcome(self) -> Optional[str]:
        """Decide the graded winner from access/detection timing, or None while
        the detection window is still open. Sets state.blue_victory on a blue win."""
        access = self.state.red_access_turn
        detect = self.state.blue_detect_turn
        contain = self.state.blue_contain_turn

        # Prevention beats detection: a firewall block OR account lock before red
        # reached the objective stops the attack — blue wins.
        prevent = min(
            [t for t in (contain, self.state.blue_remediate_turn) if t is not None],
            default=None,
        )
        if prevent is not None and (access is None or prevent <= access):
            self.state.blue_victory = True
            return "blue"

        # Blue wins only by catching a REAL breach in time: a detection in
        # [access, access + K]. A detection with no access is a false alarm.
        if (
            access is not None
            and detect is not None
            and access <= detect <= access + self.detect_within_turns
        ):
            self.state.blue_victory = True
            return "blue"

        if access is not None and self.state.turn - access > self.detect_within_turns:
            return "red"   # red reached the objective and blue missed the window

        return None
