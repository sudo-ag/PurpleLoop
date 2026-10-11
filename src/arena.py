"""
Autonomous learning arena.

Runs many self-contained episodes back to back, scores each side against the
rubric from the orchestrator's ground truth, persists a per-episode scorecard,
and prints cross-episode trends. Lessons compound across episodes through the
orchestrator's existing experience/knowledge.json loop, so strategy can emerge
without us scripting the agents' steps.

Build-order note: this is increment 1 (loop machinery + scorecard), proven on
`--host mock`. The full T1/T2/T3 tiering and the scripted reset land in later
increments; `reset_fn` is the hook they plug into.

    uv run python -m src.arena --episodes 3 --host mock
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.agents import Agent
from src.executor import ToolExecutor, _is_ipv4
from src.mock_executor import MockExecutor
from src.orchestrator import Orchestrator

REPO = Path(__file__).resolve().parent.parent
EPISODES_PATH = REPO / "episodes.jsonl"
REPORTS_DIR = REPO / "episode_reports"

# Hook: (blue_executor, red_executor, episode_number) -> None. Increment 2 plugs
# the scripted cleanup in here; the default is a no-op.
ResetFn = Callable[[Any, Any, int], None]


def build_scorecard(state: Any, winner: Optional[str], episode: int) -> Dict[str, Any]:
    """Structured result for one episode, from the orchestrator's ground truth.

    `state` is anything exposing the SimulationState fields (duck-typed), so
    tests can pass a lightweight stand-in. The red T1/T2/T3 tiering slots in once
    the earned-SSH game lands; for now we score the signals we already track.
    """
    g = lambda name: getattr(state, name, None)
    access = g("red_access_turn")
    detect = g("blue_detect_turn")
    contain = g("blue_contain_turn")

    dwell = detect - access if (access is not None and detect is not None) else None

    if contain is not None and (access is None or contain <= access):
        blue_outcome = "contained"       # prevented the breach
    elif access is not None and detect is not None and access <= detect:
        blue_outcome = "detected"        # caught the breach after it happened
    elif detect is not None and access is None:
        blue_outcome = "false_positive"  # flagged with no real access
    else:
        blue_outcome = "missed"

    return {
        "episode": episode,
        "winner": winner,
        "turns": g("turn"),
        "red_outcome": "reached" if access is not None else "blocked",
        "red_access_turn": access,
        "blue_outcome": blue_outcome,
        "blue_detect_turn": detect,
        "blue_contain_turn": contain,
        "contained_ip": g("contained_ip"),
        "dwell": dwell,
    }


def summarize(cards: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate trends across a run of episodes (pure)."""
    n = len(cards)
    if n == 0:
        return {"episodes": 0}
    red_wins = sum(1 for c in cards if c["winner"] == "red")
    blue_wins = sum(1 for c in cards if c["winner"] == "blue")
    detected = sum(1 for c in cards if c["blue_outcome"] in ("detected", "contained"))
    contained = sum(1 for c in cards if c["blue_outcome"] == "contained")
    false_pos = sum(1 for c in cards if c["blue_outcome"] == "false_positive")
    dwells = [c["dwell"] for c in cards if c["dwell"] is not None]
    return {
        "episodes": n,
        "red_wins": red_wins,
        "blue_wins": blue_wins,
        "draws": n - red_wins - blue_wins,
        "blue_detect_rate": round(detected / n, 3),
        "blue_contain_rate": round(contained / n, 3),
        "blue_false_positive_rate": round(false_pos / n, 3),
        "avg_dwell": round(sum(dwells) / len(dwells), 2) if dwells else None,
    }


def scripted_reset(blue_ex: Any, red_ex: Any, episode: int) -> Dict[str, Any]:
    """Operator cleanup between episodes, run over the defender's root channel so
    each episode starts from a consistent baseline rather than the previous
    episode's mess.

    Increment 2 undoes the drift that exists today:
      - firewall blocks on the attacker IP (a DROP rule a crashed episode left
        behind would stop red from ever connecting next time);
      - the auth log (red's evasion scrubbing leaves it mangled across episodes;
        clearing it gives a clean per-episode baseline — blue's analysis window
        already scopes correctness within an episode).

    Persistence vectors (keys/cron/backdoors) are cleaned in a later increment,
    once the earned game actually plants them and the cleanup can be tested.
    """
    actions: List[str] = []
    attacker_ip = getattr(red_ex, "jump_host", None)
    if attacker_ip and _is_ipv4(attacker_ip):
        # Remove every DROP rule for the attacker (loop: there may be more than one).
        blue_ex.execute(
            f"while sudo iptables -C INPUT -s {attacker_ip} -j DROP 2>/dev/null; do "
            f"sudo iptables -D INPUT -s {attacker_ip} -j DROP; done 2>/dev/null; true"
        )
        actions.append(f"flushed firewall blocks for {attacker_ip}")

    blue_ex.execute("sudo truncate -s 0 /var/log/auth.log 2>/dev/null || true")
    actions.append("cleared auth.log")

    return {"episode": episode, "actions": actions}


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def _build_agents(
    host: str, model: str, user: str, pwd: str,
    jump_host: Optional[str], jump_user: str, jump_pwd: str,
    evade: bool, earned: bool, observe: bool,
) -> "tuple[Agent, Agent]":
    """Build red/blue once; they are reused across episodes so their experience
    (via knowledge.json) compounds."""
    attacker_ex: Any = None
    if host == "mock":
        red_ex: Any = MockExecutor()
        blue_ex: Any = red_ex
    else:
        blue_ex = ToolExecutor(host=host, user=user, pwd=pwd)
        if jump_host:
            red_ex = ToolExecutor(
                host=host, user=user, pwd=pwd,
                jump_host=jump_host, jump_user=jump_user, jump_pwd=jump_pwd,
            )
            if earned:
                attacker_ex = ToolExecutor(host=jump_host, user=jump_user, pwd=jump_pwd)
        else:
            red_ex = blue_ex
    red = Agent(
        role="red", executor=red_ex, model=model,
        evade=evade, earned=earned, attacker_executor=attacker_ex,
    )
    blue = Agent(role="blue", executor=blue_ex, model=model, observe=observe)
    return red, blue


def run_episodes(
    n: int,
    host: str = "mock",
    model: Optional[str] = None,
    max_turns: int = 20,
    user: str = "vagrant",
    pwd: str = "vagrant",
    jump_host: Optional[str] = None,
    jump_user: str = "kali",
    jump_pwd: str = "kali",
    evade: bool = False,
    earned: bool = False,
    observe: bool = False,
    detect_within_turns: int = 3,
    reset_fn: Optional[ResetFn] = None,
    reset: bool = True,
    episodes_path: Path = EPISODES_PATH,
    reports_dir: Path = REPORTS_DIR,
) -> Dict[str, Any]:
    """Run `n` episodes, scoring and persisting each, and return the scorecards
    plus a cross-episode summary."""
    model = model or os.getenv("MODEL", "llama3.2:latest")
    reports_dir.mkdir(parents=True, exist_ok=True)
    # Default to the scripted reset on a real box; mock has no state to reset.
    if reset_fn is None and reset and host != "mock":
        reset_fn = scripted_reset
    red, blue = _build_agents(host, model, user, pwd, jump_host, jump_user, jump_pwd, evade, earned, observe)

    cards: List[Dict[str, Any]] = []
    for i in range(1, n + 1):
        if reset_fn is not None:
            reset_fn(blue.executor, red.executor, i)
        # Fresh episode state each time; the orchestrator reloads accumulated
        # knowledge at the start of every run so lessons carry forward.
        orch = Orchestrator(
            red_agent=red, blue_agent=blue,
            detect_within_turns=detect_within_turns, observe=observe,
        )
        winner = orch.run_simulation(max_turns=max_turns)
        card = build_scorecard(orch.state, winner, i)
        # Persist the full per-episode timeline so every scorecard is auditable —
        # a learning loop is only as trustworthy as our ability to see what
        # actually happened in each episode.
        report_path = reports_dir / f"ep_{i:03d}.md"
        try:
            report_path.write_text(orch.generate_report(), encoding="utf-8")
            card["report"] = str(report_path)
        except Exception as e:
            print(f"[episode {i}] could not write report: {e}")
        cards.append(card)
        _append_jsonl(episodes_path, card)
        print(
            f"[episode {i}/{n}] winner={card['winner'] or 'none'} "
            f"red={card['red_outcome']} blue={card['blue_outcome']} dwell={card['dwell']} "
            f"-> {report_path.name}"
        )

    summary = summarize(cards)
    print("\n=== arena summary ===")
    print(json.dumps(summary, indent=2))
    return {"cards": cards, "summary": summary}


def main() -> None:
    p = argparse.ArgumentParser(description="PurpleLoop autonomous learning arena")
    p.add_argument("--episodes", type=int, default=3)
    p.add_argument("--host", default="mock")
    p.add_argument("--model", default=os.getenv("MODEL", "llama3.2:latest"))
    p.add_argument("--max-turns", type=int, default=20)
    p.add_argument("--user", default="vagrant")
    p.add_argument("--pwd", default="vagrant")
    p.add_argument("--jump-host", default=None)
    p.add_argument("--jump-user", default="kali")
    p.add_argument("--jump-pwd", default="kali")
    p.add_argument("--evade", action="store_true")
    p.add_argument("--earned", action="store_true", help="Red must brute-force creds from its attacker box first")
    p.add_argument("--observe", action="store_true", help="Blue training mode: investigate and learn but hold containment, so blue sees more of red's kill chain")
    p.add_argument("--detect-within-turns", type=int, default=3)
    p.add_argument("--no-reset", action="store_true", help="Skip the scripted between-episode reset")
    a = p.parse_args()
    run_episodes(
        a.episodes, host=a.host, model=a.model, max_turns=a.max_turns,
        user=a.user, pwd=a.pwd, jump_host=a.jump_host, jump_user=a.jump_user,
        jump_pwd=a.jump_pwd, evade=a.evade, earned=a.earned, observe=a.observe,
        detect_within_turns=a.detect_within_turns, reset=not a.no_reset,
    )


if __name__ == "__main__":
    main()
