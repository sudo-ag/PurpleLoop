"""Coverage matrix: a (tool,name,args,output)->vector classifier over
already-recorded episode timelines (episode_reports/ep_*.json).

Reuses the existing stateless orchestrator red/blue checks wherever one
already exists for a vector, rather than re-deriving the same matching
logic a second time. No scoring/referee changes: this reads already-
written episode artifacts, it never feeds back into red_tiers/
blue_tier_detect/live scoring.

See docs/superpowers/specs/2026-11-12-purpleloop-coverage-matrix-design.md
for the full per-vector rule table this module implements.
"""
import argparse
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import MagicMock

from src.agents import Agent
from src.orchestrator import Orchestrator, TIER_FOOTHOLD, TIER_EXFIL, TIER_ROOT


def _as_tool_call(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Flattened ep_NNN.json timeline entries ({"name","args",...}) use a
    different shape than the tool_call dict ({"function": {"name",
    "arguments"}}) every reused orchestrator check expects. Getting this
    adapter wrong doesn't crash -- tool_call.get("function", {}).get("name")
    just silently returns "" on the wrong shape, so every reused-check row
    would read "unreached" forever with no error. This is the one place
    that translation happens."""
    return {"function": {"name": entry.get("name", ""), "arguments": entry.get("args") or {}}}


def _dummy_orch() -> Orchestrator:
    """A fresh, side-effect-free Orchestrator per classification call, same
    construction as tests/test_tiers.py's _orch() helper. A MagicMock(spec=Agent)
    blue agent has no `executor` attribute set, so any reused check that looks
    up a live baseline (e.g. _check_red_rogue_root_creation's uid0 baseline)
    safely resolves to None -- which is exactly the intentionally loose,
    without-baseline-exclusion behavior this module wants for dirtycow, with
    no extra code. Never shared across calls, so this stays side-effect-free."""
    return Orchestrator(MagicMock(spec=Agent), MagicMock(spec=Agent))


def _blue_sensor_breach(sensor_name: str) -> Callable[[Dict[str, Any]], bool]:
    """A blue_detect closure for a sensor with no dedicated orchestrator
    check: role == blue, name == sensor_name, parsed output's assessment
    is BREACH."""
    def fn(entry: Dict[str, Any]) -> bool:
        if entry.get("role") != "blue" or entry.get("name") != sensor_name:
            return False
        try:
            data = json.loads(entry.get("output") or "")
        except Exception:
            return False
        return isinstance(data, dict) and data.get("assessment") == "BREACH"
    return fn


def _never(entry: Dict[str, Any]) -> bool:
    """Shared by every not_attempted vector -- never fabricates a match."""
    return False


def _ssh_brute_red(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "red":
        return False
    orch = _dummy_orch()
    return bool(orch._check_red_foothold(_as_tool_call(entry), entry.get("output", "") or ""))


def _ssh_brute_blue(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "blue":
        return False
    orch = _dummy_orch()
    return bool(orch._check_blue_foothold_detect(entry.get("output", "") or ""))


def _sqli_exfil_red(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "red":
        return False
    orch = _dummy_orch()
    return bool(orch._check_red_data_exfil(_as_tool_call(entry), entry.get("output", "") or ""))


def _sqli_exfil_blue(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "blue":
        return False
    orch = _dummy_orch()
    return bool(orch._check_blue_exfil_detect(entry.get("output", "") or ""))


def _proftpd_red(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "red":
        return False
    orch = _dummy_orch()
    return bool(orch._check_red_tier1_via_webshell(_as_tool_call(entry), entry.get("output", "") or ""))


def _drupal_red(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "red":
        return False
    orch = _dummy_orch()
    return bool(orch._check_red_tier1_via_drupal_rce(_as_tool_call(entry), entry.get("output", "") or ""))


def _persistence_red(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "red":
        return False
    orch = _dummy_orch()
    return bool(orch._check_red_persistence_planted(_as_tool_call(entry), entry.get("output", "") or ""))


def _dirtycow_red(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "red" or entry.get("name") != "execute_command":
        return False
    orch = _dummy_orch()
    return bool(orch._check_red_rogue_root_creation(_as_tool_call(entry), entry.get("output", "") or ""))


def _docker_breakout_red(entry: Dict[str, Any]) -> bool:
    if entry.get("role") != "red" or entry.get("name") != "execute_command":
        return False
    command = (entry.get("args") or {}).get("command", "")
    if "docker run" not in command:
        return False
    if "-v /:" not in command and "--privileged" not in command:
        return False
    orch = _dummy_orch()
    return bool(orch._check_red_victory(entry.get("output", "") or ""))


_webshells_breach = _blue_sensor_breach("investigate_webshells")

VECTORS: List[Dict[str, Any]] = [
    {"name": "ssh_brute", "tier": TIER_FOOTHOLD, "status": "active",
     "red_reach": _ssh_brute_red, "blue_detect": _ssh_brute_blue},
    {"name": "sqli_payroll_exfil", "tier": TIER_EXFIL, "status": "active",
     "red_reach": _sqli_exfil_red, "blue_detect": _sqli_exfil_blue},
    {"name": "proftpd_modcopy", "tier": TIER_FOOTHOLD, "status": "active",
     "red_reach": _proftpd_red, "blue_detect": _webshells_breach},
    {"name": "drupal_drupalgeddon2", "tier": TIER_FOOTHOLD, "status": "active",
     "red_reach": _drupal_red, "blue_detect": _webshells_breach},
    {"name": "ssh_key_persistence", "tier": None, "status": "active",
     "red_reach": _persistence_red, "blue_detect": _blue_sensor_breach("investigate_persistence")},
    {"name": "docker_breakout", "tier": TIER_ROOT, "status": "active",
     "red_reach": _docker_breakout_red, "blue_detect": _blue_sensor_breach("investigate_docker")},
    {"name": "dirtycow", "tier": TIER_ROOT, "status": "active",
     "red_reach": _dirtycow_red, "blue_detect": _blue_sensor_breach("investigate_privileged_accounts")},
    {"name": "writable_sinatra_privesc", "tier": None, "status": "not_attempted",
     "red_reach": _never, "blue_detect": _never},
    {"name": "sambacry", "tier": None, "status": "not_attempted",
     "red_reach": _never, "blue_detect": _never},
    {"name": "phpmyadmin_preg_replace", "tier": None, "status": "not_attempted",
     "red_reach": _never, "blue_detect": _never},
]


def classify_episode(ep_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Classify one parsed ep_NNN.json against every vector in VECTORS."""
    timeline = ep_data.get("timeline", [])
    tiers = ep_data.get("tiers", [])
    result: Dict[str, Dict[str, Any]] = {}
    for v in VECTORS:
        reached = any(v["red_reach"](e) for e in timeline)
        detected = any(v["blue_detect"](e) for e in timeline)
        prevented: Optional[bool]
        if v["tier"] is None or not (reached and detected):
            prevented = None
        else:
            tier_entry = next((t for t in tiers if t.get("tier") == v["tier"]), None)
            prevented = None if tier_entry is None else bool(tier_entry.get("defended"))
        result[v["name"]] = {"reached": reached, "detected": detected, "prevented": prevented}
    return result


def aggregate(per_episode: List[Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """Aggregate classify_episode outputs across every scanned episode:
    reached/detected are true if true in ANY episode; prevented is None
    only if no episode ever both reached+detected this vector, False if
    judged at least once but never defended, True if defended at least
    once."""
    result: Dict[str, Dict[str, Any]] = {}
    names = per_episode[0].keys() if per_episode else (v["name"] for v in VECTORS)
    for name in names:
        reached = any(ep[name]["reached"] for ep in per_episode)
        detected = any(ep[name]["detected"] for ep in per_episode)
        judged = [ep[name]["prevented"] for ep in per_episode if ep[name]["prevented"] is not None]
        prevented = None if not judged else (True if any(judged) else False)
        result[name] = {"reached": reached, "detected": detected, "prevented": prevented}
    return result


def build_matrix(episodes_dir: str = "episode_reports") -> Dict[str, Any]:
    """Scan every ep_*.json under episodes_dir, classify and aggregate."""
    paths = sorted(Path(episodes_dir).glob("ep_*.json"))
    per_episode = []
    for p in paths:
        try:
            ep_data = json.loads(p.read_text())
        except Exception:
            continue
        per_episode.append(classify_episode(ep_data))
    agg = aggregate(per_episode)
    vectors_out = {v["name"]: {**agg[v["name"]], "status": v["status"]} for v in VECTORS}
    return {"vectors": vectors_out, "episodes_scanned": [p.name for p in paths]}


def _symbol(value: Optional[bool]) -> str:
    return "✅" if value is True else ("❌" if value is False else "—")


def write_outputs(
    matrix: Dict[str, Any],
    json_path: str = "coverage_matrix.json",
    md_path: str = "coverage_matrix.md",
) -> None:
    """Write the full matrix as JSON, and a rendered markdown table (with
    an explicit note for every not_attempted vector) to md_path."""
    Path(json_path).write_text(json.dumps(matrix, indent=2))

    lines = [
        "# Coverage Matrix",
        "",
        f"Episodes scanned: {len(matrix['episodes_scanned'])}",
        "",
        "| vector | red reaches | blue detects | blue prevents |",
        "|---|---|---|---|",
    ]
    not_attempted_notes = []
    for name, v in matrix["vectors"].items():
        reach = "✅" if v["reached"] else "—"
        detect = "✅" if v["detected"] else "—"
        prevent = _symbol(v["prevented"])
        lines.append(f"| {name} | {reach} | {detect} | {prevent} |")
        if v["status"] == "not_attempted":
            not_attempted_notes.append(f"- `{name}` — not attempted this project (see HANDOFF.md)")
    if not_attempted_notes:
        lines.append("")
        lines.extend(not_attempted_notes)
    Path(md_path).write_text("\n".join(lines) + "\n")


def main() -> None:
    p = argparse.ArgumentParser(description="PurpleLoop coverage matrix")
    p.add_argument("--episodes-dir", default="episode_reports")
    p.add_argument("--out-json", default="coverage_matrix.json")
    p.add_argument("--out-md", default="coverage_matrix.md")
    a = p.parse_args()
    matrix = build_matrix(a.episodes_dir)
    write_outputs(matrix, a.out_json, a.out_md)
    vectors = matrix["vectors"]
    total = len(vectors)
    reached_n = sum(1 for v in vectors.values() if v["reached"])
    detected_n = sum(1 for v in vectors.values() if v["detected"])
    prevented_n = sum(1 for v in vectors.values() if v["prevented"] is True)
    print(
        f"coverage: {reached_n}/{total} vectors reached, {detected_n}/{total} detected, "
        f"{prevented_n} prevented"
    )


if __name__ == "__main__":
    main()
