"""Per-agent, per-episode debrief: a first-person, pentest-style narrative.

Deterministic by default (assembled from the finished episode `state` + the
`card` that already holds verdict/tiers), so the same episode renders the same
report. An optional `polish` callable rewrites the skeleton into prose; it is
the only non-deterministic step and it fails safe to the skeleton.
"""
from typing import Any, Callable, Dict, List, Optional

ROLE_LABEL = {"red": "🔴 Red", "blue": "🔵 Blue"}

# Plain-language phrasing for the "Actions taken" narration (spec: one
# plain-language line per action, not a raw tool name).
_TOOL_PHRASE = {
    "execute_command": "ran a command on the target",
    "use_credential": "logged in with a discovered credential",
    "run_on_attacker": "worked from my attacker box",
    "investigate_logs": "reviewed the auth and sudo logs",
    "investigate_connections": "checked inbound network connections",
    "investigate_processes": "inspected running processes",
    "investigate_file_access": "checked access to the sensitive file",
    "investigate_network": "scanned for unexpected listeners",
    "investigate_docker": "checked container-escape posture",
    "investigate_privileged_accounts": "audited privileged accounts",
    "investigate_webshells": "checked the web root for web shells",
    "investigate_persistence": "checked for planted SSH keys",
    "investigate_box_anomalies": "profiled the box for anomalies",
    "investigate_ftp_sessions": "reviewed FTP session activity",
    "investigate_web_requests": "reviewed web-server access logs",
    "contain_attacker": "firewalled the attacker's IP",
    "remediate_account": "locked the compromised account",
    "revoke_escalation": "stripped the account's escalation path",
    "remove_persistence": "removed a planted SSH key",
    "remove_privileged_account": "deleted a rogue privileged account",
    "record_lead": "filed a lead in my case file",
    "update_hypothesis": "updated my working hypothesis",
}


def _phrase(name: str) -> str:
    return _TOOL_PHRASE.get(name, f"used {name}")


def build_debrief(role: str, state: Any, card: Dict[str, Any],
                  polish: Optional[Callable[[str, str], str]] = None) -> str:
    """One agent's full markdown debrief. With `polish`, returns the rewritten
    prose, falling back to the deterministic skeleton on any error/empty."""
    skeleton = _skeleton(role, state, card)
    if polish is None:
        return skeleton
    try:
        out = polish(skeleton, role)
        return out if (out and out.strip()) else skeleton  # never emit a blank/whitespace debrief
    except Exception:
        return skeleton


def make_polish(client: Any, model: str) -> Callable[[str, str], str]:
    """Build a polish callable that asks `model` to rewrite a debrief skeleton as
    prose. It must NOT invent facts; errors/empties are absorbed by build_debrief."""
    def polish(skeleton: str, role: str) -> str:
        prompt = (
            f"Rewrite this {role}-team episode debrief as flowing, first-person prose. "
            "Keep all four sections and their headings. Do NOT add any fact, number, "
            "or event that is not already present in the text below.\n\n" + skeleton
        )
        resp = client.chat(model=model, messages=[{"role": "user", "content": prompt}])
        return resp["message"]["content"]
    return polish


def _skeleton(role: str, state: Any, card: Dict[str, Any]) -> str:
    label = ROLE_LABEL.get(role, role.capitalize())
    parts: List[str] = [
        f"## {label} Debrief",
        "",
        "### Executive Summary",
        _exec_summary(role, state, card),
        "",
        "### Actions Taken",
        _actions(role, state),
        "",
        "### What I Learned",
        _learned(role, state),
        "",
        "### What's Next",
        _next_step(role, state, card),
    ]
    if role == "blue":
        auto = _automated_responses(state)
        if auto:
            parts += ["", "### Automated Responses", auto]
    return "\n".join(parts)


def _exec_summary(role: str, state: Any, card: Dict[str, Any]) -> str:
    who = "attacker" if role == "red" else "defender"
    verdict = card.get("verdict") or "no graded verdict was recorded"
    return f"This episode, operating as the {who}, the graded outcome was: {verdict}."


def _actions(role: str, state: Any) -> str:
    if role == "blue":
        return _blue_actions(state)
    return _history_actions(state, role) or "I took no recorded actions this episode."


def _blue_actions(state: Any) -> str:
    case = getattr(state, "blue_case", None) or {"leads": [], "hypotheses": []}
    leads = case.get("leads", [])
    hyps = case.get("hypotheses", [])
    if not leads and not hyps:
        return _history_actions(state, "blue") or "I investigated but filed no leads this episode."
    lines = [f"I filed {len(leads)} lead(s) as I investigated:"]
    for lead in leads:
        lines.append(
            f"- [{lead.get('confidence')}] {lead.get('sensor')}: {lead.get('observation')}"
        )
    if hyps:
        lines.append("My working theory evolved:")
        for hyp in hyps:
            lines.append(f"- ({hyp.get('confidence')}) {hyp.get('claim')}")
    return "\n".join(lines)


def _history_actions(state: Any, role: str) -> str:
    lines = []
    for h in (getattr(state, "history", []) or []):
        if h.get("role") != role:
            continue
        if "tool" in h:
            name = ((h.get("tool") or {}).get("function", {}) or {}).get("name")
            if name:
                lines.append(f"- I {_phrase(name)}.")
    return "\n".join(lines)


def _learned(role: str, state: Any) -> str:
    return getattr(state, f"{role}_lesson", None) or "No lesson recorded this episode."


def _next_step(role: str, state: Any, card: Dict[str, Any]) -> str:
    lesson = getattr(state, f"{role}_lesson", None) or ""
    low = lesson.lower()
    for marker in ("so next time", "next time"):
        i = low.find(marker)
        if i != -1:
            clause = lesson[i + len(marker):].strip(" ,.;:")
            if clause:
                return clause
    return _tier_next(role, card) or "No explicit next step recorded."


def _tier_next(role: str, card: Dict[str, Any]) -> Optional[str]:
    tiers = card.get("tiers") or []
    if role == "red":
        if any(b.get("reached_turn") is not None for b in tiers):
            return "Build on the access already gained and push to the next tier."
    else:
        if any(b.get("reached_turn") is not None and not b.get("defended") for b in tiers):
            return "Close the gap on the tier the attacker reached undefended."
    return None


def _automated_responses(state: Any) -> str:
    notes = []
    if getattr(state, "escalation_auto_revoked", False):
        notes.append("- The orchestrator auto-revoked the foothold account's escalation path.")
    if getattr(state, "remediated_user", None):
        notes.append(f"- Account '{state.remediated_user}' was locked.")
    return "\n".join(notes)
