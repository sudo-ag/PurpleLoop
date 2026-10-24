from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import requests
import json
import os
import re
import difflib
from src.agents import Agent
from src.referee import (
    Referee,
    TIER_FOOTHOLD,
    TIER_EXFIL,
    TIER_ROOT,
    TIERS,
    TIER_NAMES,
)


# --- lesson memory hygiene --------------------------------------------------
# Every lesson in knowledge.json is injected into the agent's prompt each turn,
# so an unbounded, near-duplicate-laden list bloats the prompt and drowns real
# signal (the loop produced ~10 near-identical "repeating failed find/sudo"
# lessons per side). Keep the list deduped and bounded.
_LESSON_CAP = 20
_LESSON_SIM_THRESHOLD = 0.82      # char-sequence (difflib): near-identical text
_LESSON_JACCARD_THRESHOLD = 0.5   # token overlap: reordered / reworded repeats


def _normalize_lesson(s: str) -> str:
    return " ".join(s.strip().lstrip("*•- ").lower().split())


def merge_lesson(lessons: List[str], new: Optional[str],
                 cap: int = _LESSON_CAP,
                 threshold: float = _LESSON_SIM_THRESHOLD,
                 jaccard: float = _LESSON_JACCARD_THRESHOLD) -> List[str]:
    """Append `new` unless it duplicates an existing lesson, then keep only the
    most recent `cap`. Pure — returns a new list, never mutates. A duplicate is
    exact-normalized, char-similar (difflib >= threshold), or token-similar
    (Jaccard >= jaccard). Thresholds are conservative so genuinely distinct
    lessons are never merged.

    shortcut: this catches exact/reworded re-emits, not semantically identical
    lessons phrased very differently (measured char/token overlap there is
    indistinguishable from distinct lessons); the cap bounds those. Upgrade to
    an embedding / LLM-judge pass for true semantic dedup (needs a model).
    """
    if not new or not new.strip():
        return list(lessons)
    norm_new = _normalize_lesson(new)
    tok_new = set(norm_new.split())
    for ex in lessons:
        norm = _normalize_lesson(ex)
        tok = set(norm.split())
        union = tok | tok_new
        if (norm == norm_new
                or difflib.SequenceMatcher(None, norm, norm_new).ratio() >= threshold
                or (union and len(tok & tok_new) / len(union) >= jaccard)):
            return list(lessons)
    return (list(lessons) + [new])[-cap:]


def dedupe_lessons(lessons: List[str],
                   cap: int = _LESSON_CAP,
                   threshold: float = _LESSON_SIM_THRESHOLD) -> List[str]:
    """Compact an existing lesson list by replaying it through `merge_lesson`,
    so accumulated near-duplicates collapse and the result respects the cap."""
    out: List[str] = []
    for lesson in lessons:
        out = merge_lesson(out, lesson, cap=cap, threshold=threshold)
    return out


# Blue steers through its investigation tools in this order. The first two are
# the only tools that surface flag-file access (the breach signal), so they
# lead; the rest give context. Blue is nudged toward the first tool it has not
# run yet, which stops the 3B model from repeating one tool every turn.

@dataclass
class SimulationState:
    turn: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)
    red_captured_flag: bool = False
    blue_victory: bool = False
    current_agent_role: str = "red"
    red_phase: str = "initial_enum"
    red_stalled_turns: int = 0
    red_failed_turns: int = 0   # turns where red made tool calls but none succeeded (output contains error/permission/no such/file not found)
    red_access_turn: Optional[int] = None   # turn red first reached the objective
    blue_detect_turn: Optional[int] = None  # turn blue first raised a confirmed BREACH
    blue_contain_turn: Optional[int] = None  # turn blue firewalled the real attacker IP
    contained_ip: Optional[str] = None       # the attacker IP blue contained
    blue_remediate_turn: Optional[int] = None  # turn blue locked the compromised account
    remediated_user: Optional[str] = None      # the account blue remediated
    red_tiers: Dict[int, int] = field(default_factory=dict)        # tier -> turn red first reached it
    blue_tier_detect: Dict[int, int] = field(default_factory=dict) # tier -> turn blue first detected it
    red_foothold_cred: Optional[Dict[str, str]] = None             # {user,pwd} red earned via use_credential
    escalation_auto_revoked: bool = False  # blue's reflex stripped the foothold account's escalation path
    staged_remediation_user: Optional[str] = None  # account blue asked to lock while the grace window is still open (not yet applied)

class Orchestrator:
    def __init__(self, red_agent: Agent, blue_agent: Agent, max_tools_per_turn: int = 3, stall_limit: int = 5, flag_path: str = "/root/flag.txt", detect_within_turns: int = 3, dashboard_url: Optional[str] = None, knowledge_file: str = "knowledge.json", observe: bool = False, remediate_grace: int = 0):
        self.red_agent = red_agent
        self.blue_agent = blue_agent
        self.max_tools_per_turn = max_tools_per_turn
        self.stall_limit = stall_limit
        self.flag_path = flag_path
        # Blue "wins" a breach if it raises a confirmed BREACH within this many
        # turns of red first reaching the objective (dwell time). Beyond it, the
        # access went undetected long enough that red is scored the winner.
        self.detect_within_turns = detect_within_turns
        self.dashboard_url = dashboard_url
        self.knowledge_file = knowledge_file
        # Observation/training mode: suppress blue's containment order so blue
        # observes the attacker's full approach instead of ending at turn 1.
        self.observe = observe
        # Grace window (turns) between red earning a foothold and blue's account
        # lock actually taking effect: blue still detects on time, but its lock is
        # held for this many turns so red gets a window to escalate before being
        # cut off — models a defender's response lag and keeps the T1 contest from
        # being an instant-lock auto-win. 0 disables it (instant lock).
        self.remediate_grace = remediate_grace
        self.state = SimulationState()
        # The referee scores from the state's recorded milestones; the loop
        # records, the referee judges.
        self.referee = Referee(self.state, detect_within_turns)


    def _notify_dashboard(self, event_type: str, data: Dict[str, Any]):
        if self.dashboard_url:
            try:
                requests.post(f"{self.dashboard_url}/update", json={"event_type": event_type, "data": data}, timeout=1.0)
            except Exception:
                pass # Don't let dashboard failures stop simulation

    def get_current_agent(self) -> Agent:

        return self.red_agent if self.state.current_agent_role == "red" else self.blue_agent

    def _check_red_victory(self, output: str) -> bool:
        """Red read the flag if its output carries the flag marker. The box's
        flag is `FLAG{...}`; match case-insensitively so a lower/mixed-case read
        still registers. (A genuine read is also corroborated by blue's auth-log
        detection, which back-fills red's access if this misses.)"""
        return "flag{" in output.lower()

    def _check_blue_victory(self, output: str) -> bool:
        """True only when blue has CONFIRMED access to the objective (the flag).

        Generic 'suspicious'/'critical' process or network findings are presence
        signals, not an objective catch — treating them as a win is what let a
        benign baseline service (e.g. `tcpdump`) hand blue a false-positive win.
        The authoritative signal is `flag_access_detected` (set only on an
        in-window flag read); a read-after-write SUSPICIOUS result is NOT a catch.
        """
        try:
            data = json.loads(output)
        except Exception:
            lowered = output.lower()
            return (
                "sensitive file was accessed" in lowered
                or "flag file access detected" in lowered
                or "confirmed compromise" in lowered
            )

        if not isinstance(data, dict):
            return False
        if data.get("flag_access_detected") is True:
            return True
        summary = str(data.get("summary", "")).lower()
        return (
            "sensitive file was accessed" in summary
            or "flag file access detected" in summary
            or "confirmed compromise" in summary
        )

    def _attacker_ip(self) -> Optional[str]:
        """The attacker's source IP as the target sees it — red's jump host. None
        for a single-box run (no jump), where attacker and defender share a source
        and containment can't be attributed."""
        return getattr(self.red_agent.executor, "jump_host", None)

    def _check_blue_containment(self, output: str) -> Optional[str]:
        """Return the IP blue successfully contained this turn, or None."""
        try:
            data = json.loads(output)
        except Exception:
            return None
        if (
            isinstance(data, dict)
            and data.get("tool") == "contain_attacker"
            and data.get("contained") is True
        ):
            return data.get("target_ip")
        return None

    def _check_blue_remediation(self, output: str) -> Optional[str]:
        """Return the account blue successfully remediated (locked + killed) this
        turn, or None."""
        try:
            data = json.loads(output)
        except Exception:
            return None
        if (isinstance(data, dict) and data.get("tool") == "remediate_account"
                and data.get("remediated") is True):
            return data.get("target_user")
        return None

    def _remediation_held(self) -> bool:
        """True while blue's account lock is inside the post-foothold grace window:
        the lock is staged but NOT executed, so red stays logged in and gets turns
        to escalate before being cut off."""
        foothold = self.state.red_tiers.get(TIER_FOOTHOLD)
        return (self.remediate_grace > 0 and foothold is not None
                and self.state.turn < foothold + self.remediate_grace)

    def _stage_remediation(self, tool_call: Dict[str, Any]) -> str:
        """Record blue's lock request without executing it (grace window). Returns
        a `remediated: False` result so blue is not credited a containment yet and
        the episode does not end on it."""
        user = (tool_call.get("function", {}).get("arguments", {}) or {}).get("user", "")
        self.state.staged_remediation_user = user
        return json.dumps({
            "tool": "remediate_account", "target_user": user, "remediated": False,
            "assessment": "STAGED",
            "summary": (f"Attacker detected on '{user}'; account lock staged "
                        "(response lag) and not yet applied."),
        })

    def _apply_staged_remediation(self) -> None:
        """Execute the lock blue requested during the grace window, once that window
        has closed. Idempotent; a no-op if nothing is staged or blue already locked."""
        user = self.state.staged_remediation_user
        if not user or self._remediation_held() or self.state.blue_remediate_turn is not None:
            return
        self.state.staged_remediation_user = None
        findings = self.blue_agent.executor.remediate_account(user)
        if isinstance(findings, dict) and findings.get("remediated"):
            self.state.blue_remediate_turn = self.state.turn
            self.state.remediated_user = user
            self._notify_dashboard("blue_remediation", {"turn": self.state.turn, "user": user})

    def _auto_revoke_escalation(self, detect_output: str) -> None:
        """Blue's deterministic reflex: strip the foothold account's escalation
        path (docker/sudo) the moment the foothold is detected, outside the model
        loop — an EDR-style auto-isolate. Fires once; the account is read from
        blue's own detection output (`suspicious_users`). Runs even in observe
        (on-host least-privilege, not a network block); no-ops on executors that
        lack the action (mock)."""
        if self.state.escalation_auto_revoked:
            return
        ex = getattr(self.blue_agent, "executor", None)
        if ex is None or not hasattr(ex, "revoke_escalation"):
            return
        try:
            users = [u for u in (json.loads(detect_output).get("suspicious_users") or []) if u]
        except Exception:
            users = []
        if not users:
            return
        user = users[0]
        result = ex.revoke_escalation(user)
        self.state.escalation_auto_revoked = True
        self.state.history.append({
            "role": "blue", "turn": self.state.turn,
            "tool": {"function": {"name": "revoke_escalation",
                                  "arguments": {"user": user}}, "auto": True},
            "output": json.dumps(result),
        })
        self._notify_dashboard("battle_log",
                               {"tool": "auto revoke_escalation", "output": json.dumps(result)})

    def _check_red_foothold(self, tool_call: Dict[str, Any], output: str) -> bool:
        """Red proved an interactive foothold this turn (T1): a validated
        `use_credential`, or any successful command on the target (recon from the
        attacker box via `run_on_attacker` is not a target foothold)."""
        name = tool_call.get("function", {}).get("name", "")
        if name == "use_credential":
            try:
                data = json.loads(output)
            except Exception:
                return False
            return isinstance(data, dict) and data.get("status") == "success"
        if name == "execute_command":
            return bool(output and output.strip()) and not self._is_error_output(output)
        return False

    def _check_blue_foothold_detect(self, output: str) -> bool:
        """Blue saw red's foothold (T1): the auth log shows a successful login
        from a non-control source. The parser tags these 'Successful
        authentication' (blue's own session is tagged separately).

        shortcut: relies on that high-severity event surviving log compaction;
        upgrade to an explicit parser boolean if a critical-event flood hides it.
        """
        try:
            data = json.loads(output)
        except Exception:
            return False
        if not isinstance(data, dict):
            return False
        for evt in data.get("events", []) or []:
            if isinstance(evt, dict) and evt.get("event") == "Successful authentication":
                return True
        return False

    # Error indicators that mean a red tool call produced no usable result
    # (permission denied, missing paths, bad syntax, etc.) rather than a
    # useful reconnaissance result the red agent can act on.
    _RED_ERROR_PATTERNS = (
        "permission denied",
        "no such file",
        "no such directory",
        "cannot open",
        "cannot access",
        "command not found",
        "not found",
        "error:",
        "error ",
        "usage:",
        "option requires",
        "invalid",
        "failed",
        "denied",
        "exit status",
    )

    def _is_error_output(self, output: str) -> bool:
        """True only when a command produced NOTHING actionable — every non-empty
        line reads as an error. Output that mixes real results with a few error
        lines (e.g. `find` printing hits alongside some 'Permission denied') is
        still useful, so it is not an error. (Previously a single error word
        anywhere mislabeled the whole output, suppressing legit foothold credit
        and skewing the stall/fail heuristic.)"""
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        if not lines:
            return True
        return all(
            any(p in ln.lower() for p in self._RED_ERROR_PATTERNS)
            for ln in lines
        )

    def _tool_call_signature(self, tool_call: Dict[str, Any]) -> str:
        function = tool_call.get("function", {})
        name = function.get("name", "")
        arguments = function.get("arguments", {})
        return json.dumps({"name": name, "arguments": arguments}, sort_keys=True)

    def step(self) -> Optional[str]:
        """
        Performs one turn of the simulation.
        Returns the winner if the simulation ends, otherwise None.
        """
        agent = self.get_current_agent()
        role = self.state.current_agent_role

        # Grace window closed? Apply the lock blue staged during it (blue's action,
        # so only on blue's turn — applying on red's turn would preempt its window).
        if role == "blue":
            self._apply_staged_remediation()

        # Notify dashboard of turn start
        self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": None})

        # The agent builds its own observation and self-steers — the orchestrator
        # no longer hand-feeds it a state summary.
        state_summary = agent.build_observation()

        tools_called = 0
        text_retries = 0
        seen_tool_calls = set()
        while tools_called < self.max_tools_per_turn:
            action = agent.act(state_summary)

            if isinstance(action, str):
                if tools_called == 0 and text_retries < 1 and role in ("red", "blue"):
                    text_retries += 1
                    if role == "red":
                        state_summary += (
                            "\nYour previous response was text, but red must call "
                            "`execute_command`. Return a tool call now."
                        )
                    else:
                        state_summary += (
                            "\nYour previous response was text. Blue must either call "
                            "the next investigation tool or write a final incident "
                            "report only after confirmed compromise evidence."
                        )
                    continue
                # Agent decided to stop or just sent a message
                self.state.history.append({"role": role, "turn": self.state.turn, "action": "text", "content": action})
                agent.record_turn(observation=state_summary, action="text", output=action)
                self._notify_dashboard("agent_action", {"role": role, "type": "text", "content": action})
                break

            if isinstance(action, list):
                # Agent called tools
                tools_before_batch = tools_called
                for tool_call in action:
                    if tools_called >= self.max_tools_per_turn:
                        break

                    signature = self._tool_call_signature(tool_call)
                    if signature in seen_tool_calls:
                        continue
                    seen_tool_calls.add(signature)

                    # Notify dashboard of tool call
                    self._notify_dashboard("agent_action", {"role": role, "type": "tool", "content": str(tool_call)})

                    if (role == "blue"
                            and tool_call.get("function", {}).get("name") == "remediate_account"
                            and self._remediation_held()):
                        # Blue detected the foothold in time, but its lock is held
                        # for the grace window — stage it instead of executing.
                        output = self._stage_remediation(tool_call)
                    else:
                        output = agent.process_tool_call(tool_call)
                    tools_called += 1
                    self.state.history.append({"role": role, "turn": self.state.turn, "tool": tool_call, "output": output})
                    agent.record_turn(observation=state_summary, action=tool_call, output=output)

                    # Notify dashboard of tool output
                    self._notify_dashboard("battle_log", {"tool": str(tool_call), "output": output})

                    # Graded scoring: record WHEN each side hit its milestone
                    # rather than ending the sim instantly. The outcome is
                    # resolved from the dwell time between the two (below), so
                    # blue gets turns to detect instead of losing the moment
                    # red reads the flag.
                    if role == "red" and TIER_FOOTHOLD not in self.state.red_tiers \
                            and self._check_red_foothold(tool_call, output):
                        self.state.red_tiers[TIER_FOOTHOLD] = self.state.turn
                    if role == "red" and self.state.red_access_turn is None \
                            and self._check_red_victory(output):
                        self.state.red_captured_flag = True
                        self.state.red_access_turn = self.state.turn
                        self.state.red_tiers.setdefault(TIER_ROOT, self.state.turn)
                        self._notify_dashboard("red_objective", {"turn": self.state.turn})
                    if role == "blue" and TIER_FOOTHOLD not in self.state.blue_tier_detect \
                            and self._check_blue_foothold_detect(output):
                        self.state.blue_tier_detect[TIER_FOOTHOLD] = self.state.turn
                        # Reflex: the instant blue's foothold alert fires, strip the
                        # account's escalation path — synchronously, before control
                        # returns to red, so the docker/sudo breakout one command away
                        # is denied. The model is too slow/unreliable to win this race.
                        self._auto_revoke_escalation(output)
                    if role == "blue" and self.state.blue_detect_turn is None \
                            and self._check_blue_victory(output):
                        self.state.blue_detect_turn = self.state.turn
                        self.state.blue_tier_detect.setdefault(TIER_ROOT, self.state.turn)
                        # Blue confirming flag access is itself proof the flag WAS
                        # accessed. If red's access wasn't already recorded (red's
                        # own output didn't surface it), corroborate it now so a
                        # genuine catch resolves as a blue win instead of being
                        # discarded as a no-access false alarm.
                        if self.state.red_access_turn is None:
                            self.state.red_access_turn = self.state.turn
                            self.state.red_tiers.setdefault(TIER_ROOT, self.state.turn)
                        self._notify_dashboard("blue_detection", {"turn": self.state.turn})
                    if role == "blue" and self.state.blue_contain_turn is None:
                        contained_ip = self._check_blue_containment(output)
                        # Only a block of the REAL attacker counts — blocking a
                        # wrong IP doesn't stop red, so it isn't a containment win.
                        if contained_ip and contained_ip == self._attacker_ip():
                            self.state.blue_contain_turn = self.state.turn
                            self.state.contained_ip = contained_ip
                            self._notify_dashboard(
                                "blue_containment",
                                {"turn": self.state.turn, "ip": contained_ip},
                            )
                    if role == "blue" and self.state.blue_remediate_turn is None:
                        remediated_user = self._check_blue_remediation(output)
                        if remediated_user:
                            self.state.blue_remediate_turn = self.state.turn
                            self.state.remediated_user = remediated_user
                            self._notify_dashboard(
                                "blue_remediation",
                                {"turn": self.state.turn, "user": remediated_user},
                            )

                    state_summary += f"\nTool Call: {tool_call['function']['name']} -> Output: {output}"

                if tools_called == tools_before_batch:
                    break

                if text_retries > 0:
                    break

                if tools_called >= self.max_tools_per_turn:
                    break

        # Update Red's performance status for this turn.
        # Red is "stalled" when they made no tool calls this turn.
        # Red is "failing" when they made tool calls but every one produced
        # an error / non-actionable output (permission denied, missing paths,
        # bad syntax, etc.) with no useful reconnaissance result.
        if role == "red":
            if tools_called == 0:
                self.state.red_stalled_turns += 1
            else:
                self.state.red_stalled_turns = 0

            # A "failed turn" = at least one tool call and every tool call's
            # output is an error (per _is_error_output). Useful output resets it.
            had_useful_output = False
            for entry in self.state.history[-tools_called:]:
                out = entry.get("output", "")
                if isinstance(out, str) and out.strip() and not self._is_error_output(out):
                    had_useful_output = True
                    break
            if tools_called > 0 and not had_useful_output:
                self.state.red_failed_turns += 1
            else:
                self.state.red_failed_turns = 0

        # Graded outcome from the access/detection timing (the primary win path).
        outcome = self._resolve_outcome()
        if outcome:
            self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": outcome})
            return outcome

        # Blue wins when red gives up (stalls or only errors for stall_limit
        # turns) — but only when blue is actually defending. See _stall_blue_win.
        if self._stall_blue_win():
            self.state.blue_victory = True
            self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": "blue"})
            return "blue"

        # Rotate turn
        self.state.current_agent_role = "blue" if self.state.current_agent_role == "red" else "red"
        self.state.turn += 1

        return None

    def detection_dwell(self) -> Optional[int]:
        return self.referee.detection_dwell()

    def tier_scoreboard(self) -> List[Dict[str, Any]]:
        return self.referee.tier_scoreboard()

    def verdict(self) -> str:
        return self.referee.verdict()

    def _outcome_brief(self, side: str) -> str:
        """Factual, per-side result of the finished episode, for causal reflection.

        States who won and how (containment/detection turn, access turn) without
        naming *why* a given action was loud — the agent must draw that link
        itself (no hints to red; see the project's 'no seeding' decision).
        """
        s = self.state
        contain, detect, access = s.blue_contain_turn, s.blue_detect_turn, s.red_access_turn

        if s.blue_victory:
            if contain is not None:
                how = f"contained your source IP at turn {contain}, cutting off your access before you reached the objective" \
                    if side == "red" else f"containing the attacker's IP at turn {contain} before it reached the objective"
            else:
                how = f"detected your access at turn {detect}" if side == "red" \
                    else f"detecting the breach at turn {detect}"
            return (f"OUTCOME: You (red) LOST this episode. Blue {how}."
                    if side == "red"
                    else f"OUTCOME: You (blue) WON this episode by {how}.")

        if s.red_captured_flag:
            return (f"OUTCOME: You (red) WON this episode — reached the objective at turn {access}, "
                    f"and blue failed to detect or contain you in time."
                    if side == "red"
                    else f"OUTCOME: You (blue) LOST this episode — red reached the objective at turn {access} "
                    f"and you did not detect or contain it in time.")

        return "OUTCOME: Stalemate — neither side decisively won within the turn limit."

    def _stall_blue_win(self) -> bool:
        """A red stall/failure streak hands blue the win — but only when blue is
        actually defending. In observe mode blue holds containment by design, so
        a red that gives up is a stalemate, not a blue victory (the episode just
        runs out its turns).

        shortcut: in observe this lets a fully-stalled red burn the remaining
        turns rather than ending early; upgrade to an early draw-return if that
        ever wastes meaningful cloud budget.
        """
        if self.observe:
            return False
        return (self.state.red_stalled_turns >= self.stall_limit or
                self.state.red_failed_turns >= self.stall_limit)

    def _resolve_outcome(self) -> Optional[str]:
        return self.referee.resolve_outcome()

    @staticmethod
    def _executor_supports(executor: Any, name: str) -> bool:
        return hasattr(executor, name) and callable(getattr(executor, name))

    def _executors(self) -> List[Any]:
        """Distinct executors to manage: red's target channel, red's attacker
        box (earned foothold), and blue's — de-duplicated by identity (several
        collapse to one for the mock / single-box case)."""
        unique: List[Any] = []
        for ex in (
            self.red_agent.executor,
            getattr(self.red_agent, "attacker_executor", None),
            self.blue_agent.executor,
        ):
            if ex is not None and all(ex is not seen for seen in unique):
                unique.append(ex)
        return unique

    def run_simulation(self, max_turns: int = 20) -> Optional[str]:
        """
        Runs the simulation until a victory condition is met or max_turns is reached.
        """
        # 0. Fresh per-episode agent state (history/foothold/phase). Agents are
        # reused across episodes so their knowledge compounds, but their
        # per-episode state must reset or red skips re-earning its foothold.
        self.red_agent.reset_episode()
        self.blue_agent.reset_episode()

        # 1. Establish connections (best-effort; a stateless executor can skip
        # this). Red and blue may share one executor (mock / single box) or be two
        # (red via the jump host, blue direct); connect each distinct one.
        for ex in self._executors():
            if self._executor_supports(ex, "connect"):
                try:
                    ex.connect()
                except Exception as e:
                    print(f"Failed to establish initial connection: {e}")
                    # Non-fatal — fall back to per-call reconnect in the executor.

        # 1b. Scope BLUE's log analysis to THIS run. Blue reads the target's logs,
        # so the window belongs to blue's executor. Without it, blue reads the
        # box's months-old provisioning history (flag setup, etc.) and declares an
        # instant BREACH before red acts. Anchored to the target's own clock to
        # avoid controller/target skew.
        blue_executor = self.blue_agent.executor
        if self._executor_supports(blue_executor, "mark_analysis_window"):
            try:
                blue_executor.mark_analysis_window()
            except Exception as e:
                print(f"Could not set analysis window (continuing): {e}")

        # 1c. Arm inbound-connection logging so blue can see the attacker's
        # network recon (scanning / service probing), not just post-foothold host
        # signals. Removed at disconnect.
        if self._executor_supports(blue_executor, "enable_connection_logging"):
            try:
                blue_executor.enable_connection_logging()
            except Exception as e:
                print(f"Could not arm connection logging (continuing): {e}")

        # 2. Knowledge is owned by the agents: they loaded (and compacted) their
        # own lessons at construction and persist via reflect() below.

        try:
            for _ in range(max_turns):
                winner = self.step()
                if winner:
                    break

                # Incremental learning: Save state every turn as a backup
                # (Actual lesson summarization happens at the end,
                # but we could add intermediate checkpoints here if desired)
        finally:
            # 3. Always disconnect (best-effort), each distinct executor.
            for ex in self._executors():
                if self._executor_supports(ex, "disconnect"):
                    try:
                        ex.disconnect()
                    except Exception as e:
                        print(f"Warning: executor disconnect failed: {e}")

        # 4. Learn from the battle — each agent reflects on its OWN episode and
        # persists its own lessons (the agent owns its knowledge).
        print("\nSimulation ended. Agents are now reflecting on the battle...")
        red_lesson = self.red_agent.reflect(self._outcome_brief("red"))
        blue_lesson = self.blue_agent.reflect(self._outcome_brief("blue"))
        if red_lesson:
            print(f"Red learned: {red_lesson}")
        if blue_lesson:
            print(f"Blue learned: {blue_lesson}")

        # Horizon reached without an in-loop decision. Blue takes precedence
        # (an in-time detection already set blue_victory); otherwise red wins if
        # it reached the objective at all, since the window went unanswered.
        if self.state.blue_victory: return "blue"
        if self.state.red_captured_flag: return "red"
        return None



    def generate_report(self) -> str:

        """
        Generates a human-readable Markdown report of the simulation history.
        """
        # Blue precedence: red_captured_flag only means red *reached* the
        # objective, not that it won — blue may have detected in time.
        if self.state.blue_victory:
            final_result = "Winner: BLUE"
        elif self.state.red_captured_flag:
            final_result = "Winner: RED"
        else:
            final_result = "No Winner"

        report = []
        report.append("# 🛡️ PurpleLoop Battle Report")
        report.append(f"\n**Final Result:** {final_result}")
        report.append(f"**Total Turns:** {self.state.turn}")

        access = self.state.red_access_turn
        detect = self.state.blue_detect_turn
        report.append(
            f"**Red reached objective:** "
            f"{'turn ' + str(access) if access is not None else 'no'}"
        )
        report.append(
            f"**Blue detected breach:** "
            f"{'turn ' + str(detect) if detect is not None else 'no'}"
        )
        contain = self.state.blue_contain_turn
        report.append(
            f"**Blue contained attacker:** "
            f"{'turn ' + str(contain) + ' (' + str(self.state.contained_ip) + ')' if contain is not None else 'no'}"
        )
        dwell = self.detection_dwell()
        if dwell is not None:
            report.append(
                f"**Detection dwell:** {dwell} turn(s) "
                f"(threshold {self.detect_within_turns})"
            )
        report.append("")
        report.append("## 🎯 Objective Tiers\n")
        report.append(f"**Verdict:** {self.verdict()}\n")
        report.append("| Tier | Red reached | Blue detected | Dwell | Defended |")
        report.append("|------|-------------|---------------|-------|----------|")
        for b in self.tier_scoreboard():
            rr = f"turn {b['reached_turn']}" if b["reached_turn"] is not None else "—"
            bd = f"turn {b['detect_turn']}" if b["detect_turn"] is not None else "—"
            dw = b["dwell"] if b["dwell"] is not None else "—"
            df = "—" if b["defended"] is None else ("yes" if b["defended"] else "no")
            report.append(f"| T{b['tier']} {b['name']} | {rr} | {bd} | {dw} | {df} |")
        report.append("")
        report.append("## 📜 Battle Timeline\n")

        for i, entry in enumerate(self.state.history):
            role = entry['role'].upper()
            if 'tool' in entry:
                tool_name = entry['tool']['function']['name']
                args = entry['tool']['function']['arguments']
                output = entry['output']
                report.append(f"### {role} Action")
                report.append(f"- **Tool:** `{tool_name}`")
                report.append(f"- **Command:** `{args.get('command', 'N/A')}`")
                report.append(f"- **Output:**\n```\n{output}\n```\n")
            else:
                content = entry.get('content', 'No content')
                report.append(f"### {role} Thought")
                report.append(f"\"{content}\"\n")

        return "\n".join(report)
