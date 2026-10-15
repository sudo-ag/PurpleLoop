from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import requests
import json
import os
import re
from src.agents import Agent


_RED_PHASE_GUIDANCE = {
    "initial_enum": (
        "Next objective: establish context with one compact enum command, then move on. "
        "Good choices: `whoami; id; uname -a; hostname; pwd`."
    ),
    "flag_discovery": (
        "Next objective: locate flag.txt. Use `find / -maxdepth 4 -name flag.txt "
        "-print 2>/dev/null` or check common dirs. Do not repeat whoami/id."
    ),
    "privilege_check": (
        "Next objective: get a usable privilege path. Try `sudo -n -l`, then SUID "
        "and cron checks if sudo is unavailable."
    ),
}

# Blue steers through its investigation tools in this order. The first two are
# the only tools that surface flag-file access (the breach signal), so they
# lead; the rest give context. Blue is nudged toward the first tool it has not
# run yet, which stops the 3B model from repeating one tool every turn.
# A source with at least this many failed SSH auths in the window is brute-forcing
# (evidence of malice), not just connecting.
_BRUTE_FORCE_THRESHOLD = 5

_BLUE_TOOL_PRIORITY = [
    "investigate_logs",
    "investigate_connections",
    "investigate_file_access",
    "investigate_processes",
    "investigate_users",
    "investigate_cron",
    "investigate_network",
]

# Graded objective tiers (realistic rubric). Red climbs these; blue defends each
# with a matching sensor. T2 (data/credential exfil) is declared but INERT until
# the web/DB exfil sensor lands — nothing records its slots yet.
TIER_FOOTHOLD = 1   # red authenticated an interactive, non-admin foothold
TIER_EXFIL = 2      # red exfiltrated data/credentials (e.g. payroll DB via SQLi)
TIER_ROOT = 3       # red read the root flag (the legacy top objective)
TIERS = (TIER_FOOTHOLD, TIER_EXFIL, TIER_ROOT)
TIER_NAMES = {TIER_FOOTHOLD: "foothold", TIER_EXFIL: "exfil", TIER_ROOT: "root"}


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
    red_tiers: Dict[int, int] = field(default_factory=dict)        # tier -> turn red first reached it
    blue_tier_detect: Dict[int, int] = field(default_factory=dict) # tier -> turn blue first detected it

class Orchestrator:
    def __init__(self, red_agent: Agent, blue_agent: Agent, max_tools_per_turn: int = 3, stall_limit: int = 5, flag_path: str = "/root/flag.txt", detect_within_turns: int = 3, dashboard_url: Optional[str] = None, knowledge_file: str = "knowledge.json", observe: bool = False):
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
        self.state = SimulationState()


    def _notify_dashboard(self, event_type: str, data: Dict[str, Any]):
        if self.dashboard_url:
            try:
                requests.post(f"{self.dashboard_url}/update", json={"event_type": event_type, "data": data}, timeout=1.0)
            except Exception:
                pass # Don't let dashboard failures stop simulation

    def _load_knowledge(self) -> Dict[str, List[str]]:
        if not os.path.exists(self.knowledge_file):
            return {"red": [], "blue": []}
        try:
            with open(self.knowledge_file, "r") as f:
                return json.load(f)
        except Exception:
            return {"red": [], "blue": []}

    def _save_knowledge(self, knowledge: Dict[str, List[str]]):
        try:
            with open(self.knowledge_file, "w") as f:
                json.dump(knowledge, f, indent=4)
        except Exception as e:
            print(f"Error saving knowledge: {e}")

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

    def _red_tool_history(self) -> List[Dict[str, Any]]:
        return [
            entry
            for entry in self.state.history
            if entry.get("role") == "red" and "tool" in entry
        ]

    def _red_commands(self) -> List[str]:
        commands = []
        for entry in self._red_tool_history():
            tool = entry.get("tool", {})
            function = tool.get("function", {})
            arguments = function.get("arguments", {})
            command = arguments.get("command")
            if isinstance(command, str):
                commands.append(command)
        return commands

    def _discovered_flag_paths(self) -> List[str]:
        paths = []
        seen = set()
        for entry in self._red_tool_history():
            output = str(entry.get("output", ""))
            command = ""
            tool = entry.get("tool", {})
            function = tool.get("function", {})
            arguments = function.get("arguments", {})
            if isinstance(arguments.get("command"), str):
                command = arguments["command"]
            for text in (command, output):
                for path in re.findall(r"/[A-Za-z0-9_./-]*flag\.txt", text):
                    if path not in seen:
                        paths.append(path)
                        seen.add(path)
        return paths

    def _root_available(self) -> bool:
        """True once red has confirmed a passwordless-root path from sudo -l.

        Metasploitable3's vagrant user carries `(ALL : ALL) NOPASSWD: ALL`, so
        the moment that shows up red can read the flag directly with sudo — it
        does not need `find` to succeed first.
        """
        for entry in self._red_tool_history():
            output = str(entry.get("output", "")).lower()
            if "nopasswd" in output or "(all" in output:
                return True
        return False

    def _update_red_phase(self) -> None:
        commands = self._red_commands()
        outputs = [str(entry.get("output", "")) for entry in self._red_tool_history()]
        combined = "\n".join(commands + outputs).lower()

        if self._discovered_flag_paths() or self._root_available():
            self.state.red_phase = "flag_read"
            return
        if "permission denied" in combined or "sudo -l" in combined or "sudo -n -l" in combined:
            self.state.red_phase = "privilege_check"
            return
        if any("find" in command.lower() and "flag.txt" in command.lower() for command in commands):
            self.state.red_phase = "privilege_check"
            return
        if len(commands) >= 2 or any("uid=" in output.lower() for output in outputs):
            self.state.red_phase = "flag_discovery"
            return
        self.state.red_phase = "initial_enum"

    def _red_phase_guidance(self) -> str:
        self._update_red_phase()
        phase = self.state.red_phase
        if phase == "flag_read":
            return f"Red Phase: {phase}. {self._flag_read_guidance()}"
        return f"Red Phase: {phase}. {_RED_PHASE_GUIDANCE[phase]}"

    def _flag_read_guidance(self) -> str:
        paths = self._discovered_flag_paths()
        target = paths[0] if paths else self.flag_path
        if self._root_available():
            guidance = (
                f"Next objective: you have confirmed passwordless root. READ THE FLAG "
                f"NOW with `sudo cat {target}`. Stop enumerating — one command wins."
            )
        else:
            guidance = (
                f"Next objective: read the flag at {target}. Try `cat {target}`; if "
                f"permission denied, try `sudo cat {target}`."
            )
        if paths:
            guidance += f" Discovered path(s): {', '.join(paths)}."
        return guidance

    def _blue_tools_used(self) -> List[str]:
        used = []
        for entry in self.state.history:
            if entry.get("role") != "blue" or "tool" not in entry:
                continue
            name = entry.get("tool", {}).get("function", {}).get("name", "")
            if name:
                used.append(name)
        return used

    def _blue_confirmed_attackers(self) -> List[str]:
        """Attacker IPs blue has EVIDENCE OF MALICE for in its own tool output —
        a port scan, a brute-force spike, or a confirmed flag access — not merely
        a foreign connection. Excludes blue's own control IP. Containing on mere
        presence is trivial in a two-box setup; blue must earn it with evidence.
        """
        own = getattr(getattr(self.blue_agent, "executor", None), "control_source_ip", None)
        confirmed: List[str] = []

        def add(ips):
            for ip in ips or []:
                if ip and ip != own and ip not in confirmed:
                    confirmed.append(ip)

        for entry in self.state.history:
            if entry.get("role") != "blue":
                continue
            out = entry.get("output", "")
            if not isinstance(out, str):
                continue
            try:
                data = json.loads(out)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            tool = data.get("tool")
            if tool == "investigate_connections":
                add(data.get("port_scanners"))                     # scanning = malice
            elif tool == "investigate_logs":
                if (data.get("failed_attempts") or 0) >= _BRUTE_FORCE_THRESHOLD:
                    add(data.get("suspicious_ips"))                # brute-force spike
                if data.get("flag_access_detected"):
                    add(data.get("suspicious_ips"))                # confirmed breach
        return confirmed

    def _blue_tool_guidance(self) -> str:
        # Once blue has EVIDENCE of malice from an attacker IP (a scan, a
        # brute-force, or a confirmed breach), give it a direct containment order —
        # the model otherwise narrates the finding instead of acting. A bare
        # foreign connection is NOT enough; blue must catch an actual attack.
        if not self.observe and self.state.blue_contain_turn is None:
            attackers = self._blue_confirmed_attackers()
            if attackers:
                ip = attackers[0]
                return (
                    f"Blue guidance: You have EVIDENCE of an attack from {ip} (a port "
                    f"scan, brute-force, or confirmed access — not just a connection). "
                    f"Stop investigating and CONTAIN it now: call `contain_attacker` with "
                    f"ip=\"{ip}\". Containing the attacker before it reaches its objective "
                    f"wins the engagement. Do this before any other tool."
                )

        used = self._blue_tools_used()
        last = used[-1] if used else None
        # `investigate_logs` is the ONLY reliable flag-read detector, and the read
        # can land on any turn, so it is blue's heartbeat: run it almost every turn.
        # The only time we steer elsewhere is right after a logs check, to cover one
        # breadth tool (or confirm via file-access) before returning to logs. This
        # keeps the reliable detector re-checked within red's breach window instead
        # of being drowned out by a slow one-pass sweep.
        guidance = "You are the blue defender."
        if last != "investigate_logs":
            guidance += (
                " Call `investigate_logs` now. It is the only tool that reliably reveals a "
                "flag read, the read can happen on ANY turn, so you re-run it almost every "
                "turn as your primary check. Do NOT declare the system clean or write a "
                "report off a quiet earlier sweep — a breach can occur after you looked. "
                "Only write the incident report once a tool returns a BREACH / "
                "flag_access_detected."
            )
        else:
            # Just checked logs — cover one breadth tool this turn. Pick the
            # least-recently-used breadth tool so blue keeps rotating instead of
            # sticking on one once every tool has been tried at least once.
            breadth = [t for t in _BLUE_TOOL_PRIORITY if t != "investigate_logs"]
            last_use = {t: i for i, t in enumerate(used)}  # most recent index wins
            next_breadth = min(breadth, key=lambda t: last_use.get(t, -1))
            guidance += (
                f" You just checked the logs. Use this turn for breadth — call `{next_breadth}` "
                f"— then go back to `investigate_logs` next turn to stay on watch."
            )
        if used:
            guidance += f" Already run: {', '.join(dict.fromkeys(used))}."
        return f"Blue guidance: {guidance}"

    def _repeat_nudge(self, role: str) -> str:
        """Nudge an agent that spent its whole last turn re-issuing tool calls it
        had already tried, with no new action — the loop both sides fell into.
        Blue's `investigate_logs` heartbeat is excluded: it is meant to repeat.
        """
        exclude = {"investigate_logs"} if role == "blue" else set()
        entries = []  # (turn, sig, label, out) for this role's tool calls, in order
        for entry in self.state.history:
            if entry.get("role") != role or "tool" not in entry:
                continue
            fn = entry.get("tool", {}).get("function", {})
            name = fn.get("name", "")
            if not name or name in exclude:
                continue
            args = fn.get("arguments", {}) or {}
            sig = name + ":" + json.dumps(args, sort_keys=True, default=str)
            cmd = args.get("command") if isinstance(args, dict) else None
            label = f"`{cmd}`" if isinstance(cmd, str) else f"`{name}` {args}"
            out = str(entry.get("output", "")).strip().replace("\n", " ")
            entries.append((entry.get("turn"), sig, label, out))
        if len(entries) < 2:
            return ""
        last_turn = entries[-1][0]
        last = [e for e in entries if e[0] == last_turn]
        earlier = {e[1] for e in entries if e[0] != last_turn}
        if not last or any(e[1] not in earlier for e in last):
            return ""  # nothing done, or at least one genuinely new action — not looping
        tried = list(dict.fromkeys(f"{label} -> {out[:80]}" for _, _, label, out in last))
        return (
            "\nRepetition check: last turn you only repeated actions you had already "
            f"tried ({'; '.join(tried)}) with no new result. Stop repeating these — "
            "try a genuinely different approach."
        )

    def _build_state_summary(self, role: str) -> str:
        state_summary = (
            f"Turn {self.state.turn}. Current Role: {role}. "
            f"History: {self.state.history[-5:]}"
        )
        if role == "red":
            state_summary += f"\n{self._red_phase_guidance()}"
        elif role == "blue":
            state_summary += f"\n{self._blue_tool_guidance()}"
        state_summary += self._repeat_nudge(role)
        return state_summary

    def step(self) -> Optional[str]:
        """
        Performs one turn of the simulation.
        Returns the winner if the simulation ends, otherwise None.
        """
        agent = self.get_current_agent()
        role = self.state.current_agent_role

        # Notify dashboard of turn start
        self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": None})

        # Construct current state for the agent
        state_summary = self._build_state_summary(role)

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

                    output = agent.process_tool_call(tool_call)
                    tools_called += 1
                    self.state.history.append({"role": role, "turn": self.state.turn, "tool": tool_call, "output": output})

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
        """Turns between red reaching the objective and blue detecting it.

        None if either milestone is missing. Negative means blue flagged the
        intrusion before red completed it (an early catch).
        """
        if self.state.red_access_turn is None or self.state.blue_detect_turn is None:
            return None
        return self.state.blue_detect_turn - self.state.red_access_turn

    def tier_scoreboard(self) -> List[Dict[str, Any]]:
        """Per-tier graded result: for each objective tier, whether red reached
        it and whether blue defended it (detected within the dwell window, or
        contained the attacker at/before that tier). `defended` is None for a
        tier red never reached (no attack to defend)."""
        contain = self.state.blue_contain_turn
        board: List[Dict[str, Any]] = []
        for tier in TIERS:
            reached = self.state.red_tiers.get(tier)
            detect = self.state.blue_tier_detect.get(tier)
            dwell = (detect - reached) if (reached is not None and detect is not None) else None
            if reached is None:
                defended: Optional[bool] = None
            else:
                contained_first = contain is not None and contain <= reached
                in_time = detect is not None and reached <= detect <= reached + self.detect_within_turns
                defended = bool(contained_first or in_time)
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
        """Decide the graded winner from access/detection timing, or None.

        BLUE if it detected the breach at or before red's access, or within
        detect_within_turns of it. RED once red has accessed and that detection
        window has fully elapsed with no (in-time) catch. None while the window
        is still open.
        """
        access = self.state.red_access_turn
        detect = self.state.blue_detect_turn
        contain = self.state.blue_contain_turn

        # Prevention beats detection: if blue firewalled the attacker before it
        # reached the objective, the attack is stopped and blue wins. (Containment
        # physically blocks red, so access normally stays None once this fires.)
        if contain is not None and (access is None or contain <= access):
            self.state.blue_victory = True
            return "blue"

        # Blue wins only by catching a REAL breach in time. A detection with no
        # actual red access (access is None) is a false alarm, not a win — blue
        # cannot win by crying wolf. A detection strictly before red's access
        # (detect < access) likewise can't be a catch of a breach that had not
        # happened yet, so the catch must fall in [access, access + K].
        if (
            access is not None
            and detect is not None
            and access <= detect <= access + self.detect_within_turns
        ):
            self.state.blue_victory = True
            return "blue"

        if access is not None and self.state.turn - access > self.detect_within_turns:
            # Red reached the objective and blue missed the detection window.
            return "red"

        return None

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

        # 2. Load long-term knowledge
        knowledge = self._load_knowledge()
        self.red_agent.experience = knowledge.get("red", [])
        self.blue_agent.experience = knowledge.get("blue", [])

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

        # 4. Learn from the battle
        print("\nSimulation ended. Agents are now reflecting on the battle...")
        red_history = [h for h in self.state.history if h.get("role") == "red"]
        blue_history = [h for h in self.state.history if h.get("role") == "blue"]
        red_lesson = self.red_agent.summarize_experience(red_history, self._outcome_brief("red"))
        blue_lesson = self.blue_agent.summarize_experience(blue_history, self._outcome_brief("blue"))

        if red_lesson:
            knowledge["red"].append(red_lesson)
            print(f"Red learned: {red_lesson}")
        if blue_lesson:
            knowledge["blue"].append(blue_lesson)
            print(f"Blue learned: {blue_lesson}")

        # 5. Save updated knowledge
        self._save_knowledge(knowledge)

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
