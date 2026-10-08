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
_BLUE_TOOL_PRIORITY = [
    "investigate_logs",
    "investigate_file_access",
    "investigate_processes",
    "investigate_users",
    "investigate_cron",
    "investigate_network",
]


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

class Orchestrator:
    def __init__(self, red_agent: Agent, blue_agent: Agent, max_tools_per_turn: int = 3, stall_limit: int = 5, flag_path: str = "/root/flag.txt", dashboard_url: Optional[str] = None, knowledge_file: str = "knowledge.json"):
        self.red_agent = red_agent
        self.blue_agent = blue_agent
        self.max_tools_per_turn = max_tools_per_turn
        self.stall_limit = stall_limit
        self.flag_path = flag_path
        self.dashboard_url = dashboard_url
        self.knowledge_file = knowledge_file
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
        # Simple check: if the output of a command contains the flag
        # In a real scenario, we might check for a specific regex or the content of flag_path
        # For this implementation, we check if the output looks like a flag (e.g., "FLAG{...}")
        # or if it's the result of reading flag_path.
        if "FLAG{" in output:
            return True
        return False

    def _check_blue_victory(self, output: str) -> bool:
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
        if data.get("assessment") == "BREACH":
            return True
        if data.get("flag_access_detected") is True:
            return True
        if data.get("suspicious_count", 0) > 0 and (
            data.get("tool") == "investigate_file_access"
            or data.get("file_path") == self.flag_path
        ):
            return True
        if data.get("critical_events", 0) > 0 or data.get("critical_count", 0) > 0:
            return True
        summary = str(data.get("summary", "")).lower()
        return (
            "sensitive file was accessed" in summary
            or "flag file access detected" in summary
            or "confirmed compromise" in summary
        )

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
        """Return True when a command's output is clearly an error / non-actionable."""
        lowered = output.lower()
        for pattern in self._RED_ERROR_PATTERNS:
            if pattern in lowered:
                return True
        return False

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

    def _blue_tool_guidance(self) -> str:
        used = self._blue_tools_used()
        used_set = set(used)
        next_tool = next((t for t in _BLUE_TOOL_PRIORITY if t not in used_set), None)
        guidance = (
            "You are the blue defender. Vary your investigation — do not repeat a "
            "tool you have already run this battle."
        )
        if next_tool:
            guidance += (
                f" Call `{next_tool}` next. `investigate_logs` and "
                f"`investigate_file_access` are the only tools that reveal flag-file "
                f"access, so reach them early to confirm a breach."
            )
        else:
            guidance += (
                " You have run every investigation tool. If any returned a BREACH or "
                "flag_access_detected, write your final incident report now."
            )
        if used:
            guidance += f" Already run: {', '.join(dict.fromkeys(used))}."
        return f"Blue guidance: {guidance}"

    def _build_state_summary(self, role: str) -> str:
        state_summary = (
            f"Turn {self.state.turn}. Current Role: {role}. "
            f"History: {self.state.history[-5:]}"
        )
        if role == "red":
            state_summary += f"\n{self._red_phase_guidance()}"
        elif role == "blue":
            state_summary += f"\n{self._blue_tool_guidance()}"
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
                self.state.history.append({"role": role, "action": "text", "content": action})
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
                    self.state.history.append({"role": role, "tool": tool_call, "output": output})

                    # Notify dashboard of tool output
                    self._notify_dashboard("battle_log", {"tool": str(tool_call), "output": output})

                    if role == "red" and self._check_red_victory(output):
                        self.state.red_captured_flag = True
                        self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": "red"})
                        return "red"
                    if role == "blue" and self._check_blue_victory(output):
                        self.state.blue_victory = True
                        self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": "blue"})
                        return "blue"

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

        # Blue victory conditions (two ways to win):
        # 1. Red is stalled (no tool calls) for stall_limit consecutive turns.
        # 2. Red is failing — repeatedly making tool calls that all produce
        #    errors / non-actionable output — for fail_limit consecutive turns.
        #    This models blue having effectively contained / denied red's activity.
        if self.state.red_stalled_turns >= self.stall_limit or \
           self.state.red_failed_turns >= self.stall_limit:
            self.state.blue_victory = True
            self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": "blue"})
            return "blue"

        # Rotate turn
        self.state.current_agent_role = "blue" if self.state.current_agent_role == "red" else "red"
        self.state.turn += 1

        return None

    def _executor_supports(self, name: str) -> bool:
        return hasattr(self.red_agent.executor, name) and callable(getattr(self.red_agent.executor, name))

    def run_simulation(self, max_turns: int = 20) -> Optional[str]:
        """
        Runs the simulation until a victory condition is met or max_turns is reached.
        """
        # 1. Establish persistent connection (best-effort; a stateless executor can skip this)
        if self._executor_supports("connect"):
            try:
                self.red_agent.executor.connect()
            except Exception as e:
                print(f"Failed to establish initial connection: {e}")
                # Non-fatal for the sim — fall back to per-call reconnect behavior in the executor.

        # 1b. Scope blue's log analysis to THIS run. Without it, blue reads the
        # box's months-old provisioning history (flag setup, etc.) and declares
        # an instant BREACH before red acts. Anchored to the target's own clock
        # to avoid controller/target skew.
        if self._executor_supports("mark_analysis_window"):
            try:
                self.red_agent.executor.mark_analysis_window()
            except Exception as e:
                print(f"Could not set analysis window (continuing): {e}")

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
            # 3. Always disconnect (best-effort)
            if self._executor_supports("disconnect"):
                try:
                    self.red_agent.executor.disconnect()
                except Exception as e:
                    print(f"Warning: executor disconnect failed: {e}")

        # 4. Learn from the battle
        print("\nSimulation ended. Agents are now reflecting on the battle...")
        red_history = [h for h in self.state.history if h.get("role") == "red"]
        blue_history = [h for h in self.state.history if h.get("role") == "blue"]
        red_lesson = self.red_agent.summarize_experience(red_history)
        blue_lesson = self.blue_agent.summarize_experience(blue_history)

        if red_lesson:
            knowledge["red"].append(red_lesson)
            print(f"Red learned: {red_lesson}")
        if blue_lesson:
            knowledge["blue"].append(blue_lesson)
            print(f"Blue learned: {blue_lesson}")

        # 5. Save updated knowledge
        self._save_knowledge(knowledge)

        # Return the winner (if any)
        if self.state.red_captured_flag: return "red"
        if self.state.blue_victory: return "blue"
        return None



    def generate_report(self) -> str:

        """
        Generates a human-readable Markdown report of the simulation history.
        """
        if self.state.red_captured_flag:
            final_result = "Winner: RED"
        elif self.state.blue_victory:
            final_result = "Winner: BLUE"
        else:
            final_result = "No Winner"

        report = []
        report.append("# 🛡️ PurpleLoop Battle Report")
        report.append(f"\n**Final Result:** {final_result}")
        report.append(f"**Total Turns:** {self.state.turn}\n")
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
