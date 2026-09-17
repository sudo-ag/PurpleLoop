from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import requests
import json
import os
from src.agents import Agent


@dataclass
class SimulationState:
    turn: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)
    red_captured_flag: bool = False
    blue_victory: bool = False
    current_agent_role: str = "red"
    red_stalled_turns: int = 0

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
        state_summary = f"Turn {self.state.turn}. Current Role: {role}. History: {self.state.history[-5:]}"

        tools_called = 0
        while tools_called < self.max_tools_per_turn:
            action = agent.act(state_summary)

            if isinstance(action, str):
                # Agent decided to stop or just sent a message
                self.state.history.append({"role": role, "action": "text", "content": action})
                self._notify_dashboard("agent_action", {"role": role, "type": "text", "content": action})
                break

            if isinstance(action, list):
                # Agent called tools
                for tool_call in action:
                    tools_called += 1
                    if tools_called > self.max_tools_per_turn:
                        break

                    # Notify dashboard of tool call
                    self._notify_dashboard("agent_action", {"role": role, "type": "tool", "content": str(tool_call)})

                    output = agent.process_tool_call(tool_call)
                    self.state.history.append({"role": role, "tool": tool_call, "output": output})

                    # Notify dashboard of tool output
                    self._notify_dashboard("battle_log", {"tool": str(tool_call), "output": output})

                    if role == "red" and self._check_red_victory(output):
                        self.state.red_captured_flag = True
                        self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": "red"})
                        return "red"

                    state_summary += f"\nTool Call: {tool_call['function']['name']} -> Output: {output}"

                if tools_called >= self.max_tools_per_turn:
                    break

        # Update stall status for Red
        if role == "red":
            # Red is considered stalled if they didn't make any tool calls or didn't change their behavior
            # For simplicity, if they didn't call any tools, they are stalled
            if tools_called == 0:
                self.state.red_stalled_turns += 1
            else:
                self.state.red_stalled_turns = 0

        if self.state.red_stalled_turns >= self.stall_limit:
            self.state.blue_victory = True
            self._notify_dashboard("turn_update", {"turn": self.state.turn, "winner": "blue"})
            return "blue"

        # Rotate turn
        self.state.current_agent_role = "blue" if self.state.current_agent_role == "red" else "red"
        self.state.turn += 1

        return None

    def run_simulation(self, max_turns: int = 20) -> Optional[str]:
        """
        Runs the simulation until a victory condition is met or max_turns is reached.
        """
        # 1. Establish persistent connection
        try:
            self.red_agent.executor.connect()
        except Exception as e:
            print(f"Failed to establish initial connection: {e}")
            return None

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
            # 3. Always disconnect
            self.red_agent.executor.disconnect()

        # 4. Learn from the battle
        print("\nSimulation ended. Agents are now reflecting on the battle...")
        red_lesson = self.red_agent.summarize_experience(self.state.history)
        blue_lesson = self.blue_agent.summarize_experience(self.state.history)

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
        report = []
        report.append("# 🛡️ PurpleLoop Battle Report")
        report.append(f"\n**Final Result:** {('Winner: ' + self.state.current_agent_role.upper() if self.state.red_captured_flag or self.state.blue_victory else 'No Winner')}")
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
