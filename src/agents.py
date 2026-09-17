import ollama
from typing import Union, Dict, Any, List, Optional
from src.executor import ToolExecutor

# System Prompts
RED_SYSTEM_PROMPT = """You are a Red Team operator. Your goal is to perform reconnaissance,
exploit vulnerabilities, and capture the flag (CTF).
The flag is typically located in a file named 'flag.txt' in the /root directory.
You MUST use the `execute_command` tool to run shell commands on the target.
Do not explain your actions in text if you are calling a tool.
Be stealthy, efficient, and methodical. Use tools like 'ls', 'cat', 'grep', and 'find' to locate and read the flag.
IMPORTANT: If a command returns 'Permission denied' or 'No such file or directory', do NOT repeat the same command. Pivot your strategy, try a different path, or seek a way to escalate privileges.
"""

BLUE_SYSTEM_PROMPT = """You are a Blue Team operator. Your goal is to monitor the system,
detect attack patterns, and mitigate threats.
Common attack indicators include unusual processes, failed login attempts in /var/log/auth.log,
and unauthorized access to sensitive files like /root/flag.txt.
You MUST use the `execute_command` tool to run shell commands on the target.
Do not explain your actions in text if you are calling a tool.
Focus on log analysis, process monitoring, and system hardening. Use tools like 'grep', 'ps', 'netstat', and 'lastlog'.
"""

class Agent:
    def __init__(self, role: str, executor: ToolExecutor, model: str = "llama3.1", experience: List[str] = None):
        self.role = role
        self.executor = executor
        self.model = model
        self.experience = experience or []
        self.system_prompt = RED_SYSTEM_PROMPT if role.lower() == "red" else BLUE_SYSTEM_PROMPT


        # Define the tools available to the agent
        self.tools = [
            {
                'type': 'function',
                'function': {
                    'name': 'execute_command',
                    'description': 'Execute a shell command on the target host',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'command': {
                                'type': 'string',
                                'description': 'The shell command to run',
                            },
                        },
                        'required': ['command'],
                    },
                },
            },
        ]

    def act(self, state: str) -> Union[Dict[str, Any], str]:
        """
        Processes the current state and returns either a tool call or a text response.
        """
        system_content = self.system_prompt
        if self.experience:
            experience_str = "\n\nPrevious Experience:\n- " + "\n- ".join(self.experience)
            system_content += experience_str

        messages = [
            {'role': 'system', 'content': system_content},
            {'role': 'user', 'content': state},
        ]


        response = ollama.chat(
            model=self.model,
            messages=messages,
            tools=self.tools,
        )

        message = response['message']

        if message.get('tool_calls'):
            return message['tool_calls']

        content = message.get('content', "")
        # Fallback: try to parse JSON if the model returned it as text
        if content:
            import json
            try:
                # Remove markdown code blocks if present
                cleaned_content = content.replace('```json', '').replace('```', '').strip()
                data = json.loads(cleaned_content)
                if isinstance(data, dict) and 'name' in data and 'arguments' in data:
                    return [{'function': data}]
            except Exception:
                pass

        return content

    def process_tool_call(self, tool_call: Dict[str, Any]) -> str:
        """
        Processes a single tool call by executing the command via ToolExecutor.
        """
        if tool_call['function']['name'] == 'execute_command':
            command = tool_call['function']['arguments'].get('command')
            if command:
                try:
                    return self.executor.execute(command)
                except Exception as e:
                    return f"Error executing command: {str(e)}"

        return "Unsupported tool call."

    def summarize_experience(self, history: List[Dict[str, Any]]) -> Optional[str]:
        """
        Analyzes the simulation history and returns a single concise lesson learned.
        """
        history_str = "\n".join([
            f"{h.get('role', 'unknown')}: {h.get('tool', h.get('action', ''))} -> {h.get('output', h.get('content', ''))}"
            for h in history
        ])

        prompt = f"Analyze this battle history:\n\n{history_str}\n\nWhat is the single most important lesson learned from this simulation that you should remember for next time? Provide only the lesson as a short, one-sentence bullet point. Do not include preamble."

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}]
            )
            return response['message'].get('content', "").strip()
        except Exception as e:
            print(f"Error summarizing experience: {e}")
            return None

