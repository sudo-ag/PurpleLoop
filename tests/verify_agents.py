import unittest
from unittest.mock import MagicMock
from src.executor import ToolExecutor
from src.agents import Agent

class TestAgents(unittest.TestCase):
    def setUp(self):
        # Mock ToolExecutor to avoid needing a real SSH host
        self.mock_executor = MagicMock(spec=ToolExecutor)
        self.mock_executor.execute.side_effect = lambda cmd: f"Mock output for: {cmd}"

    def test_red_agent_nmap(self):
        # Use qwen2.5-coder:7b as it's available in the environment
        agent = Agent(role="red", executor=self.mock_executor, model="qwen2.5-coder:7b")
        state = "Perform a reconnaissance scan on 192.168.1.1"

        result = agent.act(state)

        self.assertIsInstance(result, list, "Red agent should have returned tool calls")
        tool_call = result[0]
        self.assertEqual(tool_call['function']['name'], 'execute_command')

        command = tool_call['function']['arguments'].get('command', '')
        self.assertIn('nmap', command.lower(), f"Red agent should have called nmap, but called: {command}")

        # Verify process_tool_call
        output = agent.process_tool_call(tool_call)
        self.assertIn("Mock output for:", output)
        self.mock_executor.execute.assert_called()

    def test_blue_agent_ls(self):
        # Use qwen2.5-coder:7b as it's available in the environment
        agent = Agent(role="blue", executor=self.mock_executor, model="qwen2.5-coder:7b")
        state = "List the files in /var/log to check for suspicious activity"

        result = agent.act(state)

        self.assertIsInstance(result, list, "Blue agent should have returned tool calls")
        tool_call = result[0]
        self.assertEqual(tool_call['function']['name'], 'execute_command')

        command = tool_call['function']['arguments'].get('command', '')
        self.assertIn('ls', command.lower(), f"Blue agent should have called ls, but called: {command}")

        # Verify process_tool_call
        output = agent.process_tool_call(tool_call)
        self.assertIn("Mock output for:", output)
        self.mock_executor.execute.assert_called()

if __name__ == "__main__":
    unittest.main()
