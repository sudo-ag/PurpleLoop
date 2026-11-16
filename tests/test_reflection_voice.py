"""Reflection prompts are anchored to the agent's own side (audit item #8)."""
from unittest.mock import MagicMock

from src.agents import Agent


def _agent(role: str) -> Agent:
    a = Agent(role=role, executor=MagicMock())
    a.client = MagicMock()
    a.client.chat.return_value = {"message": {"content": "a lesson"}}
    return a


def _prompt_sent(agent: Agent) -> str:
    return agent.client.chat.call_args.kwargs["messages"][0]["content"]


def test_red_reflection_prompt_frames_offense_and_forbids_defense():
    red = _agent("red")
    red.summarize_experience([{"role": "red", "tool": "nmap", "output": "contained"}],
                             outcome="OUTCOME: You (red) LOST this episode.")
    p = _prompt_sent(red)
    assert "RED attacker" in p and "YOUR OWN OFFENSE" in p
    assert "Never give defensive advice" in p


def test_blue_reflection_prompt_frames_defense():
    blue = _agent("blue")
    blue.summarize_experience([{"role": "blue", "tool": "investigate_logs", "output": "clean"}],
                              outcome="OUTCOME: You (blue) WON this episode.")
    p = _prompt_sent(blue)
    assert "BLUE defender" in p and "YOUR OWN DEFENSE" in p


def test_perspective_present_without_outcome_too():
    red = _agent("red")
    red.summarize_experience([{"role": "red", "tool": "nmap", "output": "x"}])
    assert "RED attacker" in _prompt_sent(red)


def test_reflection_prompt_demands_transferable_rule_with_outcome():
    # A lesson carrying this box's accounts/IPs/versions does not transfer to a
    # new environment and invites hallucination there. The prompt must require a
    # role-based, transferable rule.
    for role in ("red", "blue"):
        agent = _agent(role)
        agent.summarize_experience(
            [{"role": role, "tool": "x", "output": "y"}],
            outcome="OUTCOME: You (%s) WON this episode." % role,
        )
        p = _prompt_sent(agent)
        assert "TRANSFERABLE RULE" in p, role
        assert "never by a specific value" in p, role


def test_reflection_prompt_demands_transferable_rule_without_outcome():
    blue = _agent("blue")
    blue.summarize_experience([{"role": "blue", "tool": "investigate_logs", "output": "clean"}])
    p = _prompt_sent(blue)
    assert "TRANSFERABLE RULE" in p
