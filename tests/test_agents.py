from unittest.mock import MagicMock
from src.agents import Agent, RED_EVASION_ADDENDUM, RED_EARNED_ADDENDUM, _coerce_text_tool_call


def test_recovers_parameters_key_format():
    # The exact live failure: model emitted its tool call as text with a
    # "parameters" key, which the old parser rejected and dropped as a thought.
    call = _coerce_text_tool_call('{"name": "investigate_users", "parameters": {}}')
    assert call == {"function": {"name": "investigate_users", "arguments": {}}}


def test_recovers_arguments_key_format():
    call = _coerce_text_tool_call('{"name": "execute_command", "arguments": {"command": "whoami"}}')
    assert call == {"function": {"name": "execute_command", "arguments": {"command": "whoami"}}}


def test_recovers_no_args_tool_without_args_key():
    call = _coerce_text_tool_call('{"name": "investigate_processes"}')
    assert call == {"function": {"name": "investigate_processes", "arguments": {}}}


def test_unwraps_function_and_list_wrappers():
    assert _coerce_text_tool_call('[{"function": {"name": "investigate_logs", "parameters": {}}}]') == {
        "function": {"name": "investigate_logs", "arguments": {}}
    }


def test_tolerates_markdown_fences():
    call = _coerce_text_tool_call('```json\n{"name": "investigate_logs"}\n```')
    assert call == {"function": {"name": "investigate_logs", "arguments": {}}}


def test_plain_text_is_not_a_tool_call():
    assert _coerce_text_tool_call("I have completed my investigation. No breach found.") is None


def test_invalid_json_returns_none():
    assert _coerce_text_tool_call('{"name": "investigate_logs", ') is None


def test_json_without_name_returns_none():
    assert _coerce_text_tool_call('{"summary": "all clear"}') is None


def test_multi_element_list_is_rejected():
    assert _coerce_text_tool_call('[{"name": "a"}, {"name": "b"}]') is None


# --- red defense-evasion toggle -------------------------------------------


def _mk(role, evade=False):
    return Agent(role=role, executor=MagicMock(), model="test-model", evade=evade)


def test_red_evasion_addendum_present_only_when_enabled():
    assert RED_EVASION_ADDENDUM.strip()[:1] != ""  # non-empty
    assert RED_EVASION_ADDENDUM not in _mk("red", evade=False).system_prompt
    assert RED_EVASION_ADDENDUM in _mk("red", evade=True).system_prompt


def test_blue_never_gets_evasion_even_if_flag_set():
    blue = _mk("blue", evade=True)
    assert blue.evade is False
    assert RED_EVASION_ADDENDUM not in blue.system_prompt


# --- red earned foothold (two-channel) ------------------------------------


def test_earned_red_gets_attacker_channel_and_addendum():
    atk = MagicMock()
    red = Agent(role="red", executor=MagicMock(), model="m", earned=True, attacker_executor=atk)
    assert red.earned is True
    assert red.attacker_executor is atk
    assert RED_EARNED_ADDENDUM in red.system_prompt
    names = [t["function"]["name"] for t in red.tools]
    assert "run_on_attacker" in names and "execute_command" in names


def test_non_earned_red_has_no_attacker_channel():
    red = Agent(role="red", executor=MagicMock(), model="m")
    assert red.earned is False
    assert red.attacker_executor is None
    assert RED_EARNED_ADDENDUM not in red.system_prompt
    assert "run_on_attacker" not in [t["function"]["name"] for t in red.tools]


def test_run_on_attacker_routes_to_attacker_executor():
    atk = MagicMock()
    atk.execute.return_value = "login: vagrant password: vagrant"
    red = Agent(role="red", executor=MagicMock(), model="m", earned=True, attacker_executor=atk)
    out = red.process_tool_call({"function": {"name": "run_on_attacker", "arguments": {"command": "hydra ..."}}})
    atk.execute.assert_called_once_with("hydra ...")
    assert "vagrant" in out


def test_blue_never_gets_attacker_channel_or_earned():
    blue = Agent(role="blue", executor=MagicMock(), model="m", earned=True, attacker_executor=MagicMock())
    assert blue.earned is False
    assert blue.attacker_executor is None
