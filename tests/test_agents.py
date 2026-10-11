from src.agents import _coerce_text_tool_call


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
