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


def test_earned_red_gets_use_credential_tool():
    from unittest.mock import MagicMock
    from src.agents import Agent
    from src.executor import ToolExecutor
    ex = MagicMock(spec=ToolExecutor)
    earned = Agent(role="red", executor=ex, earned=True, attacker_executor=ex)
    handed = Agent(role="red", executor=ex, earned=False)
    names = lambda a: {t["function"]["name"] for t in a.tools}
    assert "use_credential" in names(earned)
    assert "use_credential" not in names(handed)


# --- Task 2: TargetProfile seam -------------------------------------------

def test_red_core_prompt_has_no_box_specific_app_name():
    from src.agents import RedAgent
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), earned=True)
    assert "payroll_app.php" not in red.system_prompt  # discovered, not baked


def test_env_notes_from_profile_reach_the_prompt():
    from src.agents import RedAgent
    from src.mock_executor import MockExecutor
    from src.target import TargetProfile
    prof = TargetProfile(host="x", env_notes="HINT: a payroll web app is present")
    red = RedAgent(executor=MockExecutor(), earned=True, target=prof)
    assert "payroll web app" in red.system_prompt


# --- self-checker: Linux sensors relabel not_applicable off-Linux --------------

def test_linux_sensor_not_applicable_on_windows():
    ex = MagicMock()
    ex.detected_os = "windows"
    blue = Agent(role="blue", executor=ex, model="m")
    out = blue.process_tool_call({"function": {"name": "investigate_processes", "arguments": {}}})
    assert "not_applicable" in out
    ex.investigate_processes.assert_not_called()


def test_linux_sensor_runs_when_linux():
    ex = MagicMock()
    ex.detected_os = "linux"
    ex.investigate_processes.return_value = {"tool": "investigate_processes", "ok": True}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "investigate_processes", "arguments": {}}})
    ex.investigate_processes.assert_called_once()


def test_guard_allows_environment_and_nonsensor_on_windows():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.investigate_environment.return_value = {"tool": "investigate_environment", "detected_os": "windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "investigate_environment", "arguments": {}}})
    ex.investigate_environment.assert_called_once()
    blue.process_tool_call({"function": {"name": "execute_command", "arguments": {"command": "x"}}})
    ex.execute.assert_called()


# --- mirror guard: Windows sensors relabel not_applicable on Linux -------------

def test_windows_sensor_runs_on_windows():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.investigate_processes_windows.return_value = {"tool": "investigate_processes_windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "investigate_processes_windows", "arguments": {}}})
    ex.investigate_processes_windows.assert_called_once()


def test_windows_sensor_not_applicable_on_linux():
    ex = MagicMock()
    ex.detected_os = "linux"
    blue = Agent(role="blue", executor=ex, model="m")
    out = blue.process_tool_call({"function": {"name": "investigate_processes_windows", "arguments": {}}})
    assert "not_applicable" in out
    ex.investigate_processes_windows.assert_not_called()


def test_windows_logins_sensor_runs_on_windows():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.investigate_logins_windows.return_value = {"tool": "investigate_logins_windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "investigate_logins_windows", "arguments": {}}})
    ex.investigate_logins_windows.assert_called_once()


def test_windows_persistence_sensor_runs_on_windows():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.investigate_persistence_windows.return_value = {"tool": "investigate_persistence_windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "investigate_persistence_windows", "arguments": {}}})
    ex.investigate_persistence_windows.assert_called_once()


def test_windows_network_sensor_runs_on_windows():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.investigate_network_windows.return_value = {"tool": "investigate_network_windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "investigate_network_windows", "arguments": {}}})
    ex.investigate_network_windows.assert_called_once()


def test_windows_file_access_sensor_runs_on_windows():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.investigate_file_access_windows.return_value = {"tool": "investigate_file_access_windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "investigate_file_access_windows",
                                         "arguments": {"file_path": "C:\\x.txt"}}})
    ex.investigate_file_access_windows.assert_called_once_with("C:\\x.txt")


def test_windows_remove_persistence_dispatches():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.remove_persistence_windows.return_value = {"tool": "remove_persistence_windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "remove_persistence_windows", "arguments": {}}})
    ex.remove_persistence_windows.assert_called_once()


def test_contain_windows_routes_and_observe_holds():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.contain_attacker_windows.return_value = {"tool": "contain_attacker_windows", "contained": True}
    blue = Agent(role="blue", executor=ex, model="m")
    out = blue.process_tool_call({"function": {"name": "contain_attacker_windows",
                                               "arguments": {"ip": "10.6.6.6"}}})
    ex.contain_attacker_windows.assert_called_once_with("10.6.6.6")
    assert "contain_attacker_windows" in out
    # observe mode holds the network block, same as the Linux tool
    blue_obs = Agent(role="blue", executor=ex, model="m", observe=True)
    out2 = blue_obs.process_tool_call({"function": {"name": "contain_attacker_windows",
                                                    "arguments": {"ip": "10.6.6.6"}}})
    assert "observed" in out2  # held, not executed
    ex.contain_attacker_windows.assert_called_once()  # still only the first (non-observe) call


def test_windows_account_tools_dispatch():
    ex = MagicMock()
    ex.detected_os = "windows"
    ex.remediate_account_windows.return_value = {"tool": "remediate_account_windows"}
    ex.revoke_escalation_windows.return_value = {"tool": "revoke_escalation_windows"}
    blue = Agent(role="blue", executor=ex, model="m")
    blue.process_tool_call({"function": {"name": "remediate_account_windows", "arguments": {"user": "foothold"}}})
    ex.remediate_account_windows.assert_called_once_with("foothold")
    blue.process_tool_call({"function": {"name": "revoke_escalation_windows", "arguments": {"user": "foothold"}}})
    ex.revoke_escalation_windows.assert_called_once_with("foothold")


# --- Windows prompt doctrine appended only on a winrm engagement ---------------

def test_windows_addendum_appended_by_role():
    rw = Agent(role="red", executor=MagicMock(), model="m", windows=True)
    assert "TARGET IS WINDOWS" in rw.system_prompt and "where /r" in rw.system_prompt
    bw = Agent(role="blue", executor=MagicMock(), model="m", windows=True)
    assert "investigate_logins_windows" in bw.system_prompt
    assert "remove_persistence_windows" in bw.system_prompt
    # Linux engagement: no Windows doctrine
    rl = Agent(role="red", executor=MagicMock(), model="m")
    assert "TARGET IS WINDOWS" not in rl.system_prompt


# --- Windows persistence objective: red plants a task, not an SSH key ----------

def test_objective_met_windows_persistence_credits_task_not_sshkey():
    from src.agents import RedAgent
    from src.trajectory import Turn
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), objective="persistence", windows=True)
    red.history = [Turn(0, "", None, "SUCCESS: The scheduled task \"Svc\" has successfully been created.")]
    assert red.objective_met() is True
    # an SSH key does NOT satisfy a Windows persistence objective
    red.history = [Turn(0, "", None, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij")]
    assert red.objective_met() is False


def test_phase_guidance_windows_persistence_steers_to_task_not_flag():
    from src.agents import RedAgent
    from src.mock_executor import MockExecutor
    red = RedAgent(executor=MockExecutor(), objective="persistence", windows=True)
    red.has_foothold = True  # _on_target() -> True
    g = red.phase_guidance()
    assert "PERSISTENCE" in g and "schtasks /create" in g
    assert "NOT reading the flag" in g
    assert "ssh-ed25519" not in g and "authorized_keys" not in g


def test_handed_windows_red_is_on_target_so_persistence_steer_fires():
    from src.agents import RedAgent
    from src.mock_executor import MockExecutor
    # handed (earned=False) winrm red: no use_credential, no uid= readback, but it
    # holds a working cred -> must be on-target so the persistence steer fires.
    red = RedAgent(executor=MockExecutor(), objective="persistence", windows=True, earned=False)
    assert red._on_target() is True
    g = red.phase_guidance()
    assert "persistence (WINDOWS)" in g.lower() or "schtasks /create" in g
