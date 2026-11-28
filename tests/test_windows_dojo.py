import base64
from unittest.mock import patch

from src.executor import ToolExecutor
from src.windows_dojo import (
    CASE_FILES, FLAG_PATH, provision_windows_case, teardown_windows_case,
)


def _winrm():
    return ToolExecutor(host="192.168.64.17", user="vagrant", pwd="vagrant",
                        transport="winrm", jump_host="192.168.64.11",
                        jump_user="kali", jump_pwd="kali", timeout=30)


def test_provision_refuses_non_winrm():
    ex = ToolExecutor(host="h", user="u", pwd="p", timeout=30)  # ssh
    try:
        provision_windows_case(ex)
        assert False, "expected ValueError on ssh transport"
    except ValueError:
        pass


def test_provision_writes_all_and_self_checks():
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="1") as ps:  # Test-Path -> present
        written = provision_windows_case(ex)
    assert set(written) == set(CASE_FILES)
    assert FLAG_PATH in written
    # a write command base64-encodes the content and targets the path
    flag_b64 = base64.b64encode(CASE_FILES[FLAG_PATH].encode()).decode()
    assert any(flag_b64 in c.args[0] for c in ps.call_args_list)
    # the history breadcrumb references the flag read
    assert any("PSReadLine" in c.args[0] for c in ps.call_args_list)


def test_provision_reports_missing_on_failed_write():
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="0"):  # Test-Path -> absent
        written = provision_windows_case(ex)
    assert written == []


def test_teardown_removes_each_file():
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="") as ps:
        teardown_windows_case(ex)
    removed = [c.args[0] for c in ps.call_args_list]
    file_removals = [c for c in removed if "Remove-Item" in c]
    assert len(file_removals) == len(CASE_FILES)  # every case file removed


def test_provision_creates_low_priv_contractor():
    from src.windows_dojo import CONTRACTOR_USER, _provision_contractor
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="1") as ps:
        assert _provision_contractor(ex) is True
    cmds = " ".join(c.args[0] for c in ps.call_args_list)
    assert f"New-LocalUser -Name {CONTRACTOR_USER}" in cmds
    assert "Remote Management Users" in cmds        # WinRM access
    assert "Remove-LocalGroupMember -Group Administrators" in cmds  # never admin


def test_teardown_removes_contractor():
    from src.windows_dojo import CONTRACTOR_USER
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="") as ps:
        teardown_windows_case(ex)
    cmds = " ".join(c.args[0] for c in ps.call_args_list)
    assert f"Remove-LocalUser -Name {CONTRACTOR_USER}" in cmds


def test_grant_winrm_lowpriv_inserts_rm_ace_preserving_admin():
    from src.windows_dojo import _grant_winrm_lowpriv
    ex = _winrm()
    orig = "O:NSG:BAD:P(A;;GA;;;BA)(A;;GR;;;IU)S:P(AU;FA;GA;;;WD)"
    with patch.object(ex, "_ps", side_effect=[orig, ""]) as ps:
        _grant_winrm_lowpriv(ex)
    set_cmd = ps.call_args_list[1].args[0]
    assert "(A;;GA;;;RM)" in set_cmd            # RM granted
    assert "(A;;GA;;;BA)" in set_cmd            # admin ACE preserved (no lockout)


def test_grant_winrm_lowpriv_idempotent():
    from src.windows_dojo import _grant_winrm_lowpriv
    ex = _winrm()
    already = "O:NSG:BAD:P(A;;GA;;;RM)(A;;GA;;;BA)S:P(AU;FA;GA;;;WD)"
    with patch.object(ex, "_ps", side_effect=[already]) as ps:
        _grant_winrm_lowpriv(ex)
    assert ps.call_count == 1                   # read only, no Set-Item


def test_lock_flag_acl_is_admin_only():
    from src.windows_dojo import _lock_flag_acl
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="") as ps:
        _lock_flag_acl(ex)
    cmd = ps.call_args.args[0]
    assert "/inheritance:r" in cmd and "Administrators:F" in cmd


def test_share_breadcrumbs_grants_users_read_except_flag():
    from src.windows_dojo import _share_breadcrumbs, FLAG_PATH
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="") as ps:
        _share_breadcrumbs(ex)
    cmds = [c.args[0] for c in ps.call_args_list]
    assert all("Users:R" in c for c in cmds)
    assert not any(FLAG_PATH in c for c in cmds)   # flag stays admin-only
    assert len(cmds) == len(CASE_FILES) - 1
