"""Startup-folder persistence class: _list_win_persistence must enumerate it and
_remove_win_persist_entry must evict it, so blue both sees and removes the class."""
import json
from unittest.mock import patch

from src.executor import ToolExecutor


def _winrm():
    return ToolExecutor(host="192.168.64.17", user="vagrant", pwd="vagrant",
                        transport="winrm", jump_host="192.168.64.11",
                        jump_user="kali", jump_pwd="kali", timeout=30)


def test_list_enumerates_startup_folder():
    # The enumeration SCRIPT must reach into the Startup folder(s) and emit
    # startup| entries — a generic parser passing a mocked entry through proves
    # nothing, so assert the script itself enumerates Startup.
    ex = _winrm()
    with patch.object(ex, "_ps", return_value="[]") as ps:
        ex._list_win_persistence()
    script = ps.call_args[0][0]
    assert "startup|" in script and "Startup" in script


def test_list_parses_startup_entry():
    ex = _winrm()
    entry = "startup|C:\\Users\\x\\...\\Startup\\eysvc.lnk"
    with patch.object(ex, "_ps", return_value=json.dumps(["task|\\Old", entry])):
        got = ex._list_win_persistence()
    assert entry in got


def test_remove_startup_entry_routes_to_file_delete():
    ex = _winrm()
    path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\r un.bat"
    with patch.object(ex, "_ps", return_value="PL_OK") as ps:
        removed, _ = ex._remove_win_persist_entry(f"startup|{path}")
    assert removed is True
    script = ps.call_args[0][0]
    assert "Remove-Item" in script and path in script  # the space round-trips


def test_remove_startup_unknown_still_handled():
    ex = _winrm()
    removed, detail = ex._remove_win_persist_entry("startup|")  # no path
    assert removed is False
