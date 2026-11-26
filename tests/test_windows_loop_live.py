"""End-to-end Windows detect->respond loop against a LIVE Windows box.

This exercises the whole Windows capability together — a scripted (no-LLM)
attacker plants persistence, takes an account foothold, and reads the audited
objective; blue then investigates with every Windows sensor and evicts with every
Windows response tool. It is the integration counterpart to the per-tool unit
tests, closing the "never run in a full loop" gap without needing red LLM
doctrine.

It MUTATES the target (a Run key, a local user, a scheduled task, a SACL + audit
policy, a temp flag file) and so is OFF by default: set PL_LIVE_WINRM=1 to run it.
Every artifact is torn down in a finally block, pass or fail. Reproducible: the
only non-deterministic step is waiting for the Security log to surface Event 4663
after the read task runs (polled, not slept-on blindly).

    PL_LIVE_WINRM=1 uv run pytest tests/test_windows_loop_live.py -q -s

Config via env (defaults match the dojo): PL_WIN_HOST, PL_WIN_USER, PL_WIN_PWD,
PL_JUMP_HOST, PL_JUMP_USER, PL_JUMP_PWD.
"""
import os
import time

import pytest

from src.executor import ToolExecutor

pytestmark = pytest.mark.skipif(
    os.getenv("PL_LIVE_WINRM") != "1",
    reason="live Windows box test; set PL_LIVE_WINRM=1 to run",
)

HOST = os.getenv("PL_WIN_HOST", "192.168.64.17")
USER = os.getenv("PL_WIN_USER", "vagrant")
PWD = os.getenv("PL_WIN_PWD", "vagrant")
JUMP_HOST = os.getenv("PL_JUMP_HOST", "192.168.64.11")
JUMP_USER = os.getenv("PL_JUMP_USER", "kali")
JUMP_PWD = os.getenv("PL_JUMP_PWD", "kali")

FLAG = r"C:\Windows\Temp\pl_flag.txt"
FOOTHOLD = "plfoothold"
FOOTHOLD_PW = "P@ssw0rd!23x"
RUN_KEY = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "PLImplant"
READ_TASK = "PLReadFlag"


def _executor():
    return ToolExecutor(host=HOST, user=USER, pwd=PWD, transport="winrm",
                        jump_host=JUMP_HOST, jump_user=JUMP_USER, jump_pwd=JUMP_PWD,
                        timeout=120)


def _nuke(ex):
    """Best-effort removal of every artifact the harness creates."""
    ex._ps(f"schtasks /delete /tn {READ_TASK} /f 2>$null; "
           f"Remove-ItemProperty -Path '{RUN_KEY}' -Name '{RUN_NAME}' -Force -EA SilentlyContinue; "
           f"Remove-LocalGroupMember -Group Administrators -Member {FOOTHOLD} -EA SilentlyContinue; "
           f"Remove-LocalUser -Name {FOOTHOLD} -EA SilentlyContinue; "
           f"Remove-Item -LiteralPath '{FLAG}' -Force -EA SilentlyContinue")
    ex._disable_file_audit()


def _flag_access_breach(ex, timeout=25):
    """Poll the file-access sensor until the foothold's 4663 surfaces (the
    Security log is eventually-consistent after the read task runs)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = ex.investigate_file_access_windows(FLAG)
        if last.get("assessment") == "BREACH":
            return last
        time.sleep(3)
    return last


def test_windows_detect_respond_loop():
    ex = _executor()
    try:
        ex._ps("$null")  # warm the jump + WinRM channel

        # --- ARM: objective file + auditing, then open blue's window -----------
        ex._ps(f"Set-Content -LiteralPath '{FLAG}' -Value 'FLAG{{pl-live-loop}}'")
        assert ex.enable_file_audit(FLAG) is True
        ex.mark_analysis_window()
        assert ex.analysis_since_epoch is not None
        assert ex._win_persist_baseline is not None

        # --- ATTACK (scripted, no LLM) -----------------------------------------
        # 1. persistence: a Run-key implant
        ex._ps(f"Set-ItemProperty -Path '{RUN_KEY}' -Name '{RUN_NAME}' "
               r"-Value 'C:\Windows\Temp\implant.exe'")
        # 2. account foothold: a local user escalated into Administrators
        ex._ps(f"New-LocalUser -Name {FOOTHOLD} -Password (ConvertTo-SecureString "
               f"'{FOOTHOLD_PW}' -AsPlainText -Force) -EA SilentlyContinue | Out-Null; "
               f"Add-LocalGroupMember -Group Administrators -Member {FOOTHOLD} -EA SilentlyContinue")
        # 3. objective read AS the foothold account (a task running as plfoothold),
        #    so Event 4663's SubjectUserName is foreign, not blue's own session.
        ex._ps(f"schtasks /create /tn {READ_TASK} /tr "
               f"'cmd /c type \\\"{FLAG}\\\"' /sc once /st 23:59 "
               f"/ru {FOOTHOLD} /rp '{FOOTHOLD_PW}' /f | Out-Null; "
               f"schtasks /run /tn {READ_TASK} | Out-Null")

        # --- BLUE DETECTS ------------------------------------------------------
        persist = ex.investigate_persistence_windows()
        assert persist["assessment"] == "BREACH"
        assert any(RUN_NAME in e for e in persist["new_entries"]), persist["new_entries"]

        fa = _flag_access_breach(ex)
        assert fa["assessment"] == "BREACH", fa
        assert any(FOOTHOLD.lower() in str(e).lower() for e in fa["access_events"]), fa

        # --- BLUE RESPONDS -----------------------------------------------------
        revoke = ex.revoke_escalation_windows(FOOTHOLD)
        assert revoke["assessment"] == "REVOKED"
        assert "Administrators" in revoke["revoked_groups"]

        remediate = ex.remediate_account_windows(FOOTHOLD)
        assert remediate["assessment"] == "REMEDIATED"

        evict = ex.remove_persistence_windows()
        assert evict["assessment"] == "REMOVED"
        assert any(RUN_NAME in e for e in evict["removed_entries"]), evict

        # --- VERIFY the box is actually cleaned ---------------------------------
        run_gone = ex._ps(f"if (Get-ItemProperty -Path '{RUN_KEY}' -Name '{RUN_NAME}' "
                          "-EA SilentlyContinue){'PRESENT'}else{'GONE'}").strip()
        assert run_gone == "GONE"
        in_admins = ex._ps(f"[bool](Get-LocalGroupMember Administrators -Member "
                           f"{FOOTHOLD} -EA SilentlyContinue)").strip()
        assert in_admins == "False"
        enabled = ex._ps(f"(Get-LocalUser {FOOTHOLD}).Enabled").strip()
        assert enabled == "False"
    finally:
        _nuke(ex)
