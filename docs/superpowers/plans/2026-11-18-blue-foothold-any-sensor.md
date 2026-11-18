# Blue foothold on any sensor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In observe mode, blue closes the escalation surface on a foothold detected by ANY sensor (auth login, service-account critical process, or webshell BREACH), not only on an auth-log SSH login.

**Architecture:** Add `_has_foothold()` to `BlueAgent` (true for a foothold from any sensor) and gate the standalone HARDEN directive on it instead of `_attacker_account()`. IDENTIFY/RESPOND keep `_attacker_account()`, so the SSH-account revoke playbook is untouched and service accounts never reach `revoke_escalation`/`remediate_account`. Generalize the HARDEN directive text, which currently assumes a revoke already ran.

**Tech Stack:** Python 3.13, pytest (run as `uv run python -m pytest`).

**Spec:** `docs/superpowers/specs/2026-11-18-blue-foothold-any-sensor-design.md`

## Global Constraints

- No new scoring tier; no change to non-observe behavior.
- Service accounts (`www-data` etc.) must NOT be routed into `revoke_escalation` / `remediate_account` — those stay gated on `_attacker_account()` (auth-log only).
- Tests run with `uv run python -m pytest` (plain `pytest`/`uv run pytest` fail to import `src`).

## Review Focus

- A root-owned critical process (red already escalated) must still count as a foothold — `_has_foothold()` excludes only the control account, not root. (Task 1, covered.)
- Blue's own benign recon must NOT register as a foothold: a critical process whose user is the control account (`self.executor.user`) is excluded. (Task 1, covered.)
- Recon-only (port scan, no foothold) must still NOT trigger HARDEN. (Task 1, covered.)

---

### Task 1: `_has_foothold()` + HARDEN gate on any-sensor foothold

**Files:**
- Modify: `src/agents.py` — add `_has_foothold()` near `_attacker_account()` (~1750); swap the HARDEN gate at ~1831; generalize the directive text at ~1833–1840.
- Test: `tests/test_foothold_any_sensor.py` (create)

**Interfaces:**
- Consumes: existing `BlueAgent.history` (list of `Turn` with `.output` JSON strings), `BlueAgent._attacker_account()`, `self.executor.user` (control account).
- Produces: `BlueAgent._has_foothold(self) -> bool`.

- [ ] **Step 1: Write the failing tests**

```python
import json
from src.agents import BlueAgent
from src.mock_executor import MockExecutor
from src.trajectory import Turn

def _blue():
    b = BlueAgent(executor=MockExecutor(), model="x")
    b.executor.control_source_ip = "192.168.64.1"
    b.executor.user = "vagrant"
    return b

def _logs_turn(**extra):
    d = {"tool": "investigate_logs", "suspicious_users": [], **extra}
    return Turn(0, "", {"function": {"name": "investigate_logs", "arguments": {}}}, json.dumps(d))

def _proc_turn(critical):
    d = {"tool": "investigate_processes", "critical_processes": critical}
    return Turn(0, "", {"function": {"name": "investigate_processes", "arguments": {}}}, json.dumps(d))

def _webshell_turn(**extra):
    d = {"tool": "investigate_webshells", "new_files": [], **extra}
    return Turn(0, "", {"function": {"name": "investigate_webshells", "arguments": {}}}, json.dumps(d))

def test_service_account_critical_process_is_a_foothold():
    b = _blue()
    b.history = [_proc_turn([{"user": "www-data", "command": "find / -name flag.txt", "critical": True}])]
    assert b._has_foothold() is True

def test_root_critical_process_is_a_foothold():
    b = _blue()
    b.history = [_proc_turn([{"user": "root", "command": "cat /root/flag.txt", "critical": True}])]
    assert b._has_foothold() is True

def test_webshell_breach_is_a_foothold():
    b = _blue()
    b.history = [_webshell_turn(assessment="BREACH")]
    assert b._has_foothold() is True

def test_auth_account_is_a_foothold():
    b = _blue()
    b.history = [_logs_turn(suspicious_users=["boba_fett"])]
    assert b._has_foothold() is True

def test_blue_own_recon_process_is_not_a_foothold():
    b = _blue()
    b.history = [_proc_turn([{"user": "vagrant", "command": "stat /root/flag.txt", "critical": True}])]
    assert b._has_foothold() is False

def test_recon_only_is_not_a_foothold():
    b = _blue()
    b.history = [_logs_turn(), _webshell_turn(assessment="CLEAN")]
    assert b._has_foothold() is False

def test_harden_fires_for_webrce_foothold_without_account():
    # Confirmed attacker + www-data foothold, no auth account: observe-mode
    # guidance must direct the surface close, not just document.
    b = _blue()
    b.history = [_proc_turn([{"user": "www-data", "command": "find / -name flag.txt", "critical": True}])]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_escalation_surface" in g

def test_recon_only_does_not_harden():
    b = _blue()
    b.history = [_logs_turn()]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_escalation_surface" not in g
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_foothold_any_sensor.py -v`
Expected: FAIL — `AttributeError: 'BlueAgent' object has no attribute '_has_foothold'`.

- [ ] **Step 3: Implement `_has_foothold(self) -> bool` in `src/agents.py`**

Add near `_attacker_account()`. True if any of: `_attacker_account()` is not `None`; any `investigate_processes` output has a `critical_processes` entry whose `user` is truthy and `!= self.executor.user`; any `investigate_webshells` output with `assessment == "BREACH"` or non-empty `new_files` or `flag_access_detected` truthy. Same history-walk + `json.loads` try/except pattern as `_attacker_account()`.

- [ ] **Step 4: Swap the HARDEN gate**

At agents.py ~1831, change `self._attacker_account()` → `self._has_foothold()` in the standalone HARDEN `if`. Leave IDENTIFY (~1799) and RESPOND (~1846) on `_attacker_account()`.

- [ ] **Step 5: Generalize the HARDEN directive text**

At agents.py ~1833–1840, replace the opening that assumes a revoke ran ("You cut the account's group-based escalation.") with a foothold-neutral opening (a foothold has landed; close its escalation surface in one move). Keep the `remediate_escalation_surface` instruction and the "does NOT ban them" clause unchanged.

- [ ] **Step 6: Run the new tests**

Run: `uv run python -m pytest tests/test_foothold_any_sensor.py -v`
Expected: PASS (all 8).

- [ ] **Step 7: Run the full suite (regression)**

Run: `uv run python -m pytest -q`
Expected: PASS — the current 540 plus the 8 new tests (548), no failures. Confirms SSH-account footholds still go IDENTIFY→revoke→HARDEN and recon-only still never HARDENs.

- [ ] **Step 8: Commit**

```bash
git add src/agents.py tests/test_foothold_any_sensor.py docs/superpowers/specs/2026-11-18-blue-foothold-any-sensor-design.md docs/superpowers/plans/2026-11-18-blue-foothold-any-sensor.md
git commit -m "feat(blue): close the surface on any foothold, not just SSH logins"
```

---

## Self-Review

1. **Spec coverage:** `_has_foothold()` (Task 1 Step 3) ✓; HARDEN gate swap (Step 4) ✓; directive text (Step 5) ✓; non-goal "no service account into revoke" held by leaving IDENTIFY/RESPOND on `_attacker_account()` (Step 4) ✓; verification (Steps 6–7) ✓.
2. **Step scan:** each step writes one thing; bodies given only as test assertions and the predicate's membership rule, which the signature alone doesn't fix.
3. **Type consistency:** `_has_foothold(self) -> bool`, used in Step 4's gate, matches Step 3's definition.
4. **Review Focus:** root-process, own-recon, and recon-only cases each have a named test in Step 1.
5. **Proportion:** plan ≈ spec length; the one code block is tests + the membership rule, not the implementation body.
