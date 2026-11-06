# Family 1 — Privilege Escalation (Dirty COW) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give red a kernel privesc vector (Dirty COW, CVE-2016-5195) that bypasses blue's docker/sudo revoke, and a coupled blue sensor that detects + removes the rogue root account it creates.

**Architecture:** Red writes a Dirty COW PoC on the target, compiles with on-box gcc, and appends a uid=0 account (`firefart`) to `/etc/passwd` — a path the existing `FORBIDDEN_KEYWORDS` guard blocks, so a narrow dojo-scoped exception (`dojo_exploit_ok`) is added. Blue gets `investigate_privileged_accounts()`, which flags any uid=0 account absent from a window-start baseline (the honest-scoring analog of the docker sensor's window-binding), credits a T3 defense, and triggers a removal reflex mirroring the existing `_auto_revoke_escalation`. Scoring reuses the existing T3 flag hooks; reset restores `/etc/passwd`.

**Tech Stack:** Python 3.13, pytest, existing `src/executor.py` / `src/agents.py` / `src/orchestrator.py` / `src/arena.py`. On-target: kernel 3.13.0-24, gcc 4.8.4 (both verified live 2026-11-05).

**Spec:** `docs/superpowers/specs/2026-11-05-purpleloop-linux-breadth-families-design.md` (Family 1 row; the privesc family).

## Global Constraints

- No seeding: the Dirty COW PoC source is supplied tradecraft (precedent: the seeded docker breakout command in `src/agents.py`), but kernel applicability stays red's discovery. Never hand red the box's facts.
- `dojo_exploit_ok` defaults **off**; `rm -rf /`, `mkfs`, `dd if=`, `shutdown`, `reboot` stay blocked regardless of it. Only `passwd`/`/etc/passwd`/`/etc/shadow` are unblocked, and only when it is on.
- Honest scoring: only an **in-window** rogue uid=0 (absent from the baseline captured at `mark_analysis_window`) is a breach; a pre-existing uid=0 account is never credited.
- Live exploit runs are gated on a confirmed `.12` VM snapshot (taken 2026-11-05) and restore `/etc/passwd` after.
- Per-call SSH: target filesystem persists between red's calls, shell/group state does not — the PoC must be written, compiled, and run as separate commands referencing an on-disk path.
- Don't commit autonomously beyond each task's own commit; do not push (user's CLAUDE.md).

## Review Focus

- **passwd access with `dojo_exploit_ok` OFF** must still raise `ValueError` — guard integrity. (Task 1 tests.)
- **`rm -rf /` with `dojo_exploit_ok` ON** must still be blocked — the exception is passwd/shadow only. (Task 1 tests.)
- **A pre-existing uid=0 account** (baseline, e.g. a box that ships one) must NOT be flagged as a breach — only additions after the window start. (Task 2 tests.)
- **`investigate_privileged_accounts` reading `/etc/passwd`** must itself pass the guard (the sensor command names `/etc/passwd`), i.e. blue's executor must also carry `dojo_exploit_ok`. (Task 2/3 tests.)
- **Reset re-running** when no `firefart` exists must be a safe no-op, not an error that aborts the episode loop. (Task 6 tests.)

---

### Task 1: `dojo_exploit_ok` guardrail exception

**Files:**
- Modify: `src/executor.py` (`ToolExecutor.__init__`, `_check_forbidden`)
- Modify: `src/arena.py` (`build_agents`, ~lines 231–243: set the flag on the dojo executors)
- Test: `tests/test_dojo_guardrail.py` (new)

**Interfaces:**
- Produces: `ToolExecutor(__init__ ..., dojo_exploit_ok: bool = False)`; instance attr `self.dojo_exploit_ok`. `_check_forbidden(command, scope)` unchanged signature, new behavior.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_dojo_guardrail.py
import pytest
from src.executor import ToolExecutor

DOJO_ONLY = ["echo x >> /etc/passwd", "cat /etc/shadow"]
ALWAYS_BLOCKED = ["rm -rf /", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/x", "shutdown now", "reboot"]

def test_passwd_blocked_when_flag_off():
    ex = ToolExecutor(host="mock", dojo_exploit_ok=False)
    for cmd in DOJO_ONLY:
        with pytest.raises(ValueError):
            ex._check_forbidden(cmd, "remote")

def test_passwd_allowed_when_flag_on():
    ex = ToolExecutor(host="mock", dojo_exploit_ok=True)
    for cmd in DOJO_ONLY:
        ex._check_forbidden(cmd, "remote")  # no raise

def test_destructive_blocked_even_when_flag_on():
    ex = ToolExecutor(host="mock", dojo_exploit_ok=True)
    for cmd in ALWAYS_BLOCKED:
        with pytest.raises(ValueError):
            ex._check_forbidden(cmd, "remote")

def test_default_is_off():
    assert ToolExecutor(host="mock").dojo_exploit_ok is False
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/test_dojo_guardrail.py -v` → FAIL (unexpected `dojo_exploit_ok` kwarg).

- [ ] **Step 3: Implement.** Add `dojo_exploit_ok: bool = False` param + `self.dojo_exploit_ok = dojo_exploit_ok` in `__init__`. In `_check_forbidden`, split `FORBIDDEN_KEYWORDS` into an always-blocked set and a dojo-exempt set `{"passwd", "/etc/shadow", "/etc/passwd"}`; when `self.dojo_exploit_ok`, skip the dojo-exempt keywords. Keep the existing list as the source of truth (derive the two sets from it). In `src/arena.py` `build_agents`, pass `dojo_exploit_ok=(host != "mock")` to the target executors (blue `blue_ex` and earned red `red_ex`) so the dojo — and only the dojo — carries the exception.

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/test_dojo_guardrail.py -v` → PASS.

- [ ] **Step 5: Commit** — `git add src/executor.py src/arena.py tests/test_dojo_guardrail.py && git commit -m "feat(dojo): dojo-scoped guardrail exception for passwd/shadow"`

---

### Task 2: `investigate_privileged_accounts` sensor

**Files:**
- Modify: `src/executor.py` (new method; baseline capture in `mark_analysis_window`)
- Test: `tests/test_privileged_accounts.py` (new)

**Interfaces:**
- Consumes: `self.dojo_exploit_ok` (Task 1) — the method's command names `/etc/passwd`.
- Produces: `investigate_privileged_accounts(self) -> Dict[str, Any]` returning keys mirroring `investigate_docker`'s contract: `{"tool": "investigate_privileged_accounts", "rogue_accounts": [names], "suspicious_users": [names], "flag_access_detected": bool, "assessment": "BREACH"|"CLEAN"}`. `suspicious_users` is the key the orchestrator reflex reads (same as the docker path). Instance attr `self._uid0_baseline: Optional[set] = None`, populated in `mark_analysis_window()`.

- [ ] **Step 1: Write the failing tests** (parse synthetic passwd; a fake executor stubbing `execute()` to return canned `/etc/passwd`):

```python
# tests/test_privileged_accounts.py
PASSWD_CLEAN = "root:x:0:0:root:/root:/bin/bash\nboba_fett:x:1121:100::/home/boba:/bin/bash\n"
PASSWD_ROGUE = PASSWD_CLEAN + "firefart:x:0:0:pwned:/root:/bin/bash\n"

def test_only_root_uid0_is_clean():
    ex = _ex_returning(PASSWD_CLEAN); ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == [] and r["flag_access_detected"] is False

def test_new_uid0_is_a_breach():
    ex = _ex_returning(PASSWD_ROGUE); ex._uid0_baseline = {"root"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == ["firefart"]
    assert r["suspicious_users"] == ["firefart"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"

def test_preexisting_uid0_not_credited():
    # baseline already had the extra uid0 -> not a breach (window-binding)
    ex = _ex_returning(PASSWD_ROGUE); ex._uid0_baseline = {"root", "firefart"}
    r = ex.investigate_privileged_accounts()
    assert r["rogue_accounts"] == [] and r["flag_access_detected"] is False
```

- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/test_privileged_accounts.py -v` → FAIL (no method).

- [ ] **Step 3: Implement.** `investigate_privileged_accounts` runs `cat /etc/passwd` via `self.execute`, parses uid (field 3) == 0, computes `rogue = {names with uid0} - (self._uid0_baseline or {"root"})`. BREACH iff `rogue` non-empty. In `mark_analysis_window()`, capture `self._uid0_baseline = {names with uid0 now}` so only accounts added during the episode count. (Baseline default `{"root"}` keeps unit tests that don't call the window simple.)

- [ ] **Step 4: Run to verify pass** → PASS.

- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_privileged_accounts.py && git commit -m "feat(blue): investigate_privileged_accounts sensor with window-bound uid0 baseline"`

---

### Task 3: Register the sensor in BlueAgent + removal response

**Files:**
- Modify: `src/agents.py` (tool schema list ~line 437 pattern; `process_tool_call` dispatch ~line 823 pattern; `BLUE_TOOL_PRIORITY` ~line 1080)
- Modify: `src/executor.py` (new `remove_privileged_account(user)` response, mirroring `revoke_escalation`)
- Test: `tests/test_blue_privaccounts_wiring.py` (new)

**Interfaces:**
- Consumes: `investigate_privileged_accounts` (Task 2).
- Produces: tool name `"investigate_privileged_accounts"` in the blue schema, dispatched in `process_tool_call`; `remove_privileged_account(self, user: str) -> str` that refuses `root`/`vagrant`/self (reuse `revoke_escalation`'s refusal guard) and runs `deluser --remove-home <user>` (guard-safe: no `passwd` keyword). Added to `BLUE_TOOL_PRIORITY` after `investigate_docker`.

- [ ] **Step 1: Write the failing tests** — assert the blue tool schema contains `investigate_privileged_accounts`; assert `process_tool_call` routes it to the executor method; assert `remove_privileged_account("root")` refuses and `("firefart")` issues a `deluser`.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Copy the `investigate_docker` schema/dispatch blocks; add `remove_privileged_account`; extend `BLUE_TOOL_PRIORITY`. Tool description names the technique (rogue uid=0 / Dirty COW artifact) the way the docker tool names T1611.

- [ ] **Step 4: Run to verify pass** → PASS.

- [ ] **Step 5: Commit** — `git add src/agents.py src/executor.py tests/test_blue_privaccounts_wiring.py && git commit -m "feat(blue): register privileged-accounts sensor + remove-rogue response"`

---

### Task 4: Scoring + removal reflex in the orchestrator

**Files:**
- Modify: `src/orchestrator.py` (`_check_blue_victory` ~line 147 to also credit the new sensor's `flag_access_detected`; the turn loop ~line 441–451 to fire a removal reflex on rogue-uid0 detection, mirroring `_auto_revoke_escalation` ~line 243)
- Test: `tests/test_dirtycow_scoring.py` (new)

**Interfaces:**
- Consumes: the Task 2 return contract (`flag_access_detected`, `suspicious_users`).
- Produces: on a blue `investigate_privileged_accounts` turn whose output is a BREACH: `blue_tier_detect[TIER_ROOT]` set; `_auto_remove_rogue(detect_output)` strips the rogue account (reflex, runs even in observe, idempotent via a `state.rogue_removed` flag like `escalation_auto_revoked`).

- [ ] **Step 1: Write the failing tests** — drive the orchestrator turn handler with a canned blue BREACH output; assert `blue_tier_detect[TIER_ROOT]` is set and the executor's `remove_privileged_account` was called once (fake executor records calls). Assert a CLEAN output credits nothing and removes nothing.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** `_check_blue_victory` already keys on `flag_access_detected`; confirm the new sensor's output flows through the same path (it will, since the tool output is JSON with that key) — add a test-pinned branch only if the victory check filters by tool name. Add `_auto_remove_rogue` modeled on `_auto_revoke_escalation` (read `suspicious_users`, call `remove_privileged_account`, set the once-only flag), invoked in the same turn-loop region that calls `_auto_revoke_escalation`.

- [ ] **Step 4: Run to verify pass** → PASS; then `uv run pytest -q` (full suite stays green).

- [ ] **Step 5: Commit** — `git add src/orchestrator.py tests/test_dirtycow_scoring.py && git commit -m "feat(score): credit rogue-uid0 as T3 defense + removal reflex"`

---

### Task 5: Red Dirty COW doctrine

**Files:**
- Modify: `src/agents.py` (red doctrine block, near the seeded docker triage ~lines 244–250)
- Test: `tests/test_red_dirtycow_doctrine.py` (new)

**Interfaces:**
- Consumes: nothing new.
- Produces: red's earned/privesc prompt includes the Dirty COW tradecraft: write PoC to `/tmp/dc.c` → `gcc -pthread /tmp/dc.c -o /tmp/dc` → run → `su firefart` → read the flag, each as a **separate** command (per-call SSH note), and a line that red must first confirm the kernel is vulnerable (`uname -r`) — discovery, not seeded fact.

- [ ] **Step 1: Write the failing test** — build the red agent (earned) and assert its composed prompt/doctrine string contains the Dirty COW steps and the `uname -r` discovery instruction (mirror the existing `test_redagent_phase_guidance_*` style).

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Add the doctrine text alongside the docker triage. The PoC C source is supplied verbatim (tradecraft); keep it a known public Dirty COW passwd-append PoC.

- [ ] **Step 4: Run to verify pass** → PASS.

- [ ] **Step 5: Commit** — `git add src/agents.py tests/test_red_dirtycow_doctrine.py && git commit -m "feat(red): Dirty COW privesc doctrine"`

---

### Task 6: Reset restores `/etc/passwd`

**Files:**
- Modify: `src/arena.py` (`scripted_reset`, ~lines 177–210)
- Test: `tests/test_reset_passwd_restore.py` (new)

**Interfaces:**
- Consumes: a blue executor with `dojo_exploit_ok` (Task 1) — the restore command names `/etc/passwd`.
- Produces: `scripted_reset` additionally removes any uid=0 account that isn't `root` (idempotent; safe no-op when none exists), appended to `actions`.

- [ ] **Step 1: Write the failing test** — fake `blue_ex.execute` recording commands; assert `scripted_reset` issues a command that removes non-root uid0 accounts (e.g. a `deluser firefart` or a `sed`/`grep -v` passwd rewrite), and that it tolerates the no-match case (records the action, raises nothing).

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Add a reset line that deletes non-root uid0 accounts, guarded with `|| true` like the sibling cleanups. Prefer `deluser` over editing `/etc/passwd` directly (no `passwd` keyword, survives the guard even if the flag were off).

- [ ] **Step 4: Run to verify pass** → PASS; `uv run pytest -q` green.

- [ ] **Step 5: Commit** — `git add src/arena.py tests/test_reset_passwd_restore.py && git commit -m "feat(reset): remove rogue uid0 accounts between episodes"`

---

### Task 7: LIVE gated validation (one episode)

**Files:** none (operational). Produces an `episode_reports/ep_NNN.*` and a note in `HANDOFF.md`.

**HARD GATE:** confirm with the human that the `.12` snapshot is current before running. (Confirmed taken 2026-11-05; reconfirm it hasn't been consumed.)

- [ ] **Step 1:** Run one live earned+observe episode:
  `uv run python -m src.arena --episodes 1 --host 192.168.64.12 --jump-host 192.168.64.11 --earned --observe --model gemma4:31b-cloud --max-turns 20`
- [ ] **Step 2:** Confirm from `ep_NNN.json`: red reached T3 via Dirty COW (a `su firefart` / uid0 flag read, distinct from docker) **or** honestly recorded red failing the race (expect variance); blue detected the rogue account and the removal reflex fired.
- [ ] **Step 3:** Verify the box is clean: `/etc/passwd` has only root at uid0, no `firefart`, auth.log alive (the direct-SSH check used throughout this session).
- [ ] **Step 4:** If the kernel wedged or passwd is corrupt, restore from snapshot. Record the outcome + any variance in `HANDOFF.md`.
- [ ] **Step 5: Commit** the handoff note — `git add HANDOFF.md && git commit -m "docs(handoff): Family 1 Dirty COW live validation result"` (HANDOFF is gitignored/local per the repo note — skip if so; otherwise commit).

---

## Notes carried from the spec

- This family is the first of five; it is also the first concrete instance the step-3 engine extraction will generalize from. Keep the sensor/doctrine shapes close to the docker precedent so the two are comparable when the engine is pulled out.
- Honest-risk (spec): an LLM reliably landing a race-condition exploit is uncertain — Task 7 expects variance and treats an honest failure as a valid recorded outcome, not a plan failure.
