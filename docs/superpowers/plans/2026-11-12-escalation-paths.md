# Blue Escalation-Paths Sensor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give blue one read-only privilege-escalation posture sensor that enumerates the host, flags only deviations from known-good (package provenance first), and emits findings as candidate leads blue chains into privesc paths via the ② case engine.

**Architecture:** Pure parsers/classifiers in a new `src/escalation.py` (raw command output → flagged `Finding` dicts) — fully unit-testable with sample outputs, no live box. A new `ToolExecutor.investigate_escalation_paths` runs the read-only commands, feeds the parsers, assembles a per-category result (`clean`/`findings`/`unavailable`), caches per episode, and fails safe. The blue agent gets the tool wired in plus a doctrine line telling it to chain findings with `record_lead`/`update_hypothesis`. The tool never joins or ranks; blue does.

**Tech Stack:** Python 3.13, pytest, uv. Touches `src/escalation.py` (new), `src/executor.py`, `src/agents.py`.

**Spec:** `docs/superpowers/specs/2026-11-12-purpleloop-escalation-paths-design.md`

## Global Constraints

- Test command: `uv run python -m pytest` (the `-m` form puts cwd on `sys.path`).
- **Read-only + guardrail-clean**: every command is a benign read and must pass `FORBIDDEN_KEYWORDS` without `dojo_exploit_ok`.
- **Known-good = package provenance first**, no distro SUID allowlist. A SUID/privileged binary owned by no package, or whose package hash deviated (`dpkg -V`), is flagged; a normal owned non-GTFOBins SUID is NOT.
- **Fail safe per category**: a command that errors or returns nothing yields `unavailable` for that category, never `clean` (the Family-1 "can't read must not credit" rule). `clean` means ran-and-found-nothing.
- **Findings carry the file path** so blue can match a writable-item lead to a scheduled-item lead. The tool does NOT join them.
- **No new scoring tier**; cache per episode, cleared on `reset_episode`.
- Scans exclude `/proc`, `/sys`; bound the findings list fed back to blue.

## Review Focus

- **Unreadable category** (e.g. no `dpkg`, empty `getcap`): reported `unavailable`, never `clean` — no false all-clear. → Task 3.
- **A normal, package-owned, non-GTFOBins SUID** (e.g. `/usr/bin/passwd`) must NOT be flagged — no false positive. → Task 1.
- **The same file world-writable AND run by root cron**: both leads emitted, each carrying that path, so blue can chain. → Task 2.
- **Non-Debian / missing `dpkg`**: `package_integrity` → `unavailable`, no crash. → Task 1/Task 3.
- **Output bound**: a host with hundreds of writable files returns a capped, flagged subset, not a dump. → Task 3.

---

### Task 1: Deviation backbone (`src/escalation.py` — SUID provenance, package integrity, GTFOBins)

**Files:**
- Create: `src/escalation.py`
- Test: `tests/test_escalation_backbone.py`

**Interfaces:**
- Produces:
  - `GTFOBINS: frozenset[str]` — basenames of known shell-spawning binaries (small, embedded, auditable).
  - `finding(category: str, item: str, principal: str, why: str, detail: str) -> dict` — the canonical finding shape.
  - `parse_suid(find_output: str) -> list[str]` — SUID/SGID paths from `find` output.
  - `parse_owned_paths(dpkg_search_output: str) -> set[str]` — paths `dpkg -S` reports as package-owned.
  - `flag_suid(suid_paths: list[str], owned: set[str], gtfobins: frozenset[str]) -> list[dict]` — flags a SUID path when it is NOT in `owned` (why="unowned-suid") OR its basename is in `gtfobins` (why="gtfobins-shellable"); a normal owned non-GTFOBins path yields nothing.
  - `parse_package_integrity(dpkg_verify_output: str) -> list[dict]` — each `dpkg -V` line whose flags include a hash mismatch (`5` in cols 1-9) → finding(category="package_integrity", why="hash-delta").

- [ ] **Step 1: Write the failing tests**

```python
def test_parse_suid_extracts_paths():
    out = "/usr/bin/passwd\n/usr/bin/sudo\n/opt/weird/backdoor\n"
    assert parse_suid(out) == ["/usr/bin/passwd", "/usr/bin/sudo", "/opt/weird/backdoor"]

def test_flag_suid_skips_normal_owned_binary():
    owned = {"/usr/bin/passwd"}
    assert flag_suid(["/usr/bin/passwd"], owned, GTFOBINS) == []

def test_flag_suid_flags_unowned_binary():
    res = flag_suid(["/opt/weird/backdoor"], owned=set(), gtfobins=GTFOBINS)
    assert len(res) == 1 and res[0]["why"] == "unowned-suid" and res[0]["item"] == "/opt/weird/backdoor"

def test_flag_suid_flags_gtfobins_shellable_even_if_owned():
    owned = {"/usr/bin/find"}
    res = flag_suid(["/usr/bin/find"], owned, GTFOBINS)  # find IS a GTFOBins shell-spawner
    assert res and res[0]["why"] == "gtfobins-shellable"

def test_gtfobins_contains_known_shell_spawners():
    assert {"find", "vim", "nmap", "bash"} <= GTFOBINS

def test_parse_package_integrity_flags_hash_delta_only():
    # dpkg -V: leading 9 cols, "5" = md5 mismatch; "??" = not checked
    out = "??5??????   /usr/bin/tampered\n??????????  c /etc/some.conf\n"
    res = parse_package_integrity(out)
    assert len(res) == 1 and res[0]["item"] == "/usr/bin/tampered" and res[0]["why"] == "hash-delta"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_escalation_backbone.py -v`
Expected: FAIL (module not defined)

- [ ] **Step 3: Implement `src/escalation.py`** with the signatures above. `GTFOBINS` is a hand-curated frozenset of shell-spawning binary basenames. `parse_package_integrity` treats a line as a hash-delta when the `5` flag appears in the first whitespace-delimited column.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_escalation_backbone.py -v`
Expected: PASS

- [ ] **Step 5: Commit** (if commits enabled)

```bash
git add src/escalation.py tests/test_escalation_backbone.py
git commit -m "feat(escalation): deviation backbone — suid provenance, package integrity, gtfobins"
```

---

### Task 2: Remaining parsers (`src/escalation.py` — writable, scheduled, capabilities)

**Files:**
- Modify: `src/escalation.py`
- Test: `tests/test_escalation_parsers.py`

**Interfaces:**
- Consumes: `finding` (Task 1).
- Produces:
  - `parse_writable(find_output: str) -> list[dict]` — world/group-writable paths → finding(category="writable", principal from mode, why="world-writable"/"group-writable"), **item = the path**.
  - `parse_scheduled(cron_output: str, systemd_timer_output: str) -> list[dict]` — each scheduled job that runs a command as root → finding(category="scheduled", principal="root", why="runs-as-root-scheduled", **item = the executed file path**, detail = the schedule/unit). Extract the executed path from the cron line / unit `ExecStart`.
  - `parse_capabilities(getcap_output: str) -> list[dict]` — files carrying a privilege-relevant capability (`cap_setuid`, `cap_dac_override`, `cap_sys_admin`, …) → finding(category="capability", why="dangerous-capability", item = the path).

- [ ] **Step 1: Write the failing tests**

```python
def test_parse_writable_carries_path_and_principal():
    out = "/opt/backup/run.sh\n/tmp/x\n"  # find already filtered to writable
    res = parse_writable(out)
    assert any(f["item"] == "/opt/backup/run.sh" and f["category"] == "writable" for f in res)

def test_parse_scheduled_extracts_executed_path_for_chaining():
    cron = "*/5 * * * * root /opt/backup/run.sh\n"
    res = parse_scheduled(cron, "")
    assert len(res) == 1
    assert res[0]["item"] == "/opt/backup/run.sh"   # SAME path a writable finding would carry
    assert res[0]["principal"] == "root" and res[0]["category"] == "scheduled"

def test_scheduled_and_writable_share_the_item_path_so_blue_can_chain():
    path = "/opt/backup/run.sh"
    w = parse_writable(path + "\n")
    s = parse_scheduled("*/5 * * * * root " + path + "\n", "")
    assert w[0]["item"] == s[0]["item"] == path

def test_parse_capabilities_flags_setuid_capability():
    out = "/usr/bin/odd = cap_setuid+ep\n/usr/bin/ping = cap_net_raw+ep\n"
    res = parse_capabilities(out)
    assert any(f["item"] == "/usr/bin/odd" for f in res)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_escalation_parsers.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** the three parsers. `parse_scheduled` pulls the executed path from a cron line (field after the user) and from a unit's `ExecStart=`. `parse_capabilities` flags only the privilege-relevant capability set, not every capability.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_escalation_parsers.py -v`
Expected: PASS

- [ ] **Step 5: Commit** (if enabled)

```bash
git add src/escalation.py tests/test_escalation_parsers.py
git commit -m "feat(escalation): writable / scheduled / capability parsers (path-carrying leads)"
```

---

### Task 3: Executor sensor — `investigate_escalation_paths`

**Files:**
- Modify: `src/executor.py` (new method near the other `investigate_*` sensors; cache field; clear it in `reset_episode`)
- Test: `tests/test_escalation_sensor.py`

**Interfaces:**
- Consumes: all `src/escalation.py` parsers (Tasks 1-2); `self.execute`.
- Produces: `investigate_escalation_paths() -> dict`:
  ```
  {"tool": "investigate_escalation_paths",
   "categories": {"suid": {"status": "findings"|"clean"|"unavailable", "findings": [...]}, ...},
   "findings": [...capped flat list...], "assessment": "CLEAN"|"FINDINGS"}
  ```
  Per category: run its read-only command(s) via `self.execute`; empty/error output ⇒ `status="unavailable"`; parser returns `[]` ⇒ `clean`; else `findings`. Cache the whole result on `self._escalation_cache`; later calls in the same episode return it. `reset_episode` sets `self._escalation_cache = None`.

- [ ] **Step 1: Write the failing tests** (mock `self.execute` per command via a dispatch stub)

```python
def test_unreadable_category_is_unavailable_not_clean():
    ex = _ex_returning({"dpkg -V": ""})  # dpkg present elsewhere; package cmd returns nothing
    res = ex.investigate_escalation_paths()
    assert res["categories"]["package_integrity"]["status"] == "unavailable"

def test_flagged_suid_appears_in_findings():
    ex = _ex_with_suid_backdoor()  # find returns an unowned /opt/x; dpkg -S says unowned
    res = ex.investigate_escalation_paths()
    assert any(f["category"] == "suid" for f in res["findings"])
    assert res["assessment"] == "FINDINGS"

def test_clean_host_assesses_clean():
    ex = _ex_clean()  # only normal owned non-gtfobins suid, no deviations
    res = ex.investigate_escalation_paths()
    assert res["assessment"] == "CLEAN"

def test_result_is_cached_within_episode():
    ex = _ex_clean(); calls = ex.execute_calls
    ex.investigate_escalation_paths(); n = len(calls)
    ex.investigate_escalation_paths()
    assert len(calls) == n  # second call ran no new commands

def test_reset_episode_clears_the_cache():
    ex = _ex_clean(); ex.investigate_escalation_paths(); ex.reset_episode()
    assert ex._escalation_cache is None

def test_findings_are_capped():
    ex = _ex_many_writable(300)
    res = ex.investigate_escalation_paths()
    assert len(res["findings"]) <= 100
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_escalation_sensor.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** the method: a small table of (category → command(s) → parser), run each, map empty/error → `unavailable`, assemble, cap `findings`, cache. Add `self._escalation_cache = None` in `__init__` and `reset_episode`. All commands read-only (`find ... -perm`, `getcap -r /`, `dpkg -V`, `dpkg -S`, `crontab -l`/`cat /etc/cron.*`, `systemctl list-timers`/show), excluding `/proc` and `/sys`.

- [ ] **Step 4: Run to verify they pass + full suite**

Run: `uv run python -m pytest tests/test_escalation_sensor.py -v && uv run python -m pytest`
Expected: PASS; suite green

- [ ] **Step 5: Commit** (if enabled)

```bash
git add src/executor.py tests/test_escalation_sensor.py
git commit -m "feat(escalation): investigate_escalation_paths sensor (per-category status, cached, fail-safe)"
```

---

### Task 4: Wire into blue + doctrine to chain

**Files:**
- Modify: `src/agents.py` (blue tool schema; dispatch; `BLUE_TOOL_PRIORITY`; a doctrine line)
- Test: `tests/test_escalation_wiring.py`

**Interfaces:**
- Consumes: `ToolExecutor.investigate_escalation_paths` (Task 3).
- Produces: `investigate_escalation_paths` registered in the blue schema + dispatch, added to `BLUE_TOOL_PRIORITY` (it IS a breadth sensor, unlike the note tools), and a `BLUE_SYSTEM_PROMPT`/guidance line: when this sensor returns findings, file the relevant ones with `record_lead` and connect a writable item to the root-scheduled item that runs it with `update_hypothesis` (the chain is the finding).

- [ ] **Step 1: Write the failing tests**

```python
def test_escalation_tool_is_dispatched_to_executor(_blue):
    b = _blue(); b.executor.investigate_escalation_paths.return_value = {"tool": "investigate_escalation_paths", "findings": []}
    out = json.loads(b.execute_tool({"function": {"name": "investigate_escalation_paths", "arguments": {}}}))
    assert out["tool"] == "investigate_escalation_paths"
    assert b.executor.investigate_escalation_paths.called

def test_escalation_is_in_breadth_rotation():
    assert "investigate_escalation_paths" in BLUE_TOOL_PRIORITY

def test_blue_doctrine_tells_it_to_chain_escalation_findings():
    from src.agents import BLUE_SYSTEM_PROMPT
    assert "escalation" in BLUE_SYSTEM_PROMPT.lower()
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_escalation_wiring.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** — schema entry, dispatch branch (mirror an existing `investigate_*` branch with try/except error payload), add to `BLUE_TOOL_PRIORITY`, and the doctrine line about chaining findings via the case tools.

- [ ] **Step 4: Run to verify they pass + full suite**

Run: `uv run python -m pytest tests/test_escalation_wiring.py -v && uv run python -m pytest`
Expected: PASS; suite green

- [ ] **Step 5: Commit** (if enabled)

```bash
git add src/agents.py tests/test_escalation_wiring.py
git commit -m "feat(escalation): wire sensor into blue + doctrine to chain findings"
```

---

### Task 5: Live validation (gated on the boxes being up)

**Files:** none (observation; note outcome in `HANDOFF.md`).

- [ ] **Step 1** — When `.11`/`.12` are reachable, run one earned+observe episode (streaming to the terminal). Confirm `investigate_escalation_paths` runs under blue's `vagrant` privileges and returns real per-category status — note which categories come back `unavailable` because `vagrant` can't read them (`sudo -l` tty, `/etc/sudoers`), and gate/drop those in a follow-up if needed.
- [ ] **Step 2** — Confirm it flags the box's real deviations (Metasploitable3 has genuine privesc posture) without false-flagging normal owned SUID binaries.
- [ ] **Step 3** — If blue reaches for it, confirm it files findings as leads and (ideally) chains a writable↔root-scheduled pair into a hypothesis. Honest "didn't take the path" is a valid outcome, same as every prior family.
- [ ] **Step 4** — Record the outcome in `HANDOFF.md`.

---

## Self-Review

- **Spec coverage:** the enumeration battery (T1 suid/package, T2 writable/scheduled/capability), provenance-first known-good (T1 `flag_suid`/`parse_package_integrity`), per-category `unavailable` status (T3), path-carrying leads for blue's chain (T2), cache per episode + reset (T3), blue wiring + chain doctrine (T4), no new scoring tier (nowhere touched), live (T5). Tool never joins/ranks — no task does; by design.
- **Type consistency:** `finding(...)` dict shape identical across T1/T2; `investigate_escalation_paths()` result shape stated in T3 and consumed in T4; parsers' `(str) -> list[dict]` signatures match their call sites in T3.
- **Review Focus:** unavailable-not-clean (T3), normal-SUID-not-flagged (T1), shared-path chaining (T2), missing-dpkg (T1/T3), bounded output (T3) — each pinned to a task's tests.
