# Agent Environment Self-Checker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Blue discovers the target OS by probe and stops false-CLEAN on Windows — Linux-only sensors return `not_applicable` instead of running and reporting clean.

**Architecture:** `ToolExecutor` gains a lazily-probed `detected_os` and an `investigate_environment()` method. In `agents.py`, `process_tool_call` gets a top guard: a Linux-only `investigate_*` on a non-Linux target returns a `not_applicable` dict without dispatching. Blue's tool-steering nudges `investigate_environment` first. Linux behavior is unchanged.

**Tech Stack:** Python 3.13, existing executor/agent loop, pytest.

**Spec:** `docs/superpowers/specs/2026-11-24-agent-self-checker-design.md`

## Global Constraints

- Detection is by **probe**, not `TargetProfile.os` (profile is at most a fallback).
- Linux path unchanged: `detected_os == "linux"` → every sensor runs as today.
- Full suite stays green (601 at plan time). Agent doctrine unchanged beyond the env-check steer.
- One guard in `process_tool_call`; do NOT edit the 14 `investigate_*` bodies.

## Review Focus

- **Probe failure / ambiguous output** (`uname` errors, empty, or `WINRM_ERR`): must resolve to `"windows"`, never crash or hang — Task 1 test covers the non-"Linux" → windows path.
- **Detection caching across OS**: `detected_os` must not be computed before the analysis window / must reset per episode so a reused executor doesn't carry a stale OS — Task 1 test asserts reset.
- **Guard over-reach**: the guard must NOT intercept non-sensor tools (`execute_command`, `use_credential`) or `investigate_environment` itself — Task 2 test asserts those still dispatch on a windows target.
- **Linux no-regression**: on `detected_os == "linux"` every sensor dispatches normally — Task 2 test asserts a linux-only sensor runs when linux.

---

### Task 1: `detected_os` probe + `investigate_environment` on the executor

**Files:**
- Modify: `src/executor.py` (`ToolExecutor`: `_detect_os`, `detected_os`, `investigate_environment`, reset in the analysis-window hook)
- Test: `tests/test_executor.py`

**Interfaces:**
- Produces: `ToolExecutor.detected_os -> str` ("linux"|"windows", lazy+cached);
  `ToolExecutor.investigate_environment() -> Dict` with keys
  `tool`, `detected_os`, `probe`, `summary`.

- [ ] **Step 1: Write failing tests**

```python
def test_detect_os_linux_when_uname_reports_linux():
    ex = ToolExecutor(host="h", user="u", pwd="p")
    ex.execute = lambda c: "Linux"
    assert ex.detected_os == "linux"

def test_detect_os_windows_when_probe_lacks_linux():
    ex = ToolExecutor(host="h", user="u", pwd="p")
    ex.execute = lambda c: "WINRM_ERR(1): 'uname' is not recognized"
    assert ex.detected_os == "windows"

def test_detected_os_is_cached_one_probe():
    ex = ToolExecutor(host="h", user="u", pwd="p")
    calls = {"n": 0}
    def probe(c):
        calls["n"] += 1; return "Linux"
    ex.execute = probe
    _ = ex.detected_os; _ = ex.detected_os
    assert calls["n"] == 1

def test_investigate_environment_reports_detected_os():
    ex = ToolExecutor(host="h", user="u", pwd="p")
    ex.execute = lambda c: "Linux x86_64"
    r = ex.investigate_environment()
    assert r["tool"] == "investigate_environment" and r["detected_os"] == "linux"

def test_detected_os_resets_with_analysis_window():
    ex = ToolExecutor(host="h", user="u", pwd="p")
    ex.execute = lambda c: "Linux"
    _ = ex.detected_os
    ex.mark_analysis_window()
    assert ex._detected_os is None  # re-probes next access
```

- [ ] **Step 2: Run, verify fail** — `uv run python -m pytest tests/test_executor.py -k "detect_os or detected_os or investigate_environment" -v` → FAIL.
- [ ] **Step 3: Implement.** Add `self._detected_os: Optional[str] = None` in `__init__`. `detected_os` property: if None, run `_detect_os()` and cache. `_detect_os`: `raw = self.execute("uname -s 2>/dev/null || true"); return "linux" if "Linux" in raw or "Darwin" in raw else "windows"`. `investigate_environment()` returns the dict (uses `detected_os`). In `mark_analysis_window()`, set `self._detected_os = None`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_executor.py && git commit -m "feat(executor): probe-based detected_os + investigate_environment"`

---

### Task 2: dispatch guard + tool registration + first-move steer in the agent

**Files:**
- Modify: `src/agents.py` (`process_tool_call` guard ~`:1159`; blue tool list; blue tool-steering ~`:1020`)
- Test: `tests/test_agents.py` (or `tests/test_blue_triage.py` — whichever holds blue dispatch tests)

**Interfaces:**
- Consumes: `executor.detected_os`, `executor.investigate_environment()` (Task 1).
- Produces: `LINUX_ONLY_SENSORS: frozenset[str]`; `process_tool_call` returns a
  `not_applicable` JSON string for a member when `detected_os != "linux"`.

- [ ] **Step 1: Write failing tests** (fake executor with `detected_os` + spy)

```python
def test_linux_sensor_not_applicable_on_windows():
    # blue agent with a fake executor reporting detected_os="windows":
    # process_tool_call({'function':{'name':'investigate_processes','arguments':{}}})
    # returns JSON with "not_applicable" and does NOT call executor.investigate_processes
def test_linux_sensor_runs_when_linux():
    # same, detected_os="linux" -> executor.investigate_processes IS called
def test_guard_does_not_block_environment_or_nonsensor_tools_on_windows():
    # investigate_environment and execute_command still dispatch on windows
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement.** Add `LINUX_ONLY_SENSORS` (every `investigate_*` except `investigate_environment`). At the top of `process_tool_call`, after extracting the name: if `name in LINUX_ONLY_SENSORS and self.role == "blue" and getattr(self.executor, "detected_os", "linux") != "linux"`, return `json.dumps({"tool": name, "status": "not_applicable", "detected_os": ..., "summary": "Linux-only sensor; no Windows implementation yet"})`. Add an `investigate_environment` branch calling `self.executor.investigate_environment()`. Register the `investigate_environment` tool in blue's tool list. In blue tool-steering (~`:1020`), nudge `investigate_environment` when not yet run this episode.
- [ ] **Step 4: Run tests + full suite** — `uv run python -m pytest -q` → green.
- [ ] **Step 5: Commit** — `git add src/agents.py tests/… && git commit -m "feat(agents): self-checker — relabel Linux sensors not_applicable off-Linux"`

---

### Task 3: live re-run on `.17` + confirm relabel

Live, not CI.

- [ ] **Step 1: Mock/Linux sanity** — `uv run python -m pytest -q` green (Linux path unchanged).
- [ ] **Step 2: Re-run the Windows episode** (same as the brick's Task 4, winrm/jump):
  ```
  uv run python -m src.arena --episodes 1 --host 192.168.64.17 \
    --jump-host 192.168.64.11 --transport winrm --objective root --observe \
    --no-reset --user vagrant --pwd vagrant --jump-user kali --jump-pwd kali \
    --model glm-5.3-flash:cloud --max-turns 12
  ```
  Expected: `investigate_environment` detects windows; the Linux sensors blue calls now return `not_applicable` (not CLEAN) in `ep_001.json`.
- [ ] **Step 3: Note the before/after** in the failure-map doc (one line: false-CLEAN → honest not_applicable).
- [ ] **Step 4: Commit** the doc note.

## Self-Review notes

- Spec coverage: detect (Task 1), surface+steer (Task 2), relabel via one guard (Task 2), Linux-unchanged (Task 2 test + full suite), live confirm (Task 3).
- Review Focus: probe-ambiguous→windows (T1), cache+reset (T1), guard-over-reach (T2), linux-no-regression (T2).
- Proportion: interfaces + test names, bodies left to implementer; one guard, not 14 edits.
