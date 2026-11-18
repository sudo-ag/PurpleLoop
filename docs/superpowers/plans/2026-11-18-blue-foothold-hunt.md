# Blue foothold hunt — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When blue has a confirmed attacker but no foothold evidence yet (observe mode), direct it to hunt the foothold with the foothold-revealing sensors instead of settling into document-mode.

**Architecture:** Add `BLUE_FOOTHOLD_HUNT` (the sensors whose evidence reveals a landed foothold) and `_foothold_hunt_exhausted()` to `BlueAgent`, then a HUNT guidance branch in `tool_guidance` placed before the ATTRIBUTE block. It fires only when confirmed + observe + `not _has_foothold()` + hunt not exhausted, directing the least-recently-used unused hunt sensor; when exhausted it falls through to ATTRIBUTE unchanged.

**Tech Stack:** Python 3.13, pytest (run as `uv run python -m pytest`).

**Spec:** `docs/superpowers/specs/2026-11-18-blue-foothold-hunt-design.md`

## Global Constraints

- No auto-running of sensors; blue stays the decider (guidance only).
- No change to non-observe behavior, TRIAGE/MONITOR/IDENTIFY/RESPOND, or scoring.
- Tests run with `uv run python -m pytest` (plain `pytest`/`uv run pytest` fail to import `src`).

## Review Focus

- HUNT must not fire once `_has_foothold()` is True — HARDEN owns that turn. (Task 1, covered.)
- HUNT must terminate: once all hunt sensors have run with no foothold, blue returns to ATTRIBUTE, not an endless hunt loop. (Task 1, covered.)
- Non-observe confirmed-but-no-foothold must still go RESPOND (contain), not HUNT. (Task 1, covered.)

---

### Task 1: HUNT guidance for a confirmed scanner with no foothold yet

**Files:**
- Modify: `src/agents.py` — add `BLUE_FOOTHOLD_HUNT` constant near `BLUE_CORROBORATION` (~1617); add `_foothold_hunt_exhausted()` near `_has_foothold()` (~1766); add the HUNT branch in `tool_guidance` immediately before `if phase == "ATTRIBUTE":` (~1901).
- Test: `tests/test_foothold_hunt.py` (create)

**Interfaces:**
- Consumes: `_has_foothold()`, `_tools_used()`, `triage_phase()` (all existing on `BlueAgent`); the LRU idiom `min(candidates, key=lambda t: last_use.get(t, -1))` from TRIAGE/MONITOR.
- Produces: `BLUE_FOOTHOLD_HUNT: list[str]`, `BlueAgent._foothold_hunt_exhausted(self) -> bool`.

- [ ] **Step 1: Write the failing tests**

```python
import json
from src.agents import BlueAgent, BLUE_FOOTHOLD_HUNT
from src.mock_executor import MockExecutor
from src.trajectory import Turn

def _blue():
    b = BlueAgent(executor=MockExecutor(), model="x")
    b.executor.control_source_ip = "192.168.64.1"
    b.executor.user = "vagrant"
    return b

def _used_turn(name):
    # a tool call with a benign output (no foothold, no account)
    out = json.dumps({"tool": name})
    return Turn(0, "", {"function": {"name": name, "arguments": {}}}, out)

def test_confirmed_scanner_no_foothold_hunts_webshells_first():
    # Confirmed attacker (passed in), observe, no foothold evidence, nothing run:
    # guidance directs the first hunt sensor, not the ATTRIBUTE document text.
    b = _blue()
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "investigate_webshells" in g

def test_hunt_picks_least_recently_used_unrun_sensor():
    # webshells already run -> hunt moves to the next foothold sensor.
    b = _blue()
    b.history = [_used_turn("investigate_webshells")]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "investigate_webshells" not in g
    assert any(s in g for s in ("investigate_file_access", "investigate_processes"))

def test_hunt_exhausted_falls_through_to_attribute():
    b = _blue()
    b.history = [_used_turn(s) for s in BLUE_FOOTHOLD_HUNT]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "ATTRIBUTE" in g

def test_hunt_does_not_fire_when_foothold_already_held():
    # A critical www-data process means _has_foothold() is True -> HARDEN, not HUNT.
    b = _blue()
    b.history = [Turn(0, "", {"function": {"name": "investigate_processes", "arguments": {}}},
                      json.dumps({"tool": "investigate_processes",
                                  "critical_processes": [{"user": "www-data", "critical": True}]}))]
    g = b.tool_guidance(observe=True, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remediate_escalation_surface" in g

def test_non_observe_confirmed_no_foothold_still_responds():
    b = _blue()
    g = b.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "contain_attacker" in g
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_foothold_hunt.py -v`
Expected: FAIL — `ImportError: cannot import name 'BLUE_FOOTHOLD_HUNT'` (and, once that resolves, the HUNT-branch assertions fail until Step 5).

- [ ] **Step 3: Add `BLUE_FOOTHOLD_HUNT` constant in `src/agents.py`**

Near `BLUE_CORROBORATION`: `BLUE_FOOTHOLD_HUNT = ["investigate_webshells", "investigate_file_access", "investigate_processes"]`.

- [ ] **Step 4: Add `_foothold_hunt_exhausted(self) -> bool` to `BlueAgent`**

Near `_has_foothold()`. Returns True when every sensor in `BLUE_FOOTHOLD_HUNT` is in `self._tools_used()`.

- [ ] **Step 5: Add the HUNT guidance branch in `tool_guidance`**

Immediately before `if phase == "ATTRIBUTE":`. Fire when `phase == "ATTRIBUTE" and observe and not self._has_foothold() and not self._foothold_hunt_exhausted()`. Pick the least-recently-used `BLUE_FOOTHOLD_HUNT` sensor not yet in `_tools_used()` (LRU idiom as in TRIAGE), and return guidance naming it: the scanner is confirmed but no foothold is pinned yet — hunt it with `<sensor>` before concluding. Otherwise control falls to the existing ATTRIBUTE block unchanged.

- [ ] **Step 6: Run the new tests**

Run: `uv run python -m pytest tests/test_foothold_hunt.py -v`
Expected: PASS (all 5).

- [ ] **Step 7: Run the full suite (regression)**

Run: `uv run python -m pytest -q`
Expected: PASS — current 548 plus 5 new (553), no failures. Confirms TRIAGE/MONITOR/IDENTIFY/RESPOND/ATTRIBUTE and HARDEN paths unchanged.

- [ ] **Step 8: Commit**

```bash
git add src/agents.py tests/test_foothold_hunt.py docs/superpowers/specs/2026-11-18-blue-foothold-hunt-design.md docs/superpowers/plans/2026-11-18-blue-foothold-hunt.md
git commit -m "feat(blue): hunt the foothold after confirming a scanner"
```

---

## Self-Review

1. **Spec coverage:** `BLUE_FOOTHOLD_HUNT` (Step 3) ✓; `_foothold_hunt_exhausted` (Step 4) ✓; HUNT branch + condition + LRU + fall-through (Step 5) ✓; verification (Steps 6–7) ✓.
2. **Step scan:** each step writes one thing; the HUNT condition and LRU idiom are pinned in Step 5, the branch body is left to the builder.
3. **Type consistency:** `_foothold_hunt_exhausted(self) -> bool` (Step 4) used in Step 5's condition; `BLUE_FOOTHOLD_HUNT` defined Step 3, imported in the test and used Steps 4–5.
4. **Review Focus:** foothold-already-held, hunt-exhausted, and non-observe cases each have a named test in Step 1.
5. **Proportion:** plan ≈ spec length; the one code block is tests + the condition, not the branch body.
