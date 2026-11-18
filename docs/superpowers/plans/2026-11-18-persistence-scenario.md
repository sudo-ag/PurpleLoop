# Persistence scenario (slice #1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a selectable `persistence` objective whose win is "red's planted SSH-key backdoor survived blue's eviction" — red wins if it planted and blue never removed the key; blue wins only by running `remove_persistence`.

**Architecture:** Reuse existing mechanics (red plant → `red_persistence_planted_turn`; blue `investigate_persistence`/`remove_persistence`). Add (1) red's persistence objective + doctrine, (2) a `blue_persistence_removed_turn` eviction signal in the orchestrator, (3) a persistence win-eval wired into the scorecard plus the `--objective` plumbing. No scenario spec/loader (that is the later extract phase); `root`/flag stays a sibling objective, untouched.

**Tech Stack:** Python 3.13, pytest (run as `uv run python -m pytest`).

**Spec:** `docs/superpowers/specs/2026-11-18-persistence-scenario-design.md`

## Global Constraints

- No new red planting capability or blue tooling — reuse what exists.
- Do not change foothold/exfil/root grading, the tier board, or existing sensors.
- Blue wins the persistence objective ONLY by removing the key (`removed: True`); detection or a password lock is not a win.
- Tests run with `uv run python -m pytest` (plain `pytest`/`uv run pytest` fail to import `src`).
- No commit to master without the user's go-ahead.

## Review Focus

- A blue that only locks the account's password (never `remove_persistence`) must LOSE the persistence objective — the key still authenticates. (Task 3, covered.)
- An episode where red never planted must yield winner `None` for the persistence objective, not a spurious blue win. (Task 3, covered.)
- Selecting `--objective persistence` must not alter foothold/exfil/root episodes' grading. (Task 3, covered.)
- `blue_persistence_removed_turn` must set only on an actual removal (`removed: True`), not on a refused/no-op `remove_persistence`. (Task 2, covered.)

---

### Task 1: Red's persistence objective + doctrine

**Files:**
- Modify: `src/agents.py` — `RedAgent.__init__` (add `objective`), `RedAgent.objective_met` (~1477), the persistence doctrine block (~485).
- Test: `tests/test_persistence_objective.py` (create)

**Interfaces:**
- Consumes: `RedAgent.history` (Turns with `.output`); the plant signature `ssh-ed25519 <base64>` in a command output (same as `_check_red_persistence_planted`).
- Produces: `RedAgent(objective="persistence")` stored as `self.objective`; `objective_met()` true when red has planted under that objective.

- [ ] **Step 1: Write the failing tests**

```python
import json
from src.agents import RedAgent
from src.mock_executor import MockExecutor
from src.trajectory import Turn

def _red(objective="root"):
    return RedAgent(executor=MockExecutor(), model="x", objective=objective)

def _planted_turn():
    out = "...\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef0123456789abcdef root@attacker\n..."
    return Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}}, out)

def test_persistence_objective_met_once_planted():
    r = _red("persistence")
    assert r.objective_met() is False
    r.history = [_planted_turn()]
    assert r.objective_met() is True

def test_persistence_objective_not_met_without_plant():
    r = _red("persistence")
    r.history = [Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}}, "uid=0(root)")]
    assert r.objective_met() is False

def test_root_objective_still_uses_flag_check():
    r = _red("root")
    r.history = [_planted_turn()]            # planted but no flag read
    assert r.objective_met() is False
    r.history = [Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}}, "flag{abc}")]
    assert r.objective_met() is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_persistence_objective.py -v`
Expected: FAIL — `RedAgent.__init__` has no `objective` keyword.

- [ ] **Step 3: Add `objective` to `RedAgent.__init__`**

Add `objective: str = "root"` to the signature; store `self.objective = objective`. (Read the current `__init__` for exact parameter order.)

- [ ] **Step 4: Branch `RedAgent.objective_met`**

When `self.objective == "persistence"`, return True iff any history output contains the planted-key pattern `ssh-ed25519 [A-Za-z0-9+/]{20,}` (mirror `_check_red_persistence_planted`). Otherwise keep the existing `flag{` check.

- [ ] **Step 5: Elevate the persistence doctrine under this objective**

In the red doctrine (~485, the "it's worth planting your own way back in" block), when `self.objective == "persistence"` make planting-and-keeping a surviving key the PRIMARY objective (foothold first, then plant), not the current optional phrasing. Builder wording.

- [ ] **Step 6: Run the new tests**

Run: `uv run python -m pytest tests/test_persistence_objective.py -v`
Expected: PASS (3).

- [ ] **Step 7: Commit**

```bash
git add src/agents.py tests/test_persistence_objective.py
git commit -m "feat(red): persistence objective — planting a surviving backdoor is the goal"
```

---

### Task 2: Blue eviction signal in the orchestrator

**Files:**
- Modify: `src/orchestrator.py` — add `blue_persistence_removed_turn` to `SimulationState` (~103, by `red_persistence_planted_turn`); set it in the blue branch of the tool-processing loop (~655).
- Test: `tests/test_persistence_eviction.py` (create)

**Interfaces:**
- Consumes: a blue `remove_persistence` tool result `{"tool":"remove_persistence","removed":bool,...}`; `self.state.turn`.
- Produces: `SimulationState.blue_persistence_removed_turn: Optional[int]`, set on the first successful removal.

- [ ] **Step 1: Write the failing test**

```python
# Build the smallest orchestrator the existing orchestrator tests use (copy that
# fixture's construction), drive one blue remove_persistence result through the
# same path those tests use to feed a tool output, and assert the field.
def test_removed_true_sets_eviction_turn():
    orch = _orch()                      # same helper shape as tests/test_*orchestrator*/arena use
    orch.state.turn = 4
    _feed_blue_output(orch, json.dumps({"tool": "remove_persistence", "removed": True, "target_user": "root"}))
    assert orch.state.blue_persistence_removed_turn == 4

def test_removed_false_does_not_set_eviction_turn():
    orch = _orch()
    _feed_blue_output(orch, json.dumps({"tool": "remove_persistence", "removed": False, "target_user": "root"}))
    assert orch.state.blue_persistence_removed_turn is None
```

Builder: reuse the existing orchestrator test fixture (grep `tests/` for how a blue tool output is pushed through `_process`/the per-turn loop — match that exact construction rather than inventing one).

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run python -m pytest tests/test_persistence_eviction.py -v`
Expected: FAIL — `AttributeError: ... 'blue_persistence_removed_turn'`.

- [ ] **Step 3: Add the field**

`blue_persistence_removed_turn: Optional[int] = None` on `SimulationState`, commented like its `red_persistence_planted_turn` sibling.

- [ ] **Step 4: Set it in the blue branch**

In the tool-processing loop's blue section (near `_check_blue_foothold_detect`), when a `remove_persistence` result parses to `removed == True` and `blue_persistence_removed_turn is None`, set it to `self.state.turn`. `removed: True` only occurs when a non-baseline key was actually stripped, so no account match is needed.

- [ ] **Step 5: Run the test**

Run: `uv run python -m pytest tests/test_persistence_eviction.py -v`
Expected: PASS (2).

- [ ] **Step 6: Commit**

```bash
git add src/orchestrator.py tests/test_persistence_eviction.py
git commit -m "feat(blue): track the eviction turn when blue removes a planted key"
```

---

### Task 3: Persistence win-eval + objective plumbing

**Files:**
- Modify: `src/arena.py` — add `persistence_winner(...)` near `graded_result` (~41); thread `objective` through `build_scorecard` (~56), `build_agents` (~320), `run_episodes`, and the `--objective` CLI arg (~457).
- Test: `tests/test_persistence_winner.py` (create)

**Interfaces:**
- Consumes: `RedAgent(objective=...)` (Task 1); `SimulationState.red_persistence_planted_turn` and `blue_persistence_removed_turn` (Task 2).
- Produces: `persistence_winner(planted_turn: Optional[int], removed_turn: Optional[int]) -> Optional[str]`; `build_scorecard(..., objective: str = "root")` whose `graded_result` is the persistence winner when `objective == "persistence"`.

- [ ] **Step 1: Write the failing tests**

```python
from src.arena import persistence_winner, build_scorecard

def test_planted_and_removed_is_blue():
    assert persistence_winner(planted_turn=2, removed_turn=5) == "blue"

def test_planted_not_removed_is_red():
    assert persistence_winner(planted_turn=2, removed_turn=None) == "red"

def test_never_planted_is_none():
    assert persistence_winner(planted_turn=None, removed_turn=None) is None

def test_removal_before_plant_is_red():
    # a stale/earlier removal does not count as evicting a later plant
    assert persistence_winner(planted_turn=5, removed_turn=3) == "red"

def test_scorecard_uses_persistence_winner_when_objective_is_persistence():
    class _S:  # minimal stand-in, matching the fields build_scorecard reads
        red_persistence_planted_turn = 2
        blue_persistence_removed_turn = None
        # ... builder adds whatever else build_scorecard reads, defaulted benign
    card = build_scorecard(_S(), winner=None, episode=1, objective="persistence")
    assert card["graded_result"] == "red"
```

Builder: `_S` must carry whatever attrs `build_scorecard` already reads (give them benign defaults). The password-lock crux is covered by `test_planted_not_removed_is_red` (a lock sets no `blue_persistence_removed_turn`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run python -m pytest tests/test_persistence_winner.py -v`
Expected: FAIL — `cannot import name 'persistence_winner'`.

- [ ] **Step 3: Implement `persistence_winner`**

`blue` if `removed_turn is not None and planted_turn is not None and removed_turn >= planted_turn`; `red` if `planted_turn is not None` (and not the blue case); else `None`.

- [ ] **Step 4: Thread `objective` into `build_scorecard`**

Add `objective: str = "root"`. When `objective == "persistence"`, set the card's `graded_result` to `persistence_winner(state.red_persistence_planted_turn, state.blue_persistence_removed_turn)` instead of the tier-based `graded_result(...)`. Leave every other field and the non-persistence path unchanged.

- [ ] **Step 5: Thread `--objective` through the CLI → agents → scorecard**

Add `--objective` (choices `foothold|exfil|root|persistence`, default `root`) to the arena parser; pass it through `run_episodes` → `build_agents` (→ `RedAgent(objective=...)`) and into each `build_scorecard(..., objective=a.objective)` call.

- [ ] **Step 6: Run the new tests**

Run: `uv run python -m pytest tests/test_persistence_winner.py -v`
Expected: PASS (5).

- [ ] **Step 7: Run the full suite (regression)**

Run: `uv run python -m pytest -q`
Expected: PASS — current 553 plus the new tests, no failures. Confirms foothold/exfil/root grading and the scorecard are unchanged for the default objective.

- [ ] **Step 8: Commit**

```bash
git add src/arena.py tests/test_persistence_winner.py docs/superpowers/specs/2026-11-18-persistence-scenario-design.md docs/superpowers/plans/2026-11-18-persistence-scenario.md
git commit -m "feat(arena): persistence win-eval and --objective plumbing"
```

---

## Self-Review

1. **Spec coverage:** red objective + doctrine (Task 1) ✓; blue eviction signal (Task 2) ✓; win-eval + ledger-shaped winner + `--objective` plumbing (Task 3) ✓; non-goal "flag stays a sibling, other grading untouched" held by gating all changes on `objective == "persistence"` (Task 3 Step 4) ✓.
2. **Step scan:** each step writes one thing; win-eval rule and the `removed: True` condition are pinned, bodies left to the builder. Task 2's test construction is delegated to the existing orchestrator fixture (named, not invented) because that harness detail isn't a plan decision.
3. **Type consistency:** `persistence_winner(planted_turn, removed_turn) -> Optional[str]` defined Task 3 Step 3, used Step 4; `blue_persistence_removed_turn` defined Task 2 Step 3, consumed Task 3; `RedAgent(objective=...)` defined Task 1, consumed Task 3 Step 5.
4. **Review Focus:** password-lock-loses (`test_planted_not_removed_is_red`), never-planted-None, other-objectives-unchanged (Task 3), and removed-True-only (Task 2) each have a named test.
5. **Proportion:** plan ≈ spec length; code blocks are tests + the win-eval rule, not the implementations.
